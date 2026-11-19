#include "tools.hpp"

#include <algorithm>
#include <map>
#include <system_error>
#include <unordered_map>

#include "executor.hpp"
#include "format.hpp"
#include "oracle.hpp"

namespace
{

    std::unique_ptr<Executor_t> startVm(const FuzzerConfig_t &config)
    {
        configureNyx(config);
        nyx_config_set_process_role(config.nyxConf, StandAlone);
        DebugPrint<0>("tool", "Starting QEMU-Nyx (waiting for the root snapshot)...\n");
        auto vm = std::make_unique<Executor_t>(config, 0);
        if (!vm->ok())
        {
            DebugPrint<0>("tool", "[-] nyx_new failed\n");
            return nullptr;
        }
        return vm;
    }

    // A testcase the VM can take, or nothing (after saying why).
    std::optional<Input_t> loadTestcase(const std::filesystem::path &path, std::size_t maxSize)
    {
        auto data = readFile(path);
        if (!data)
            DebugPrint<0>("tool", "[-] cannot read {}\n", path.string());
        else if (data->empty() || data->size() > maxSize)
        {
            DebugPrint<0>("tool", "[-] {}: {} bytes, the payload must be 1..{} bytes\n", path.string(), data->size(), maxSize);
            data.reset();
        }
        return data;
    }

    // Testcases under `path`: the file itself, or the regular files of a
    // directory without the .aux notes the fuzzer saves next to crashes.
    std::vector<std::filesystem::path> listTestcases(const std::filesystem::path &path)
    {
        std::error_code ec;
        if (!std::filesystem::is_directory(path, ec))
            return {path};
        std::vector<std::filesystem::path> out;
        for (const auto &entry : std::filesystem::directory_iterator(path, ec))
        {
            if (entry.is_regular_file(ec) && entry.path().extension() != ".aux")
                out.push_back(entry.path());
        }
        std::sort(out.begin(), out.end());
        return out;
    }

} // namespace

int runRepro(const FuzzerConfig_t &config, const ToolOptions_t &opt)
{
    const auto files = listTestcases(opt.input);
    if (files.empty())
    {
        DebugPrint<0>("repro", "[-] no testcase in {}\n", opt.input);
        return 1;
    }
    const auto vm = startVm(config);
    if (!vm)
        return 1;

    const unsigned long tries = std::max(opt.tries, 1UL);
    std::size_t reproduced = 0, done = 0;
    for (const auto &file : files)
    {
        if (g_stop.load(std::memory_order_relaxed))
            break;
        ++done;
        const auto data = loadTestcase(file, maxInputSize(config));
        if (!data)
            continue;

        fmt::print("\n=== {}\n{}", file.string(), formatFor(*data).describe(*data));

        // What the fuzzer saw when it saved the crash, if it left a note.
        std::string savedAux;
        if (const auto saved = readFile(file.string() + ".aux"))
            savedAux.assign(saved->begin(), saved->end());

        std::map<std::string, unsigned long> endings;
        unsigned long hits = 0;
        for (unsigned long t = 0; t < tries && !g_stop.load(std::memory_order_relaxed); ++t)
        {
            const ExecOutcome_t out = vm->exec(*data);
            fmt::print("  run {}/{}: {}{}{}{}\n", t + 1, tries, ret_name(out.ret), out.aux.empty() ? "" : " | ", out.aux,
                       savedAux.empty() || out.ret == Normal ? "" : (out.aux == savedAux ? "  [same aux as saved]" : "  [aux differs from saved]"));
            if (isFatal(out.ret))
            {
                DebugPrint<0>("repro", "[-] the VM stopped on {}\n", ret_name(out.ret));
                return 1;
            }
            ++endings[std::string(ret_name(out.ret))];
            hits += out.ret != Normal;
        }

        std::string summary;
        for (const auto &[name, n] : endings)
            summary += fmt::format("{}{} x{}", summary.empty() ? "" : ", ", name, n);
        fmt::print("  => {} ({})\n", hits == 0 ? "NOT reproduced" : hits == tries ? "reproduced" : "reproduced, but not every time", summary);
        reproduced += hits != 0;
    }

    fmt::print("\n{} of {} testcase(s) reproduced\n", reproduced, done);
    return reproduced == files.size() ? 0 : 2;
}

int runMinimize(const FuzzerConfig_t &config, const ToolOptions_t &opt)
{
    const std::size_t maxSize = maxInputSize(config);
    auto original = loadTestcase(opt.input, maxSize);
    if (!original)
        return 1;
    const auto vm = startVm(config);
    if (!vm)
        return 1;

    const unsigned long tries = std::max(opt.tries, 1UL);

    // What are we preserving? Run the original a few times: the first abnormal
    // ending is the bug, and the count tells whether it is reliable.
    const unsigned long baselineRuns = std::max(tries, 3UL);
    NyxReturnValue wantRet = Normal;
    std::string wantAux;
    unsigned long hits = 0;
    for (unsigned long t = 0; t < baselineRuns; ++t)
    {
        const ExecOutcome_t out = vm->exec(*original);
        if (isFatal(out.ret))
        {
            DebugPrint<0>("minimize", "[-] the VM stopped on {}: {}\n", ret_name(out.ret), out.aux);
            return 1;
        }
        if (out.ret == Normal)
            continue;
        if (hits == 0)
        {
            wantRet = out.ret;
            wantAux = out.aux;
        }
        hits += out.ret == wantRet && (!opt.matchAux || out.aux == wantAux);
    }
    if (hits == 0)
    {
        DebugPrint<0>("minimize", "[-] {} exited normally {} times out of {}: nothing to minimize\n", opt.input, baselineRuns, baselineRuns);
        return 1;
    }
    DebugPrint<0>("minimize", "Target: {}{}{} ({}/{} runs), {} bytes\n", ret_name(wantRet), wantAux.empty() ? "" : " | ", wantAux,
                  hits, baselineRuns, original->size());
    if (hits < baselineRuns && tries < baselineRuns * 2)
        DebugPrint<0>("minimize", "[!] not reproduced every time: candidates will be wrongly rejected, consider a higher --tries\n");

    // The test handed to the reducer. Verdicts are cached by content, because
    // reducers revisit candidates when they loop until nothing changes.
    std::unordered_map<uint64_t, bool> verdicts;
    unsigned long execs = 0, kept = 0;
    std::string bestAux = wantAux;
    bool fatal = false, outOfBudget = false;

    const MinimizeTest_t test = [&](std::span<const uint8_t> cand)
    {
        if (fatal || outOfBudget || g_stop.load(std::memory_order_relaxed))
            return false;
        if (cand.empty() || cand.size() > maxSize)
            return false;
        const auto [slot, isNew] = verdicts.try_emplace(fnv1a64(cand), false);
        if (!isNew)
            return slot->second;

        for (unsigned long t = 0; t < tries; ++t)
        {
            if (opt.maxExecs != 0 && execs >= opt.maxExecs)
            {
                outOfBudget = true;
                verdicts.erase(slot); // not judged
                return false;
            }
            const ExecOutcome_t out = vm->exec(cand);
            ++execs;
            if (isFatal(out.ret))
            {
                DebugPrint<0>("minimize", "[-] the VM stopped on {}: {}\n", ret_name(out.ret), out.aux);
                fatal = true;
                return false;
            }
            if (out.ret == wantRet && (!opt.matchAux || out.aux == wantAux))
            {
                slot->second = true;
                bestAux = out.aux;
                ++kept;
                DebugPrint<1>("minimize", "{} bytes still ends in {} ({} execs)\n", cand.size(), ret_name(out.ret), execs);
                return true;
            }
        }
        return false;
    };

    const InputFormat_t &format = formatFor(*original);
    const Input_t best = format.minimize(*original, test);

    if (g_stop.load(std::memory_order_relaxed))
        DebugPrint<0>("minimize", "Interrupted: keeping what was reached so far\n");
    if (outOfBudget)
        DebugPrint<0>("minimize", "Execution budget used up: keeping what was reached so far\n");

    const std::filesystem::path outPath = opt.output.empty() ? opt.input + ".min" : opt.output;
    if (!writeFile(outPath, best))
    {
        DebugPrint<0>("minimize", "[-] cannot write {}\n", outPath.string());
        return 1;
    }
    if (!bestAux.empty())
        writeFile(outPath.string() + ".aux", std::string_view(bestAux));

    fmt::print("\n{}", format.describe(best));
    DebugPrint<0>("minimize", "{} -> {} bytes in {} execs ({} reductions), written to {}\n",
                  original->size(), best.size(), execs, kept, outPath.string());
    return fatal ? 1 : 0;
}
