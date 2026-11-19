#include <csignal>
#include <cstdint>
#include <iostream>
#include <string>

#include <argparse/argparse.hpp>

#include "nyx.hpp"
#include "master.hpp"
#include "mutator.hpp"
#include "tools.hpp"
#include "utils.hpp"

constexpr std::size_t kAgentPayloadBytes = 64 * 1024; // PAYLOAD_SIZE * 1024 in the driver

int main(int argc, char **argv)
{
    argparse::ArgumentParser program("nyxfuzz", "1.0", argparse::default_arguments::help);

    program.add_argument("-s", "--sharedir")
        .required()
        .metavar("DIR")
        .help("Nyx sharedir (contains config.ron)");

    program.add_argument("-w", "--workdir")
        .required()
        .metavar("DIR")
        .help("libnyx workdir (fresh one per run)");

    program.add_argument("-i", "--seeds")
        .default_value(std::string{})
        .metavar("DIR")
        .help("directory of initial inputs (optional)");

    program.add_argument("-m", "--mutator")
        .default_value(std::string{"havoc"})
        .metavar("NAME")
        .help("mutation strategy, one of:\n" + MutatorRegistry_t::instance().describe());

    program.add_argument("-n", "--agents")
        .default_value(1UL)
        .scan<'u', unsigned long>()
        .metavar("N")
        .help("number of agents to run");

    program.add_argument("-N", "--runs")
        .default_value(1UL)
        .scan<'u', unsigned long>()
        .metavar("N")
        .help("number of executions per agent (0 = until Ctrl-C)");

    program.add_argument("-t", "--timeout")
        .default_value(2000UL)
        .scan<'u', unsigned long>()
        .metavar("MS")
        .help("per-execution timeout in ms");

    program.add_argument("-v", "--verbose")
        .default_value(false)
        .implicit_value(true)
        .help("forward guest hprintf output to stderr");

    // Offline tools: one VM, no fuzzing. They use -s, -w, -t and -v like a fuzzing run.
    program.add_argument("-r", "--repro")
        .default_value(std::string{})
        .metavar("PATH")
        .help("replay a testcase (or every testcase of a directory, e.g. <workdir>/crashes) and report how it ends");

    program.add_argument("-M", "--minimize")
        .default_value(std::string{})
        .metavar("FILE")
        .help("reduce a crashing testcase to a smaller one that ends the same way");

    program.add_argument("-o", "--output")
        .default_value(std::string{})
        .metavar("FILE")
        .help("--minimize: where to write the result (default: FILE.min)");

    program.add_argument("--tries")
        .default_value(1UL)
        .scan<'u', unsigned long>()
        .metavar("N")
        .help("--repro: executions per testcase; --minimize: executions before a candidate is given up on (for flaky bugs)");

    program.add_argument("--match-aux")
        .default_value(false)
        .implicit_value(true)
        .help("--minimize: a candidate must also end with the same aux string, not just the same exit kind");

    program.add_argument("--max-execs")
        .default_value(0UL)
        .scan<'u', unsigned long>()
        .metavar("N")
        .help("--minimize: stop after N executions and keep the best so far (0 = no limit)");

    try
    {
        program.parse_args(argc, argv);
    }
    catch (const std::exception &err)
    {
        std::cerr << err.what() << '\n'
                  << program;
        return 1;
    }

    const auto mutator = program.get<std::string>("--mutator");
    if (!MutatorRegistry_t::instance().contains(mutator))
    {
        std::cerr << "Unknown mutator '" << mutator << "'. Available:\n"
                  << MutatorRegistry_t::instance().describe();
        return 1;
    }

    const auto sharedir = program.get<std::string>("--sharedir");
    void *nyxConf = nyx_config_load(sharedir.c_str());
    if (!nyxConf)
    {
        DebugPrint<0>("-", "nyx_config_load failed\n");
        return 1;
    }

    FuzzerConfig_t config{
        .sharedir = sharedir,
        .workdir = program.get<std::string>("--workdir"),
        .seedsDir = program.get<std::string>("--seeds"),
        .mutator = mutator,
        .nAgents = program.get<unsigned long>("--agents"),
        .runs = program.get<unsigned long>("--runs"),
        .timeout_ms = program.get<unsigned long>("--timeout"),
        .verbose = program.get<bool>("--verbose"),
        .kAgentPayloadBytes = kAgentPayloadBytes,
        .nyxConf = nyxConf,
    };

    // Ability to stop on a Ctrl-C
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    const auto reproPath = program.get<std::string>("--repro");
    const auto minimizePath = program.get<std::string>("--minimize");
    if (!reproPath.empty() && !minimizePath.empty())
    {
        std::cerr << "--repro and --minimize cannot be combined\n";
        return 1;
    }
    if (!reproPath.empty() || !minimizePath.empty())
    {
        const ToolOptions_t opt{
            .input = reproPath.empty() ? minimizePath : reproPath,
            .output = program.get<std::string>("--output"),
            .tries = program.get<unsigned long>("--tries"),
            .matchAux = program.get<bool>("--match-aux"),
            .maxExecs = program.get<unsigned long>("--max-execs"),
        };
        return reproPath.empty() ? runMinimize(config, opt) : runRepro(config, opt);
    }

    Master_t masterFuzzer(config);
    masterFuzzer.run();

    return 0;
}
