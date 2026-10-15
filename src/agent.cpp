#include "agent.hpp"

#include <algorithm>
#include <array>
#include <string_view>
#include <system_error>


Agent_t::Agent_t(CorpusPtr Corpus, const FuzzerConfig_t& config, unsigned int id)
    : Config_(config),
      Corpus_(std::move(Corpus)),
      Proc_(nyx_new(config.nyxConf, id), &nyx_shutdown),
      AgentId_(id),
      Status_(AgentStatus::Init),
      Mutator_(MutatorRegistry_t::instance().create(config.mutator)),
      Rng_(std::random_device{}() ^ (static_cast<uint64_t>(id + 1) * 0x9E3779B97F4A7C15ULL)),
      DumpPath_(std::filesystem::path(config.workdir) / "dump" / fmt::format("input_{}", id)),
      MaxInputSize_(maxInputSize(config)) {
    if (!Proc_) {
        DebugPrint<0>("agent", "[-] nyx_new failed for agent {}\n", id);
        setStatus(AgentStatus::Errored);
        return;
    }
    if (!Mutator_) {
        DebugPrint<0>("agent", "[-] unknown mutator '{}'\n", config.mutator);
        setStatus(AgentStatus::Errored);
        return;
    }

    // The bitmap lives in shared memory owned by the process: stable for its lifetime.
    Bitmap_ = std::span<const uint8_t>(nyx_get_bitmap_buffer(Proc_.get()),
                                       nyx_get_bitmap_buffer_size(Proc_.get()));

    const auto sec  = std::min(config.timeout_ms / 1000, 255UL);
    const auto usec = (config.timeout_ms % 1000) * 1000;
    nyx_option_set_reload_mode(Proc_.get(), true);
    nyx_option_set_timeout(Proc_.get(), static_cast<uint8_t>(sec), static_cast<uint32_t>(usec));
    nyx_option_apply(Proc_.get());

    setStatus(AgentStatus::Ready);
}


void Agent_t::run() {
    setStatus(AgentStatus::Running);
    bool hadError = false;

    Input_t testcase;
    testcase.reserve(MaxInputSize_);
    std::array<char, 1024> aux{};

    MutatorContext_t ctx{
        .rng       = Rng_,
        .maxSize   = MaxInputSize_,
        .pickOther = [this] { return Corpus_->pick(Rng_); },
    };

    for (unsigned long i = 0; !g_stop.load(std::memory_order_relaxed) && (Config_.runs == 0 || i < Config_.runs); ++i) {
        if (const InputPtr parent = Corpus_->pick(Rng_))
            testcase.assign(parent->begin(), parent->end());
        else
            testcase.assign(1, 0);

        Mutator_->mutate(testcase, ctx);
        if (testcase.size() > MaxInputSize_) testcase.resize(MaxInputSize_);
        if (testcase.empty()) testcase.push_back(0);

        // Insert after so there won't be any modification from the mutator
        //struct Input {
        //    size_t size,
        //    uint8 workerId,
        //    uint8 buffer[]
        //}
        testcase.insert(testcase.begin(), static_cast<uint8_t>(AgentId_));

        nyx_set_afl_input(Proc_.get(), testcase.data(), static_cast<uint32_t>(testcase.size()));
        const NyxReturnValue r = nyx_exec(Proc_.get());

        uint32_t n = nyx_get_aux_string(Proc_.get(), reinterpret_cast<uint8_t*>(aux.data()),
                                        static_cast<uint32_t>(aux.size() - 1));
        n = std::min<uint32_t>(n, aux.size() - 1);
        const std::string_view aux_str(aux.data(), n);

        DebugPrint<2>("agent", "[{}:{}] {}\n", AgentId_, i, ret_name(r));
        if (!aux_str.empty()) DebugPrint<2>("agent", "[{}] Last Msg: {}\n", AgentId_, aux_str);

        if (r == Error || r == IoError || r == Abort) {
            DebugPrint<0>("agent", "[-] agent {} stopped on {}: {}\n", AgentId_, ret_name(r), aux_str);
            hadError = true;
            break;
        }

     
        onExecutionDone(ExecResult_t{
            .agentId = AgentId_,
            .ret     = r,
            .input   = testcase,
            .bitmap  = Bitmap_,
            .aux     = aux_str,
        });
    }

    setStatus(hadError ? AgentStatus::Errored : AgentStatus::Stopped);
}


void Agent_t::onExecutionDone(const ExecResult_t& res) {
    collectDumpedInput();

    Corpus_->onExecution(res);
}


void Agent_t::collectDumpedInput() {
    std::error_code ec;
    if (!std::filesystem::exists(DumpPath_, ec)) return;

    auto data = readFile(DumpPath_);
    std::filesystem::remove(DumpPath_, ec);  // consume it so it's not picked twice
    if (ec) DebugPrint<0>("agent", "[-] cannot remove {}: {}\n", DumpPath_.string(), ec.message());

    if (data && !data->empty())
        Corpus_->add(std::move(*data), fmt::format("dump{}", AgentId_));
}
