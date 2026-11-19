#include "agent.hpp"

#include <algorithm>
#include <string_view>
#include <system_error>


Agent_t::Agent_t(CorpusPtr Corpus, const FuzzerConfig_t& config, unsigned int id)
    : Config_(config),
      Corpus_(std::move(Corpus)),
      Exec_(config, id),
      AgentId_(id),
      Status_(AgentStatus::Init),
      Mutator_(MutatorRegistry_t::instance().create(config.mutator)),
      Rng_(std::random_device{}() ^ (static_cast<uint64_t>(id + 1) * 0x9E3779B97F4A7C15ULL)),
      DumpPath_(std::filesystem::path(config.workdir) / "dump" / fmt::format("input_{}", id)),
      MaxInputSize_(maxInputSize(config)) {
    if (!Exec_.ok()) {
        DebugPrint<0>("agent", "[-] nyx_new failed for agent {}\n", id);
        setStatus(AgentStatus::Errored);
        return;
    }
    if (!Mutator_) {
        DebugPrint<0>("agent", "[-] unknown mutator '{}'\n", config.mutator);
        setStatus(AgentStatus::Errored);
        return;
    }

    setStatus(AgentStatus::Ready);
}


void Agent_t::run() {
    setStatus(AgentStatus::Running);
    bool hadError = false;

    Input_t testcase;
    testcase.reserve(MaxInputSize_);

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

        const ExecOutcome_t out = Exec_.exec(testcase);
        const NyxReturnValue r = out.ret;
        const std::string_view aux_str = out.aux;

        DebugPrint<2>("agent", "[{}:{}] {}\n", AgentId_, i, ret_name(r));
        if (!aux_str.empty()) DebugPrint<2>("agent", "[{}] Last Msg: {}\n", AgentId_, aux_str);

        if (isFatal(r)) {
            DebugPrint<0>("agent", "[-] agent {} stopped on {}: {}\n", AgentId_, ret_name(r), aux_str);
            hadError = true;
            break;
        }

     
        onExecutionDone(ExecResult_t{
            .agentId = AgentId_,
            .ret     = r,
            .input   = testcase,
            .bitmap  = Exec_.bitmap(),
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
