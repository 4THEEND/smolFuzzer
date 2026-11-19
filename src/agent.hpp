#pragma once

#include <atomic>
#include <filesystem>
#include <memory>
#include <span>
#include <thread>

#include "corpus.hpp"
#include "executor.hpp"
#include "mutator.hpp"
#include "oracle.hpp"
#include "utils.hpp"


using CorpusPtr = std::shared_ptr<Corpus_t>;


enum class AgentStatus {
    Init,
    Ready,
    Running,
    Errored,
    Stopped
};


class Agent_t {
private:
    FuzzerConfig_t Config_;
    CorpusPtr Corpus_;
    Executor_t Exec_;   // this agent's VM
    unsigned int AgentId_;
    std::atomic<AgentStatus> Status_;

    std::unique_ptr<Mutator_t> Mutator_;
    Rng_t Rng_;
    std::filesystem::path DumpPath_;   // <workdir>/dump/input_<id>
    std::size_t MaxInputSize_;

public:
    Agent_t(const Agent_t&) = delete;
    Agent_t& operator=(const Agent_t&) = delete;

    Agent_t(CorpusPtr Corpus, const FuzzerConfig_t& config, unsigned int id);
    inline AgentStatus getStatus() const { return Status_.load(std::memory_order_acquire); }

    void run();

private:
    void onExecutionDone(const ExecResult_t& res);
    void collectDumpedInput();
    inline void setStatus(AgentStatus s) { Status_.store(s, std::memory_order_release); }
};
