#pragma once

#include <memory>
#include <functional>
#include <thread>
#include <atomic>

extern "C" {
#include "libnyx.h"
}
#include "corpus.hpp"
#include "utils.hpp"


using NyxProcessPtr = std::unique_ptr<NyxProcess, decltype(&nyx_shutdown)>;
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
    // Proc_ is shut down automatically by the unique_ptr deleter (nyx_shutdown)
    NyxProcessPtr Proc_;
    unsigned int AgentId_;
    std::atomic<AgentStatus> Status_;

public:
    // Since using std::atomic
    Agent_t(const Agent_t&) = delete;
    Agent_t& operator=(const Agent_t&) = delete;

    Agent_t(CorpusPtr Corpus, const FuzzerConfig_t& config, unsigned int id);
    inline AgentStatus getStatus(){ return Status_.load(std::memory_order_acquire); };
    inline std::thread spawn(){ return std::thread(&Agent_t::run, this); };
private:
    void run();
    inline void setStatus(AgentStatus s) { Status_.store(s, std::memory_order_release); }
};