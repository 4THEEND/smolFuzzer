#pragma once

#include <memory>
#include <functional>

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
    CorpusPtr Corpus_;
    NyxProcessPtr Proc_;
    unsigned int AgentId_;
    AgentStatus Status_;

public:
    Agent_t(CorpusPtr Corpus, const FuzzerConfig_t& config, unsigned int id);
    inline AgentStatus getStatus(){ return Status_; };
};