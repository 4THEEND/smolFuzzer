#pragma once

#include <vector>
#include <string>

#include "agent.hpp"
#include "corpus.hpp"


struct FuzzerConfig_t {
    std::string sharedir;
    std::string workdir;
    unsigned long nAgents;
    unsigned long runs;
    unsigned long timeout_ms;
    bool verbose;
    std::size_t kAgentPayloadBytes;
    void* nyxConf;
};


class Master_t {
public:
    Master_t(const FuzzerConfig_t& conf);
private:
    FuzzerConfig_t Config_;
    CorpusPtr Corpus_;
    std::vector<Agent_t> Agents_;
};