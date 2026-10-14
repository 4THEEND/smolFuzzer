#pragma once

#include <vector>
#include <string>

#include "agent.hpp"
#include "corpus.hpp"
#include "utils.hpp"


class Master_t {
public:
    Master_t(const FuzzerConfig_t& conf);
private:
    FuzzerConfig_t Config_;
    CorpusPtr Corpus_;
    std::vector<Agent_t> Agents_;
};