#pragma once

#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include "agent.hpp"
#include "corpus.hpp"
#include "utils.hpp"


class Master_t {
public:
    Master_t(const FuzzerConfig_t& conf);
    void run();
private:
    void printStats(std::chrono::steady_clock::time_point start) const;

    FuzzerConfig_t Config_;
    CorpusPtr Corpus_;
    std::vector<std::unique_ptr<Agent_t>> Agents_;
};
