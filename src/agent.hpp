#pragma once

#include <memory>
#include <functional>

extern "C" {
#include "libnyx.h"
}
#include "corpus.hpp"


using NyxProcessPtr = std::unique_ptr<NyxProcess, decltype(&nyx_shutdown)>;
using CorpusPtr = std::shared_ptr<Corpus_t>;


class Agent_t {
public:
    Agent_t(CorpusPtr Corpus, void* nyxCfg);

private:
    CorpusPtr Corpus_;
    NyxProcessPtr Proc_;
};