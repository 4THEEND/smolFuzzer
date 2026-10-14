#include "agent.hpp"


Agent_t::Agent_t(CorpusPtr Corpus, void* nyxCfg)
 : Corpus_(Corpus), Proc_(nyx_new(nyxCfg, 0), &nyx_shutdown) 
{}