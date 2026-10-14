#include "agent.hpp"


Agent_t::Agent_t(CorpusPtr Corpus, const FuzzerConfig_t& config, unsigned int id)
 : Corpus_(Corpus), Proc_(nyx_new(config.nyxConf, 0), &nyx_shutdown), AgentId_(id), Status_(AgentStatus::Init) {
    if (!Proc_) {
        DebugPrint<0>("agent", "[-] nyx_new failed\n");
        Status_ = AgentStatus::Errored;

        return;
    }

    const auto sec  = std::min(config.timeout_ms / 1000, 255UL);
    const auto usec = (config.timeout_ms % 1000) * 1000;
    nyx_option_set_reload_mode(Proc_.get(), true);
    nyx_option_set_timeout(Proc_.get(), static_cast<uint8_t>(sec), static_cast<uint32_t>(usec));
    nyx_option_apply(Proc_.get());

    Status_ = AgentStatus::Ready;
 }