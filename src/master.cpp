#include "master.hpp"

#include <iostream>


Master_t::Master_t(const FuzzerConfig_t& conf)
    : Config_(conf), Corpus_(), Agents_() {
    nyx_config_set_workdir_path(Config_.nyxConf, Config_.workdir.c_str());
    nyx_config_set_input_buffer_size(Config_.nyxConf, Config_.kAgentPayloadBytes);
    nyx_config_set_input_buffer_write_protection(Config_.nyxConf, true);
    nyx_config_set_process_role(Config_.nyxConf, StandAlone);
    if (Config_.verbose) nyx_config_set_hprintf_fd(Config_.nyxConf, STDERR_FILENO);

    DebugPrint<0>("master", "Starting QEMU-Nyx (waiting for the root snapshot)...\n");

    for(unsigned long i = 0; i < Config_.nAgents; i++){
        Agents_.emplace_back(Corpus_, Config_, i);

        if(Agents_.back().getStatus() != AgentStatus::Ready){
            DebugPrint<0>("master", "Failed to start agent {}\n", i);
            Agents_.pop_back();
        } else {
            DebugPrint<1>("master", "Agent {} ready to run\n", i);
        }
    }
}