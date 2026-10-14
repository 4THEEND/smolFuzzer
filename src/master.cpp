#include "master.hpp"
#include "utils.hpp"

#include <iostream>


Master_t::Master_t(const FuzzerConfig_t& conf)
    : Config_(conf), Agents_(conf.nAgents) {
    nyx_config_set_workdir_path(Config_.nyxConf, Config_.workdir.c_str());
    nyx_config_set_input_buffer_size(Config_.nyxConf, Config_.kAgentPayloadBytes);
    nyx_config_set_input_buffer_write_protection(Config_.nyxConf, true);
    nyx_config_set_process_role(Config_.nyxConf, StandAlone);
    if (Config_.verbose) nyx_config_set_hprintf_fd(Config_.nyxConf, STDERR_FILENO);

    DebugPrint<0>("master", "Starting QEMU-Nyx (waiting for the root snapshot)...\n");
}