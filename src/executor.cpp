#include "executor.hpp"

#include <algorithm>

#include <unistd.h>

void configureNyx(const FuzzerConfig_t &config)
{
    nyx_config_set_workdir_path(config.nyxConf, config.workdir.c_str());
    nyx_config_set_input_buffer_size(config.nyxConf, config.kAgentPayloadBytes);
    nyx_config_set_input_buffer_write_protection(config.nyxConf, true);
    if (config.verbose)
        nyx_config_set_hprintf_fd(config.nyxConf, STDERR_FILENO);
}

Executor_t::Executor_t(const FuzzerConfig_t &config, unsigned int id)
    : Proc_(nyx_new(config.nyxConf, id), &nyx_shutdown)
{
    if (!Proc_)
        return;

    Bitmap_ = std::span<const uint8_t>(nyx_get_bitmap_buffer(Proc_.get()),
                                       nyx_get_bitmap_buffer_size(Proc_.get()));

    const auto sec = std::min(config.timeout_ms / 1000, 255UL);
    const auto usec = (config.timeout_ms % 1000) * 1000;
    nyx_option_set_reload_mode(Proc_.get(), true);
    nyx_option_set_timeout(Proc_.get(), static_cast<uint8_t>(sec), static_cast<uint32_t>(usec));
    nyx_option_apply(Proc_.get());
}

ExecOutcome_t Executor_t::exec(std::span<const uint8_t> input)
{
    // libnyx takes a non-const pointer but only copies from it.
    nyx_set_afl_input(Proc_.get(), const_cast<uint8_t *>(input.data()), static_cast<uint32_t>(input.size()));
    const NyxReturnValue r = nyx_exec(Proc_.get());

    uint32_t n = nyx_get_aux_string(Proc_.get(), reinterpret_cast<uint8_t *>(Aux_.data()),
                                    static_cast<uint32_t>(Aux_.size() - 1));
    n = std::min<uint32_t>(n, Aux_.size() - 1);
    return {r, std::string_view(Aux_.data(), n)};
}
