#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>

#include "nyx.hpp"
#include "utils.hpp"

using NyxProcessPtr = std::unique_ptr<NyxProcess, decltype(&nyx_shutdown)>;

// Settings every NyxProcess of this fuzzer needs (workdir, payload size, ...).
// Call once on config.nyxConf before the first Executor_t is created.
void configureNyx(const FuzzerConfig_t &config);

// The VM cannot go on after one of these.
inline bool isFatal(NyxReturnValue r) { return r == Error || r == IoError || r == Abort; }

struct ExecOutcome_t
{
    NyxReturnValue ret;
    std::string_view aux; // only valid until the next exec()
};

// One QEMU-Nyx VM: runs an input from the root snapshot and reports how it ended.
// Used by the agents (fuzzing), the reproducer and the minimizer. Not thread-safe.
class Executor_t
{
public:
    // Blocks until the VM reached its root snapshot. Check ok() afterwards.
    Executor_t(const FuzzerConfig_t &config, unsigned int id);

    bool ok() const { return static_cast<bool>(Proc_); }

    // `input` must not be empty nor larger than maxInputSize(config).
    ExecOutcome_t exec(std::span<const uint8_t> input);

    // Coverage bitmap of the last exec(). Shared memory owned by the process:
    // the span stays valid for the lifetime of the executor.
    std::span<const uint8_t> bitmap() const { return Bitmap_; }

private:
    // Shut down automatically by the unique_ptr deleter (nyx_shutdown).
    NyxProcessPtr Proc_;
    std::span<const uint8_t> Bitmap_;
    std::array<char, 1024> Aux_{};
};
