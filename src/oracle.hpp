#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <span>
#include <string_view>

#include "nyx.hpp"
#include "utils.hpp"

inline std::string_view ret_name(NyxReturnValue r)
{
    switch (r)
    {
    case Normal:
        return "Normal";
    case Crash:
        return "Crash";
    case Asan:
        return "Asan";
    case Timeout:
        return "Timeout";
    case InvalidWriteToPayload:
        return "InvalidWriteToPayload";
    case Error:
        return "Error";
    case IoError:
        return "IoError";
    case Abort:
        return "Abort";
    default:
        return "Unknown";
    }
}

// Everything an oracle may look at after one VM execution.
// All views are only valid for the duration of the post-execution callback.
struct ExecResult_t
{
    unsigned int agentId;
    NyxReturnValue ret;
    std::span<const uint8_t> input;
    std::span<const uint8_t> bitmap;
    std::string_view aux;
};

enum class Verdict
{
    Boring,      // drop it
    Interesting, // add it to the corpus
    Objective    // crash / bug: save it in crashes/
};

class Oracle_t
{
public:
    virtual ~Oracle_t() = default;
    virtual Verdict evaluate(const ExecResult_t &res) = 0;
    virtual std::string_view name() const = 0;
};

class VirginMap_t
{
public:
    bool update(std::span<const uint8_t> bitmap);

private:
    std::once_flag Init_;
    std::unique_ptr<std::atomic<uint8_t>[]> Bits_;
    std::size_t Size_ = 0;
};

// Default oracle:
//  - Normal exit with new coverage        -> Interesting
//  - Crash/Asan with new "crash coverage" -> Objective (cheap crash dedup)
//  - anything else                        -> Boring
class CoverageOracle_t final : public Oracle_t
{
public:
    Verdict evaluate(const ExecResult_t &res) override;
    std::string_view name() const override { return "coverage"; }

private:
    VirginMap_t Coverage_;
    VirginMap_t CrashCoverage_;
};
