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
    std::span<const uint8_t> input;  // the testcase that was executed
    std::span<const uint8_t> bitmap; // coverage bitmap of this agent's VM
    std::string_view aux;            // aux string returned by the agent
};

enum class Verdict
{
    Boring,      // drop it
    Interesting, // add it to the corpus
    Objective    // crash / bug: save it in crashes/
};

// Abstract oracle. A single instance is shared by every agent, so
// evaluate() MUST be thread-safe.
class Oracle_t
{
public:
    virtual ~Oracle_t() = default;
    virtual Verdict evaluate(const ExecResult_t &res) = 0;
    virtual std::string_view name() const = 0;
};

// AFL-style "virgin map": remembers which (edge, hit-count bucket) pairs were
// already seen. Lock-free: every byte is an atomic, and fetch_or tells exactly
// one thread that a given bit is new, even when agents race on it.
class VirginMap_t
{
public:
    enum class Result
    {
        NoCoverage, // bitmap is empty or all zeros: nothing to judge on
        Known,      // only already-seen buckets
        NewBits     // at least one never-seen bucket
    };
    Result update(std::span<const uint8_t> bitmap);

private:
    std::once_flag Init_;
    std::unique_ptr<std::atomic<uint8_t>[]> Bits_;
    std::size_t Size_ = 0;
};

// Default oracle:
//  - Normal exit with new coverage        -> Interesting
//  - Crash/Asan with new "crash coverage" -> Objective (cheap crash dedup)
//  - Crash/Asan without any coverage      -> Objective (deduped by content
//    in the corpus), so crashes are kept when running without coverage
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
