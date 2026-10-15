#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <optional>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <fmt/core.h>
#include <fmt/format.h>

// Logging
constexpr int DebugLevel = 1;

template <int Level, typename... Args_t>
void DebugPrint(std::string_view who, const char *Format, const Args_t &...args)
{
    if constexpr (Level <= DebugLevel)
    {
        // One single print call so lines coming from concurrent agents don't interleave.
        fmt::print("[{}] {}", who, fmt::format(fmt::runtime(Format), args...));
    }
}

// Fuzzing configuration
struct FuzzerConfig_t
{
    std::string sharedir;
    std::string workdir;
    std::string seedsDir; // optional, empty = no seeds
    std::string mutator;  // name looked up in MutatorRegistry_t
    unsigned long nAgents;
    unsigned long runs;
    unsigned long timeout_ms;
    bool verbose;
    std::size_t kAgentPayloadBytes;
    void *nyxConf;
};

// nyx_set_afl_input() prepends a u32 length to the payload buffer.
inline std::size_t maxInputSize(const FuzzerConfig_t &c)
{
    return c.kAgentPayloadBytes > sizeof(uint32_t) ? c.kAgentPayloadBytes - sizeof(uint32_t) : 0;
}

// Inputs, RNG, hashing, files
using Input_t = std::vector<uint8_t>;
using InputPtr = std::shared_ptr<const Input_t>;
using Rng_t = std::mt19937_64;

inline std::size_t randBelow(Rng_t &rng, std::size_t n)
{
    return n <= 1 ? 0 : std::uniform_int_distribution<std::size_t>(0, n - 1)(rng);
}

inline bool coinFlip(Rng_t &rng) { return (rng() & 1) != 0; }

inline uint64_t fnv1a64(std::span<const uint8_t> data)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    for (const uint8_t b : data)
    {
        h ^= b;
        h *= 0x100000001b3ULL;
    }
    return h;
}

inline std::optional<Input_t> readFile(const std::filesystem::path &path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f)
        return std::nullopt;
    return Input_t(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

inline bool writeFile(const std::filesystem::path &path, std::span<const uint8_t> data)
{
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f)
        return false;
    f.write(reinterpret_cast<const char *>(data.data()), static_cast<std::streamsize>(data.size()));
    return static_cast<bool>(f);
}

inline bool writeFile(const std::filesystem::path &path, std::string_view text)
{
    return writeFile(path, std::span(reinterpret_cast<const uint8_t *>(text.data()), text.size()));
}

// Stopping fuzzing
inline std::atomic<bool> g_stop{false};
static_assert(std::atomic<bool>::is_always_lock_free, "g_stop must be lock-free to be used from a signal handler");

extern "C" inline void on_signal(int) { g_stop.store(true, std::memory_order_relaxed); }
