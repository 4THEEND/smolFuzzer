#pragma once

#include <string>
#include <csignal>
#include <fmt/core.h>


// Logging options

constexpr int DebugLevel = 1;

template <int Level, typename... Args_t>
void DebugPrint(std::string agent, const char *Format, const Args_t &...args) {
  if constexpr (Level <= DebugLevel) {
    fmt::print("[{}] ", agent);
    fmt::print(fmt::runtime(Format), args...);
  }
}


// Fuzzing configuration struct


struct FuzzerConfig_t {
    std::string sharedir;
    std::string workdir;
    unsigned long nAgents;
    unsigned long runs;
    unsigned long timeout_ms;
    bool verbose;
    std::size_t kAgentPayloadBytes;
    void* nyxConf;
};


// Stopping fuzzing

inline volatile std::sig_atomic_t g_stop = 0;
extern "C" inline void on_signal(int) { g_stop = 1; }