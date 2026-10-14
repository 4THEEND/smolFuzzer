#pragma once

#include <string>
#include <fmt/core.h>

constexpr int DebugLevel = 1;

template <int Level, typename... Args_t>
void DebugPrint(std::string agent, const char *Format, const Args_t &...args) {
  if constexpr (Level <= DebugLevel) {
    fmt::print("[{}] ", agent);
    fmt::print(fmt::runtime(Format), args...);
  }
}


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