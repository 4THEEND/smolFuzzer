#pragma once

#include <string>

#include "utils.hpp"

// Options of the two offline tools (nyxfuzz --repro / --minimize).
struct ToolOptions_t
{
    std::string input;      // testcase file (--repro also takes a directory, e.g. <workdir>/crashes)
    std::string output;     // --minimize: where to write the result, empty = <input>.min
    unsigned long tries;    // executions per testcase; when minimizing, per candidate
    bool matchAux;          // --minimize: a candidate must also end with the same aux string
    unsigned long maxExecs; // --minimize: execution budget, 0 = none
};

// Both start one VM on config.workdir (a fresh one, like for fuzzing) and
// return the process exit code.

// Runs each testcase from the root snapshot, prints what it contains and how
// every execution ended. 0 = every testcase misbehaved at least once,
// 2 = at least one always exited normally, 1 = could not run.
int runRepro(const FuzzerConfig_t &config, const ToolOptions_t &opt);

// Reduces a testcase to a smaller, simpler one that ends the same way.
// 0 = result written, 1 = could not run or the testcase does not reproduce.
int runMinimize(const FuzzerConfig_t &config, const ToolOptions_t &opt);
