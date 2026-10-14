#include <array>
#include <csignal>
#include <cstdint>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>

#include <unistd.h>

#include <argparse/argparse.hpp>

extern "C" {
#include "libnyx.h"
}


#include "master.hpp"
#include "utils.hpp"


namespace {

constexpr std::size_t kAgentPayloadBytes = 64 * 1024;  // PAYLOAD_SIZE * 1024 in the driver

volatile std::sig_atomic_t g_stop = 0;
extern "C" void on_signal(int) { g_stop = 1; }

std::string_view ret_name(NyxReturnValue r) {
    switch (r) {
    case Normal:                return "Normal";
    case Crash:                 return "Crash";
    case Asan:                  return "Asan";
    case Timeout:               return "Timeout";
    case InvalidWriteToPayload: return "InvalidWriteToPayload";
    case Error:                 return "Error";
    case IoError:               return "IoError";
    case Abort:                 return "Abort";
    default:                    return "Unknown";
    }
}

using NyxProcessPtr = std::unique_ptr<NyxProcess, decltype(&nyx_shutdown)>;

}  // namespace

int main(int argc, char **argv) {
    // Only add -h/--help automatically; argparse's default -v/--version would clash with -v (verbose).
    argparse::ArgumentParser program("nyxfuzz", "1.0", argparse::default_arguments::help);

    program.add_argument("-s", "--sharedir")
        .required()
        .metavar("DIR")
        .help("Nyx sharedir (contains config.ron)");

    program.add_argument("-w", "--workdir")
        .required()
        .metavar("DIR")
        .help("libnyx workdir (fresh one per run)");

    program.add_argument("-n", "--agents")
        .default_value(1UL)
        .scan<'u', unsigned long>()
        .metavar("N")
        .help("number of agents to run");

    program.add_argument("-N", "--runs")
        .default_value(1UL)
        .scan<'u', unsigned long>()
        .metavar("N")
        .help("number of executions per agent (0 = until Ctrl-C)");

    program.add_argument("-t", "--timeout")
        .default_value(2000UL)
        .scan<'u', unsigned long>()
        .metavar("MS")
        .help("per-execution timeout in ms");

    program.add_argument("-v", "--verbose")
        .default_value(false)
        .implicit_value(true)
        .help("forward guest hprintf output to stderr");

    try {
        program.parse_args(argc, argv);
    } catch (const std::exception &err) {
        std::cerr << err.what() << '\n' << program;
        return 1;
    }

    FuzzerConfig_t config{
        .sharedir   = program.get<std::string>("--sharedir"),
        .workdir    = program.get<std::string>("--workdir"),
        .nAgents       = program.get<unsigned long>("--agents"),
        .runs       = program.get<unsigned long>("--runs"),
        .timeout_ms = program.get<unsigned long>("--timeout"),
        .verbose    = program.get<bool>("--verbose"),
        .kAgentPayloadBytes = kAgentPayloadBytes,
        .nyxConf = nyx_config_load(config.sharedir.c_str())
    };

    if (!config.nyxConf) {
        DebugPrint<0>("-", "nyx_config_load failed\n");
        return 1;
    }

    Master_t masterFuzzer(config);


    /*

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    // Dummy input: fixed bytes, the agent can ignore or parse them
    std::array<uint8_t, 4> input{0xde, 0xaa, 0xbe, 0xef};
    std::array<char, 1024> aux{};

    for (unsigned long i = 0; !g_stop && (runs == 0 || i < runs); ++i) {
        nyx_set_afl_input(proc.get(), input.data(), static_cast<uint32_t>(input.size()));
        const NyxReturnValue r = nyx_exec(proc.get());

        uint32_t n = nyx_get_aux_string(proc.get(), reinterpret_cast<uint8_t *>(aux.data()),
                                        static_cast<uint32_t>(aux.size() - 1));
        n = std::min<uint32_t>(n, aux.size() - 1);
        const std::string_view aux_str(aux.data(), n);

        std::cout << '[' << i << "] " << ret_name(r);
        if (!aux_str.empty()) std::cout << " | " << aux_str;
        std::cout << std::endl;

        if (r == Error || r == IoError || r == Abort) break;
    }

    // proc is shut down automatically by the unique_ptr deleter (nyx_shutdown) */
    return 0;
}