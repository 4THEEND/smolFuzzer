#include <csignal>
#include <cstdint>
#include <iostream>
#include <string>

#include <argparse/argparse.hpp>

#include "nyx.hpp"
#include "master.hpp"
#include "mutator.hpp"
#include "utils.hpp"


constexpr std::size_t kAgentPayloadBytes = 64 * 1024;  // PAYLOAD_SIZE * 1024 in the driver


int main(int argc, char **argv) {
    argparse::ArgumentParser program("nyxfuzz", "1.0", argparse::default_arguments::help);

    program.add_argument("-s", "--sharedir")
        .required()
        .metavar("DIR")
        .help("Nyx sharedir (contains config.ron)");

    program.add_argument("-w", "--workdir")
        .required()
        .metavar("DIR")
        .help("libnyx workdir (fresh one per run)");

    program.add_argument("-i", "--seeds")
        .default_value(std::string{})
        .metavar("DIR")
        .help("directory of initial inputs (optional)");

    program.add_argument("-m", "--mutator")
        .default_value(std::string{"havoc"})
        .metavar("NAME")
        .help("mutation strategy, one of:\n" + MutatorRegistry_t::instance().describe());

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

    const auto mutator = program.get<std::string>("--mutator");
    if (!MutatorRegistry_t::instance().contains(mutator)) {
        std::cerr << "Unknown mutator '" << mutator << "'. Available:\n"
                  << MutatorRegistry_t::instance().describe();
        return 1;
    }

    const auto sharedir = program.get<std::string>("--sharedir");
    void* nyxConf = nyx_config_load(sharedir.c_str());
    if (!nyxConf) {
        DebugPrint<0>("-", "nyx_config_load failed\n");
        return 1;
    }

    FuzzerConfig_t config{
        .sharedir           = sharedir,
        .workdir            = program.get<std::string>("--workdir"),
        .seedsDir           = program.get<std::string>("--seeds"),
        .mutator            = mutator,
        .nAgents            = program.get<unsigned long>("--agents"),
        .runs               = program.get<unsigned long>("--runs"),
        .timeout_ms         = program.get<unsigned long>("--timeout"),
        .verbose            = program.get<bool>("--verbose"),
        .kAgentPayloadBytes = kAgentPayloadBytes,
        .nyxConf            = nyxConf,
    };

    // Ability to stop on a Ctrl-C
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    Master_t masterFuzzer(config);
    masterFuzzer.run();

    return 0;
}
