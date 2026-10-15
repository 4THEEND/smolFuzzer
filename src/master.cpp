#include "master.hpp"

#include <algorithm>
#include <thread>

#include <unistd.h>


Master_t::Master_t(const FuzzerConfig_t& conf)
    : Config_(conf),
      // The oracle is chosen here; swap in any Oracle_t subclass.
      Corpus_(std::make_shared<Corpus_t>(std::make_unique<CoverageOracle_t>(), maxInputSize(conf))),
      Agents_() {
    nyx_config_set_workdir_path(Config_.nyxConf, Config_.workdir.c_str());
    nyx_config_set_input_buffer_size(Config_.nyxConf, Config_.kAgentPayloadBytes);
    nyx_config_set_input_buffer_write_protection(Config_.nyxConf, true);
    if (Config_.verbose) nyx_config_set_hprintf_fd(Config_.nyxConf, STDERR_FILENO);

    DebugPrint<0>("master", "Starting QEMU-Nyx (waiting for the root snapshot)...\n");

    for (unsigned long i = 0; i < Config_.nAgents; i++) {
        // Agent 0 creates the root snapshot
        const auto role = Config_.nAgents <= 1 ? StandAlone : (i == 0 ? Parent : Child);
        nyx_config_set_process_role(Config_.nyxConf, role);

        auto agent = std::make_unique<Agent_t>(Corpus_, Config_, static_cast<unsigned int>(i));

        if (agent->getStatus() != AgentStatus::Ready) {
            DebugPrint<0>("master", "Failed to start agent {}\n", i);
            if (i == 0 && Config_.nAgents > 1) {
                DebugPrint<0>("master", "Parent agent failed, children can't start\n");
                break;
            }
            continue; 
        }

        DebugPrint<1>("master", "Agent {} ready to run\n", i);
        Agents_.push_back(std::move(agent));
    }
}


void Master_t::run() {
    if (Agents_.empty()) {
        DebugPrint<0>("master", "No agent to run. Returning...\n");
        return;
    }

    Corpus_->enablePersistence(Config_.workdir);

    if (!Config_.seedsDir.empty()) {
        const auto n = Corpus_->loadSeeds(Config_.seedsDir);
        DebugPrint<0>("master", "Loaded {} seed(s) from {}\n", n, Config_.seedsDir);
    }
    if (Corpus_->size() == 0)
        Corpus_->add(Input_t{0xde, 0xad, 0xbe, 0xef}, "default");

    DebugPrint<0>("master", "Fuzzing with {} agent(s), mutator '{}', oracle '{}'\n",
                  Agents_.size(), Config_.mutator, Corpus_->oracle().name());

    std::vector<std::thread> agentThreads{};
    agentThreads.reserve(Agents_.size());
    for (auto& agent : Agents_) {
        if (agent->getStatus() == AgentStatus::Ready)
            agentThreads.push_back(agent->spawn());
    }

    // Periodic stats while any agent is alive.
    using namespace std::chrono_literals;
    const auto start = std::chrono::steady_clock::now();
    auto lastPrint = start;
    auto anyAlive = [this] {
        return std::any_of(Agents_.begin(), Agents_.end(), [](const auto& a) {
            const auto s = a->getStatus();
            return s == AgentStatus::Ready || s == AgentStatus::Running;
        });
    };
    while (anyAlive()) {
        std::this_thread::sleep_for(100ms);
        if (const auto now = std::chrono::steady_clock::now(); now - lastPrint >= 5s) {
            lastPrint = now;
            printStats(start);
        }
    }

    for (auto& thread : agentThreads)
        thread.join();

    printStats(start);
}


void Master_t::printStats(std::chrono::steady_clock::time_point start) const {
    const auto s = Corpus_->stats();
    const double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    DebugPrint<0>("master", "execs: {} ({:.1f}/s) | corpus: {} | objectives: {}\n",
                  s.execs, secs > 0 ? s.execs / secs : 0.0, s.entries, s.objectives);
}
