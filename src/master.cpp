#include "master.hpp"

#include <algorithm>
#include <future>
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
}


void Master_t::run() {
    DebugPrint<0>("master", "Starting QEMU-Nyx (waiting for the root snapshot)...\n");

    std::promise<void> startPromise;
    const std::shared_future<void> start = startPromise.get_future().share();
    std::vector<std::thread> threads;
    threads.reserve(Config_.nAgents);
    Agents_.resize(Config_.nAgents);

    std::size_t readyCount = 0;
    for (unsigned long i = 0; i < Config_.nAgents; i++) {
        const auto role = Config_.nAgents <= 1 ? StandAlone : (i == 0 ? Parent : Child);
        nyx_config_set_process_role(Config_.nyxConf, role);

        std::promise<bool> created;
        std::future<bool> createdFut = created.get_future();

        threads.emplace_back([this, i, start, created = std::move(created)]() mutable {
            bool ok = false;
            try {
                Agents_[i] = std::make_unique<Agent_t>(Corpus_, Config_, static_cast<unsigned int>(i));
                ok = Agents_[i]->getStatus() == AgentStatus::Ready;
            } catch (const std::exception& e) {
                DebugPrint<0>("master", "Agent {} threw: {}\n", i, e.what());
            }
            created.set_value(ok);
            if (!ok) return;

            start.wait();          // wait until the master has set up the corpus
            Agents_[i]->run();     // returns at once if g_stop is already set
        });

        if (!createdFut.get()) {
            DebugPrint<0>("master", "Failed to start agent {}\n", i);
            if (i == 0 && Config_.nAgents > 1) {
                DebugPrint<0>("master", "Parent agent failed, children can't start\n");
                break;
            }
            continue;
        }

        DebugPrint<1>("master", "Agent {} ready to run\n", i);
        ++readyCount;
    }

    if (readyCount == 0) {
        DebugPrint<0>("master", "No agent to run. Returning...\n");
        startPromise.set_value();
        for (auto& t : threads) t.join();
        return;
    }

    Corpus_->enablePersistence(Config_.workdir);

    if (!Config_.seedsDir.empty()) {
        const auto n = Corpus_->loadSeeds(Config_.seedsDir);
        DebugPrint<0>("master", "Loaded {} seed(s) from {}\n", n, Config_.seedsDir);
    }
    if (Corpus_->size() == 0){
        std::unique_ptr<Mutator_t> tempMut = MutatorRegistry_t::instance().create(Config_.mutator);
        if(!tempMut) {
            DebugPrint<0>("master", "[-] unknown mutator '{}'\n", Config_.mutator);
            return;
        }
        Corpus_->add(tempMut->emptyInput(), "default");
    }

    DebugPrint<0>("master", "Fuzzing with {} agent(s), mutator '{}', oracle '{}'\n",
                  readyCount, Config_.mutator, Corpus_->oracle().name());

    const auto startTime = std::chrono::steady_clock::now();
    startPromise.set_value();

    // Periodic stats while any agent is alive.
    using namespace std::chrono_literals;
    auto lastPrint = startTime;
    auto anyAlive = [this] {
        return std::any_of(Agents_.begin(), Agents_.end(), [](const auto& a) {
            if (!a) return false;
            const auto s = a->getStatus();
            return s == AgentStatus::Ready || s == AgentStatus::Running;
        });
    };
    while (anyAlive()) {
        std::this_thread::sleep_for(100ms);
        if (const auto now = std::chrono::steady_clock::now(); now - lastPrint >= 5s) {
            lastPrint = now;
            printStats(startTime);
        }
    }

    for (auto& t : threads)
        t.join();

    printStats(startTime);
}


void Master_t::printStats(std::chrono::steady_clock::time_point start) const {
    const auto s = Corpus_->stats();
    const double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    DebugPrint<0>("master", "execs: {} ({:.1f}/s) | corpus: {} | objectives: {}\n",
                  s.execs, secs > 0 ? s.execs / secs : 0.0, s.entries, s.objectives);
}
