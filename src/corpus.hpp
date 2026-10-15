#pragma once

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "oracle.hpp"
#include "utils.hpp"


// Shared by all agents.
class Corpus_t {
public:
    struct Stats_t {
        uint64_t execs;
        std::size_t entries;
        uint64_t objectives;
    };

    Corpus_t(std::unique_ptr<Oracle_t> oracle, std::size_t maxInputSize);

    // Must be called before agents start (creates <root>/corpus and <root>/crashes).
    void enablePersistence(const std::filesystem::path& root);
    std::size_t loadSeeds(const std::filesystem::path& dir);

    // Returns false if the input was a duplicate (or empty).
    bool add(Input_t data, std::string_view origin);

    // Uniform pick; nullptr only if the corpus is empty.
    InputPtr pick(Rng_t& rng) const;

    void onExecution(const ExecResult_t& res);

    std::size_t size() const;
    Stats_t stats() const;
    const Oracle_t& oracle() const { return *Oracle_; }

private:
    void saveObjective(const ExecResult_t& res);

    std::unique_ptr<Oracle_t> Oracle_;
    std::size_t MaxInputSize_;

    mutable std::shared_mutex Mutex_;
    std::vector<InputPtr> Entries_;
    std::unordered_set<uint64_t> Hashes_;

    std::mutex ObjMutex_;
    std::unordered_set<uint64_t> ObjHashes_;

    std::filesystem::path CorpusDir_;   // empty = no persistence
    std::filesystem::path CrashDir_;

    std::atomic<uint64_t> Execs_{0};
    std::atomic<uint64_t> Objectives_{0};
};
