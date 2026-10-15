#include "corpus.hpp"

#include <fmt/format.h>
#include <system_error>


Corpus_t::Corpus_t(std::unique_ptr<Oracle_t> oracle, std::size_t maxInputSize)
    : Oracle_(std::move(oracle)), MaxInputSize_(maxInputSize) {}


void Corpus_t::enablePersistence(const std::filesystem::path& root) {
    std::error_code ec;
    const auto corpusDir = root / "corpus";
    const auto crashDir  = root / "crashes";
    std::filesystem::create_directories(corpusDir, ec);
    std::filesystem::create_directories(crashDir, ec);
    if (ec) {
        DebugPrint<0>("corpus", "Cannot create output dirs in {}: {}\n", root.string(), ec.message());
        return;
    }
    CorpusDir_ = corpusDir;
    CrashDir_  = crashDir;
}


std::size_t Corpus_t::loadSeeds(const std::filesystem::path& dir) {
    std::error_code ec;
    std::size_t loaded = 0;
    for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        if (!entry.is_regular_file(ec)) continue;
        if (auto data = readFile(entry.path()); data && add(std::move(*data), "seed"))
            ++loaded;
    }
    if (ec) DebugPrint<0>("corpus", "Cannot read seeds from {}: {}\n", dir.string(), ec.message());
    return loaded;
}


bool Corpus_t::add(Input_t data, std::string_view origin) {
    if (data.size() > MaxInputSize_) data.resize(MaxInputSize_);
    if (data.empty()) return false;

    const uint64_t h = fnv1a64(data);
    auto entry = std::make_shared<const Input_t>(std::move(data));  // allocate outside the lock

    std::size_t id;
    {
        std::unique_lock lock(Mutex_);
        if (!Hashes_.insert(h).second) return false;
        id = Entries_.size();
        Entries_.push_back(entry);
    }

    DebugPrint<1>("corpus", "New entry #{} ({} bytes, from {})\n", id, entry->size(), origin);
    if (!CorpusDir_.empty())
        writeFile(CorpusDir_ / fmt::format("id_{:06}_{}_{:016x}", id, origin, h), *entry);
    return true;
}


InputPtr Corpus_t::pick(Rng_t& rng) const {
    std::shared_lock lock(Mutex_);
    if (Entries_.empty()) return nullptr;
    return Entries_[randBelow(rng, Entries_.size())];
}


void Corpus_t::onExecution(const ExecResult_t& res) {
    Execs_.fetch_add(1, std::memory_order_relaxed);

    switch (Oracle_->evaluate(res)) {
    case Verdict::Boring:
        return;
    case Verdict::Interesting:
        add(Input_t(res.input.begin(), res.input.end()), fmt::format("agent{}", res.agentId));
        return;
    case Verdict::Objective:
        saveObjective(res);
        return;
    }
}


void Corpus_t::saveObjective(const ExecResult_t& res) {
    const uint64_t h = fnv1a64(res.input);
    {
        std::lock_guard lock(ObjMutex_);
        if (!ObjHashes_.insert(h).second) return;
    }
    const uint64_t n = Objectives_.fetch_add(1, std::memory_order_relaxed);

    DebugPrint<0>("corpus", "[!] {} found by agent {} ({} bytes)\n",
                  ret_name(res.ret), res.agentId, res.input.size());
    if (CrashDir_.empty()) return;

    const auto base = CrashDir_ / fmt::format("{}_{:04}_{:016x}", ret_name(res.ret), n, h);
    writeFile(base, res.input);
    if (!res.aux.empty()) writeFile(base.string() + ".aux", res.aux);
}


std::size_t Corpus_t::size() const {
    std::shared_lock lock(Mutex_);
    return Entries_.size();
}


Corpus_t::Stats_t Corpus_t::stats() const {
    return {Execs_.load(std::memory_order_relaxed), size(), Objectives_.load(std::memory_order_relaxed)};
}
