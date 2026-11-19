// sysmon_argpool.hpp - pool of observed syscall arguments, organised by type.
//
// Feed it decoded calls; it files every distinct argument under its C type
// ("HWND", "UINT", "PLARGE_STRING", ...) and remembers which threads passed it.
// You can then draw a random argument of a given type, from all threads or
// from one. Every distinct argument is equally likely to be drawn.
//
// Header-only, C++17. Not thread-safe: guard it yourself if shared.
#pragma once

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <map>
#include <optional>
#include <ostream>
#include <random>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "sysmon_decode.hpp"

namespace sysmon {

// One distinct argument plus where it was seen.
struct PooledArg {
    Arg              arg;            // type, value, captured bytes/text/fields
    std::vector<std::uint64_t> threadIds;   // every thread that passed it, in order first seen

    // First observation:
    std::uint64_t    processId = 0;
    std::uint64_t    threadId = 0;
    std::uint32_t    ssn = 0;
    std::string_view syscall;        // e.g. "NtUserSetWindowPos"
    std::uint64_t    sequence = 0;   // record it was taken from

    bool SeenBy(std::uint64_t tid) const {
        return std::find(threadIds.begin(), threadIds.end(), tid) != threadIds.end();
    }
};

// The pool is a set: an argument is stored once per type, however many times
// and by however many threads it was passed. Two arguments are the same when
// they have the same type and
//   - the same pointed-to data, if data was captured (the address is ignored,
//     so one string passed from different stack addresses is one element), or
//   - the same raw value otherwise.
class ArgPool {
public:
    // Add every argument of a decoded call. Calls the decoder could not
    // identify (unknown syscall, malformed record) are skipped, because their
    // arguments have no type. Returns how many NEW elements this added;
    // arguments already in the pool only gain the calling thread.
    // If `newTypes` is given, the type of each new element is appended to it.
    std::size_t Add(const Call& call, std::vector<std::string_view>* newTypes = nullptr) {
        if (!call.known || call.malformed) return 0;
        std::size_t added = 0;
        for (const Arg& a : call.args) {
            Bucket& bucket = byType_[std::string(a.type)];
            const auto [slot, isNew] = ids_.try_emplace(Key(a), static_cast<std::uint32_t>(items_.size()));
            const std::uint32_t id = slot->second;
            if (isNew) {
                PooledArg item;
                item.arg = a;
                item.processId = call.processId;
                item.threadId = call.threadId;
                item.ssn = call.ssn;
                item.syscall = call.name;
                item.sequence = call.sequence;
                items_.push_back(std::move(item));
                bucket.all.push_back(id);
                ++added;
                if (newTypes != nullptr) newTypes->push_back(a.type);
            }
            PooledArg& item = items_[id];
            if (!item.SeenBy(call.threadId)) {
                item.threadIds.push_back(call.threadId);
                bucket.byThread[call.threadId].push_back(id);
            }
        }
        return added;
    }

    // Whether an equal argument (see above) is already in the pool.
    bool Contains(const Arg& a) const { return ids_.count(Key(a)) != 0; }

    // A random argument of `type`, or nullptr if the pool has none. Each
    // distinct argument has the same chance. With `threadId`, only arguments
    // that thread passed are considered.
    // The pointer stays valid until the pool is cleared or destroyed.
    template <typename Rng>
    const PooledArg* Pick(std::string_view type, Rng& rng,
                          std::optional<std::uint64_t> threadId = std::nullopt) const {
        const std::vector<std::uint32_t>* ids = Ids(type, threadId);
        if (ids == nullptr || ids->empty()) return nullptr;
        std::uniform_int_distribution<std::size_t> pick(0, ids->size() - 1);
        return &items_[(*ids)[pick(rng)]];
    }

    // Number of distinct arguments: in total, of one type, or of one type for one thread.
    std::size_t Size() const { return items_.size(); }
    std::size_t Count(std::string_view type,
                      std::optional<std::uint64_t> threadId = std::nullopt) const {
        const std::vector<std::uint32_t>* ids = Ids(type, threadId);
        return ids ? ids->size() : 0;
    }

    // Types present in the pool (sorted); with `threadId`, only that thread's.
    std::vector<std::string_view> Types(std::optional<std::uint64_t> threadId = std::nullopt) const {
        std::vector<std::string_view> out;
        for (const auto& [type, bucket] : byType_) {
            if (!threadId || bucket.byThread.count(*threadId)) out.push_back(type);
        }
        return out;
    }

    // Thread ids that contributed at least one argument (sorted).
    std::vector<std::uint64_t> Threads() const {
        std::map<std::uint64_t, bool> seen;
        for (const auto& [type, bucket] : byType_) {
            (void)type;
            for (const auto& [tid, ids] : bucket.byThread) { (void)ids; seen[tid] = true; }
        }
        std::vector<std::uint64_t> out;
        for (const auto& [tid, unused] : seen) { (void)unused; out.push_back(tid); }
        return out;
    }

    void Clear() {
        items_.clear();
        byType_.clear();
        ids_.clear();
    }

private:
    struct Bucket {
        std::vector<std::uint32_t> all;                                        // every thread
        std::unordered_map<std::uint64_t, std::vector<std::uint32_t>> byThread;
    };

    const std::vector<std::uint32_t>* Ids(std::string_view type,
                                          std::optional<std::uint64_t> threadId) const {
        const auto it = byType_.find(type);
        if (it == byType_.end()) return nullptr;
        if (!threadId) return &it->second.all;
        const auto t = it->second.byThread.find(*threadId);
        return t == it->second.byThread.end() ? nullptr : &t->second;
    }

    // What makes two arguments "the same" (see the class comment).
    static std::string Key(const Arg& a) {
        std::string key(a.type);
        key += '\0';
        if (a.capture == Capture::Ok || a.capture == Capture::Truncated) {
            key += (a.capture == Capture::Ok) ? 'D' : 'T';
            key.append(reinterpret_cast<const char*>(a.data.data()), a.data.size());
        } else {
            key += (a.capture == Capture::Fault) ? 'F' : 'V';
            key.append(reinterpret_cast<const char*>(&a.value), sizeof a.value);
        }
        return key;
    }

    std::deque<PooledArg>                    items_;    // deque: growth keeps addresses stable
    std::map<std::string, Bucket, std::less<>> byType_; // std::less<> allows string_view lookup
    std::unordered_map<std::string, std::uint32_t> ids_;  // identity -> index in items_
};

// Records how the pool grows, one CSV row per call added, for plot_pool_growth.py:
//
//   call,timestamp,time,pid,tid,syscall,pool_size,new_args,new_by_type
//   17,134078299231234567,2026-11-17 12:30:46.0711210,11464,7932,NtUserMessageCall,41,2,HWND:1;LPARAM:1
//
// `pool_size` is the number of distinct arguments after the call, `new_args`
// how many of them this call contributed, `new_by_type` the same per type.
// Use Add() below instead of pool.Add() and the log follows automatically.
class PoolGrowthLog {
public:
    // `out` must outlive the log. Writes the header line.
    explicit PoolGrowthLog(std::ostream& out) : out_(out) {
        out_ << "call,timestamp,time,pid,tid,syscall,pool_size,new_args,new_by_type\n";
    }

    // pool.Add(call), plus one row in the log. Returns pool.Add's result.
    std::size_t Add(ArgPool& pool, const Call& call) {
        newTypes_.clear();
        const std::size_t added = pool.Add(call, &newTypes_);
        if (!call.known || call.malformed) return added;      // not pooled: no row

        std::map<std::string_view, unsigned> perType;
        for (std::string_view t : newTypes_) ++perType[t];

        out_ << ++calls_ << ',' << call.timestamp << ',' << FormatTimestamp(call.timestamp) << ','
             << call.processId << ',' << call.threadId << ',' << call.name << ','
             << pool.Size() << ',' << added << ',';
        const char* sep = "";
        for (const auto& [type, n] : perType) {
            out_ << sep << type << ':' << n;
            sep = ";";
        }
        out_ << '\n';
        return added;
    }

    std::uint64_t Calls() const { return calls_; }

private:
    std::ostream&                 out_;
    std::uint64_t                 calls_ = 0;
    std::vector<std::string_view> newTypes_;
};

// One-line description, e.g.
//   HWND 0x4044a  (first seen: NtUserSetWindowPos a0, tid 7932; 2 threads)
//   PLARGE_STRING 0xde85afe670 -> "Chrome_WidgetWin_1"  (first seen: NtUserCreateWindowEx a1, tid 7932; 1 thread)
inline std::string Describe(const PooledArg& p) {
    char buf[64];
    std::string out(p.arg.type);
    std::snprintf(buf, sizeof buf, p.arg.isAtom ? " atom 0x%llx" : " 0x%llx",
                  static_cast<unsigned long long>(p.arg.value));
    out += buf;
    if (p.arg.capture == Capture::Fault) {
        out += " -> <unreadable>";
    } else if (p.arg.isText) {
        out += " -> \"" + p.arg.text + "\"";
    } else if (p.arg.capture != Capture::None) {
        std::snprintf(buf, sizeof buf, " -> %zu bytes", p.arg.data.size());
        out += buf;
    }
    out += "  (first seen: ";
    out += p.syscall;
    std::snprintf(buf, sizeof buf, " a%u, tid %llu; %zu thread%s)", p.arg.index,
                  static_cast<unsigned long long>(p.threadId), p.threadIds.size(),
                  p.threadIds.size() == 1 ? "" : "s");
    out += buf;
    return out;
}

}  // namespace sysmon
