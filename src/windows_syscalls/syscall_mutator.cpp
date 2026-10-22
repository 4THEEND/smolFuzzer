// syscall_mutator.cpp - type-aware mutation of decoded syscall batches.
//
// Port of the win32k_mutate tactics (NtFuzz section VI-B1) onto the wire model of
// w32k_decode.hpp. The strategy for an argument is chosen from its ArgKind, not from
// its bytes. The wire format carries less metadata than the recovered database the
// original mutator used, so three tactics are re-derived from the captured data:
//
//   * observed literals - the dictionary for (ssn, arg) is built from the values seen
//                         in this batch and in one other corpus entry; it is only used
//                         when that set is small, i.e. callers really were constrained.
//   * linked counts     - an Array/Buffer's count argument is found by looking for a
//                         nearby scalar whose value divides the blob size into a
//                         plausible element size, so count and buffer can be
//                         desynchronised on purpose.
//   * caller constants  - a leading DWORD equal to the blob size is treated as a
//                         cbSize field and mutated around its known-good value.
//   * direction         - Dir::Out pointees are kernel-written; only the pointer is
//                         mutated unless MutationConfig::mutate_out_pointee is set.
//
// Handles are excluded by default (a bad HANDLE short-circuits the syscall), Post
// events are left alone (they are the kernel's answer, not something we send), and
// every mutation is recorded in a MutationLog together with the seed that produced it.
//
// Raw-pointer convention: when an argument (or a nested pointer) is repointed to a wild
// address, its blob is dropped and its capture flags become NO_SIZE (or NULL for 0), so
// has_data() is false. The replayer must pass `value` / `pointer_value` through
// verbatim in that case instead of materialising a buffer for it.

#include "../mutator.hpp"
#include "w32k_decode.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace Syscall
{
namespace detail
{

/// Deterministic and seedable on purpose: a mutation must be replayable from its log.
class Rng
{
public:
    explicit Rng(std::uint64_t seed = 0x9E3779B97F4A7C15ull) : s_(seed ? seed : 1), seed_(s_) {}

    std::uint64_t next()
    { // splitmix64
        std::uint64_t z = (s_ += 0x9E3779B97F4A7C15ull);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        return z ^ (z >> 31);
    }
    std::uint64_t below(std::uint64_t n) { return n ? next() % n : 0; }
    bool chance(double p) { return p > 0.0 && (next() >> 11) * 0x1.0p-53 < p; }
    template <typename T> const T &pick(const std::vector<T> &v) { return v[below(v.size())]; }
    std::uint64_t seed() const { return seed_; }

private:
    std::uint64_t s_;
    std::uint64_t seed_;
};

/// Values that historically sit on the boundary of a check.
inline const std::vector<std::uint64_t> &interesting32()
{
    static const std::vector<std::uint64_t> v{
        0, 1, 2, 0x7F, 0x80, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF, 0x10000,
        0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF};
    return v;
}

inline const std::vector<std::uint64_t> &interesting64()
{
    static const std::vector<std::uint64_t> v{
        0, 1, 0xFFFFFFFFull, 0x100000000ull, 0x7FFFFFFFFFFFFFFFull,
        0x8000000000000000ull, 0xFFFFFFFFFFFFFFFFull};
    return v;
}

/// Addresses that probe the user/kernel split and the alignment checks.
inline const std::vector<std::uint64_t> &interestingPointers()
{
    static const std::vector<std::uint64_t> v{
        0x0000000000000000ull, // NULL
        0x0000000000000001ull, // unaligned, non-null
        0x000000007FFF0000ull, // 32-bit user boundary
        0x00007FFFFFFF0000ull, // x64 MmUserProbeAddress
        0x00007FFFFFFFFFFFull, // last user address
        0x0000800000000000ull, // first non-canonical
        0xFFFF800000000000ull, // kernel space
        0xFFFFFFFFFFFFFFFFull};
    return v;
}

struct MutationConfig
{
    /// Per-candidate probability; re-drawn per batch by pickProbability().
    double probability = 0.01;
    bool mutate_handles = false;      ///< a bad handle short-circuits the syscall
    bool mutate_out_pointee = false;  ///< the kernel writes there; mutating it is wasted
    bool mutate_pointers = true;      ///< replace the pointer itself with a wild address
    bool mutate_post_events = false;  ///< Post events are kernel output, not input
    bool resize_arrays = true;
    bool desync_counts = true;
    bool use_dictionary = true;       ///< prefer literals other callers were seen to pass
    std::size_t max_dictionary = 16;  ///< a larger value set means "unconstrained"
    /// Ceiling on an array's SIZE in bytes (the unit that matters), plus a backstop.
    std::size_t max_array_bytes = 0x1000;
    std::size_t max_array_elements = 4096;
    std::size_t max_mutations = 16;   ///< cap per batch, so one input stays explainable
    /// At low probability most passes change nothing; force one mutation instead of
    /// burning an execution on an unchanged input.
    bool ensure_progress = true;
};

/// Element count worth trying: boundaries, the neighbourhood of the current count,
/// and a log-uniform spread so every magnitude stays reachable.
inline std::size_t pickElementCount(Rng &rng, std::size_t current, std::size_t cap)
{
    if (cap < 1)
        cap = 1;
    const std::uint64_t roll = rng.below(100);
    if (roll < 25)
    {
        static const std::vector<std::uint64_t> edge{0, 1, 2, 3};
        return static_cast<std::size_t>(std::min<std::uint64_t>(rng.pick(edge), cap));
    }
    if (roll < 50 && current)
    {
        static const std::vector<std::int64_t> d{-2, -1, 1, 2};
        const std::int64_t n = static_cast<std::int64_t>(current) + rng.pick(d);
        return static_cast<std::size_t>(std::clamp<std::int64_t>(n, 0, static_cast<std::int64_t>(cap)));
    }
    if (roll < 90)
    {
        std::size_t bits = 0;
        while ((std::size_t{1} << (bits + 1)) <= cap && bits < 31)
            ++bits;
        const std::size_t mag = static_cast<std::size_t>(rng.below(bits + 1));
        const std::size_t hi = std::min<std::size_t>(std::size_t{1} << mag, cap);
        return static_cast<std::size_t>(rng.below(hi)) + 1;
    }
    return cap;
}

/// The paper's variable-probability strategy: p = 0.01 * 2^n, n in [-3, 3].
inline double pickProbability(Rng &rng)
{
    static const std::array<double, 7> ps{0.00125, 0.0025, 0.005, 0.01, 0.02, 0.04, 0.08};
    return ps[rng.below(ps.size())];
}

// ==================================================================== log ==

enum class Strategy
{
    ScalarBitFlip, ScalarArithmetic, ScalarInteresting, ScalarDictionary, ScalarRandom,
    StructField, StructSizeField, StructPointerField,
    ArrayElement, ArrayResize, ArrayCountDesync,
    StringLength, StringBuffer, StringContent, StringTerminator,
    PointerWild, PointerNull, PointerUnaligned,
    OpaqueBytes
};

inline const char *strategyName(Strategy s)
{
    switch (s)
    {
    case Strategy::ScalarBitFlip: return "scalar.bitflip";
    case Strategy::ScalarArithmetic: return "scalar.arith";
    case Strategy::ScalarInteresting: return "scalar.interesting";
    case Strategy::ScalarDictionary: return "scalar.dictionary";
    case Strategy::ScalarRandom: return "scalar.random";
    case Strategy::StructField: return "struct.field";
    case Strategy::StructSizeField: return "struct.size_field";
    case Strategy::StructPointerField: return "struct.pointer_field";
    case Strategy::ArrayElement: return "array.element";
    case Strategy::ArrayResize: return "array.resize";
    case Strategy::ArrayCountDesync: return "array.count_desync";
    case Strategy::StringLength: return "string.length";
    case Strategy::StringBuffer: return "string.buffer";
    case Strategy::StringContent: return "string.content";
    case Strategy::StringTerminator: return "string.terminator";
    case Strategy::PointerWild: return "pointer.wild";
    case Strategy::PointerNull: return "pointer.null";
    case Strategy::PointerUnaligned: return "pointer.unaligned";
    case Strategy::OpaqueBytes: return "opaque.bytes";
    }
    return "?";
}

struct MutationRecord
{
    std::size_t event = 0;   ///< index in the batch
    std::uint16_t ssn = 0;
    std::size_t arg = 0;
    int nested = -1;         ///< index in EventInfo::nested, -1 for the argument itself
    Strategy strategy = Strategy::ScalarRandom;
    int offset = -1;         ///< byte offset in the blob, -1 when not applicable
    std::uint64_t before = 0, after = 0;
    std::string detail;

    std::string describe() const
    {
        std::ostringstream o;
        o << "e" << event << ' ' << W32k::SyscallName(ssn) << " a" << arg;
        if (nested >= 0)
            o << ".n" << nested;
        o << ' ' << strategyName(strategy);
        if (offset >= 0)
            o << " +0x" << std::hex << offset << std::dec;
        o << ": 0x" << std::hex << before << " -> 0x" << after << std::dec;
        if (!detail.empty())
            o << "  (" << detail << ')';
        return o.str();
    }
};

struct MutationLog
{
    std::uint64_t seed = 0;
    double probability = 0;
    std::vector<MutationRecord> records;

    bool empty() const { return records.empty(); }
    std::string describe() const
    {
        std::ostringstream o;
        o << "seed=0x" << std::hex << seed << std::dec << " p=" << probability << " mutations="
          << records.size() << '\n';
        for (const auto &r : records)
            o << "  " << r.describe() << '\n';
        return o.str();
    }
};

// ============================================================ wire helpers ==

constexpr std::uint32_t kCapfNull = 0x0001u;
constexpr std::uint32_t kCapfTruncated = 0x0002u;
constexpr std::uint32_t kCapfFault = 0x0004u;
constexpr std::uint32_t kCapfNoSize = 0x0020u;
constexpr std::uint32_t kCapfUnterminated = 0x0080u;

inline std::uint64_t widthMask(int w) { return w >= 8 ? ~0ull : ((1ull << (w * 8)) - 1); }

inline int argWidth(const W32k::ArgInfo &a)
{
    switch (a.size)
    {
    case 1: case 2: case 4: case 8: return a.size;
    default: return 8;
    }
}

// Blobs are captured on x64 Windows, so little-endian like the host.
inline std::uint64_t readAt(const std::vector<std::uint8_t> &b, std::size_t off, int size)
{
    std::uint64_t v = 0;
    if (off + static_cast<std::size_t>(size) <= b.size())
        std::memcpy(&v, b.data() + off, static_cast<std::size_t>(size));
    return v;
}

inline void writeAt(std::vector<std::uint8_t> &b, std::size_t off, int size, std::uint64_t v)
{
    if (off + static_cast<std::size_t>(size) <= b.size())
        std::memcpy(b.data() + off, &v, static_cast<std::size_t>(size));
}

/// A canonical, non-tiny user-mode address: probably an inline pointer field.
inline bool looksLikeUserPointer(std::uint64_t v) { return v >= 0x10000ull && v <= 0x00007FFFFFFFFFFFull; }

inline bool isPointerKind(W32k::ArgKind k)
{
    return k == W32k::ArgKind::Pointer || k == W32k::ArgKind::Buffer ||
           k == W32k::ArgKind::Array || k == W32k::ArgKind::String;
}

inline Strategy pointerStrategy(std::uint64_t wild)
{
    if (wild == 0)
        return Strategy::PointerNull;
    if (wild & 1)
        return Strategy::PointerUnaligned;
    return Strategy::PointerWild;
}

/// Replace a captured pointer by a raw value (see the convention at the top).
inline void setRawPointer(W32k::ArgInfo &a, std::uint64_t v)
{
    a.value = v;
    a.data.clear();
    a.requested_length = 0;
    a.capture_flags.bits = v ? kCapfNoSize : kCapfNull;
}

inline void setRawPointer(W32k::NestedInfo &n, std::uint64_t v)
{
    n.pointer_value = v;
    n.data.clear();
    n.requested_length = 0;
    n.capture_flags.bits = v ? kCapfNoSize : kCapfNull;
}

/// Which argument carries this blob's length, and in what unit.
struct LengthLink
{
    int arg = -1;
    std::size_t unit = 0; ///< bytes per count unit (1 for a byte length)
};

inline LengthLink findLengthArg(const W32k::EventInfo &ev, std::size_t idx, bool bytesOnly)
{
    const auto &a = ev.args[idx];
    if (a.is_truncated() || a.data.empty())
        return {}; // a cut-short blob cannot be matched against its count
    const std::size_t bytes = a.data.size();
    static constexpr std::array<std::size_t, 11> kUnits{1, 2, 4, 8, 12, 16, 24, 32, 40, 48, 64};

    // Nearest argument first: counts usually sit right next to their buffer.
    for (std::size_t dist = 1; dist < ev.args.size(); ++dist)
    {
        for (const long long sign : {1LL, -1LL})
        {
            const long long j = static_cast<long long>(idx) + sign * static_cast<long long>(dist);
            if (j < 0 || j >= static_cast<long long>(ev.args.size()))
                continue;
            const auto &c = ev.args[static_cast<std::size_t>(j)];
            if (c.kind != W32k::ArgKind::Scalar && c.kind != W32k::ArgKind::Unknown)
                continue;
            const std::uint64_t n = c.value & widthMask(argWidth(c));
            if (!n || n > bytes || bytes % n)
                continue;
            const std::size_t unit = bytes / static_cast<std::size_t>(n);
            if (bytesOnly ? unit != 1 : std::find(kUnits.begin(), kUnits.end(), unit) == kUnits.end())
                continue;
            if (n == 1 && unit > 8)
                continue; // "1" is too often a flag to trust as a count
            return {static_cast<int>(j), unit};
        }
    }
    return {};
}

/// Element granularity for resizing/walking a blob whose element size is unknown.
inline std::size_t granularity(std::size_t bytes, const LengthLink &link)
{
    if (link.arg >= 0 && link.unit > 1)
        return link.unit;
    if (bytes && bytes % 4 == 0)
        return 4;
    if (bytes && bytes % 2 == 0)
        return 2;
    return 1;
}

} // namespace detail

// ================================================================ mutator ==

class SyscallMutator_t final : public Mutator_t
{
    using ArgKind = W32k::ArgKind;
    using Dir = W32k::Dir;
    using Strategy = detail::Strategy;

public:
    Input_t emptyInput() override { return Input_t{0xde, 0xad, 0xbe, 0xef}; };

    void mutate(Input_t &d, MutatorContext_t &ctx) override
    {
        if (d.empty())
            d.push_back(0);

        std::cout << d.size() << "\n";
        const auto original = W32k::DecodeBatch(d);
        if (!original.ok)
        {
            DebugPrint<1>("Syscall", "Failed to decode the buffer: {}\n", original.error_msg);
            return;
        }
        if (original.events.empty())
            return;

        maxSize_ = ctx.maxSize;
        // Another corpus entry, read only for its argument values (dictionary).
        const auto donor = pickDonor(ctx);

        // A mutation that grows past the VM's payload limit is discarded and retried
        // with a fresh seed rather than truncated, which would corrupt the batch.
        for (int attempt = 0; attempt < kMaxAttempts; ++attempt)
        {
            W32k::BatchResult batch = original;
            const auto seed = static_cast<std::uint64_t>(ctx.rng());
            rng_ = detail::Rng(seed);
            cfg_.probability = detail::pickProbability(rng_);
            log_ = detail::MutationLog{};
            log_.seed = seed;
            log_.probability = cfg_.probability;
            budget_ = cfg_.max_mutations;

            buildDictionary(batch.events, donor);

            for (eventIndex_ = 0; eventIndex_ < batch.events.size(); ++eventIndex_)
            {
                if (budgetExhausted())
                    break;
                auto &ev = batch.events[eventIndex_];
                if (eligible(ev))
                    mutateOne(ev, ctx);
            }

            if (log_.empty() && cfg_.ensure_progress)
                forceOne(batch.events);
            if (log_.empty())
                return; // nothing in this batch is mutable under the current config

            auto out = W32k::EncodeBatch(batch);
            if (maxSize_ && out.size() > maxSize_)
                continue;

            if constexpr (kTrace)
            {
                std::cout << log_.describe();
                W32k::Print(batch, std::cout);
            }
            d = std::move(out);
            return;
        }
    }

    /// Mutate every argument of one event in place, logging what was done.
    void mutateOne(W32k::EventInfo &syscall, MutatorContext_t &ctx)
    {
        (void)ctx;
        for (std::size_t i = 0; i < syscall.args.size(); ++i)
        {
            if (budgetExhausted())
                break;
            mutateArg(syscall, i);
        }
    }

    const detail::MutationLog &lastLog() const { return log_; }
    detail::MutationConfig &config() { return cfg_; }

private:
    static constexpr int kMaxAttempts = 4;
    static constexpr bool kTrace = false;

    using DictKey = std::pair<std::uint16_t, std::size_t>; // (ssn, arg index)

    detail::Rng rng_;
    detail::MutationConfig cfg_;
    detail::MutationLog log_;
    std::size_t budget_ = 0;
    std::size_t maxSize_ = 0;
    std::size_t eventIndex_ = 0;
    std::uint16_t ssn_ = 0;
    std::map<DictKey, std::vector<std::uint64_t>> dict_;

    // ---- batch-level ------------------------------------------------------

    bool eligible(const W32k::EventInfo &ev) const { return ev.is_pre() || cfg_.mutate_post_events; }
    bool budgetExhausted() const { return log_.records.size() >= budget_; }
    bool roll() { return !budgetExhausted() && rng_.chance(cfg_.probability); }

    std::vector<W32k::EventInfo> pickDonor(MutatorContext_t &ctx)
    {
        if (!ctx.pickOther)
            return {};
        const auto other = ctx.pickOther();
        if (!other)
            return {};
        auto r = W32k::DecodeBatch(*other);
        if (!r.ok)
            return {};
        std::vector<W32k::EventInfo> out;
        for (auto &ev : r.events)
            if (eligible(ev))
                out.push_back(std::move(ev));
        return out;
    }

    /// Observed literals: every value passed for (ssn, arg) by any caller we have seen.
    void buildDictionary(const std::vector<W32k::EventInfo> &events, const std::vector<W32k::EventInfo> &donor)
    {
        dict_.clear();
        if (!cfg_.use_dictionary)
            return;
        auto add = [&](const std::vector<W32k::EventInfo> &evs) {
            for (const auto &ev : evs)
            {
                if (!ev.is_pre())
                    continue;
                for (std::size_t i = 0; i < ev.args.size(); ++i)
                {
                    const auto &a = ev.args[i];
                    if (a.kind != ArgKind::Scalar && a.kind != ArgKind::Unknown)
                        continue;
                    auto &v = dict_[{ev.ssn, i}];
                    const std::uint64_t x = a.value & detail::widthMask(detail::argWidth(a));
                    if (std::find(v.begin(), v.end(), x) == v.end())
                        v.push_back(x);
                }
            }
        };
        add(events);
        add(donor);
        for (auto it = dict_.begin(); it != dict_.end();)
            it = it->second.size() > cfg_.max_dictionary ? dict_.erase(it) : std::next(it);
    }

    /// Exactly one mutation on a random eligible argument, at a raised probability.
    void forceOne(std::vector<W32k::EventInfo> &events)
    {
        std::vector<std::pair<std::size_t, std::size_t>> cands;
        for (std::size_t e = 0; e < events.size(); ++e)
        {
            if (!eligible(events[e]))
                continue;
            for (std::size_t i = 0; i < events[e].args.size(); ++i)
                if (events[e].args[i].kind != ArgKind::Handle || cfg_.mutate_handles)
                    cands.emplace_back(e, i);
        }
        if (cands.empty())
            return;

        const double savedP = cfg_.probability;
        const std::size_t savedBudget = budget_;
        cfg_.probability = 0.5;
        budget_ = log_.records.size() + 1;
        for (int c = 0; c < 4 && log_.empty(); ++c)
        {
            const auto [e, i] = cands[rng_.below(cands.size())];
            eventIndex_ = e;
            for (int t = 0; t < 32 && log_.empty(); ++t)
                mutateArg(events[e], i);
        }
        cfg_.probability = savedP;
        budget_ = savedBudget;
    }

    // ---- per-argument -----------------------------------------------------

    void mutateArg(W32k::EventInfo &ev, std::size_t i)
    {
        ssn_ = ev.ssn;
        switch (ev.args[i].kind)
        {
        case ArgKind::Handle: if (cfg_.mutate_handles) mutateScalar(ev, i); break;
        case ArgKind::Scalar: mutateScalar(ev, i); break;
        case ArgKind::Array: mutateArray(ev, i); break;
        case ArgKind::Buffer: mutateBuffer(ev, i); break;
        case ArgKind::String: mutateString(ev, i); break;
        case ArgKind::Pointer: mutateOpaque(ev, i); break;
        case ArgKind::Unknown:
        default:
            // Width-only: an integer unless something was captured behind it.
            if (ev.args[i].data.empty())
                mutateScalar(ev, i);
            else
                mutateOpaque(ev, i);
            break;
        }
    }

    bool skipPointee(const W32k::ArgInfo &a) const { return a.direction == Dir::Out && !cfg_.mutate_out_pointee; }

    void mutateScalar(W32k::EventInfo &ev, std::size_t i)
    {
        if (!roll())
            return;
        auto &a = ev.args[i];
        const int width = detail::argWidth(a);
        const std::uint64_t before = a.value;

        // Only the literals that would actually change the value.
        std::vector<std::uint64_t> alternatives;
        if (const auto it = dict_.find({ev.ssn, i}); it != dict_.end())
            for (const auto v : it->second)
                if (v != (before & detail::widthMask(width)))
                    alternatives.push_back(v);
        const std::vector<std::uint64_t> *dict = alternatives.empty() ? nullptr : &alternatives;

        Strategy how;
        std::uint64_t out = before;
        switch (rng_.below(dict ? 5 : 4))
        {
        case 0:
            how = Strategy::ScalarBitFlip;
            out = before ^ (1ull << rng_.below(static_cast<std::uint64_t>(width) * 8));
            break;
        case 1:
            how = Strategy::ScalarArithmetic;
            out = before + static_cast<std::uint64_t>(static_cast<std::int64_t>(rng_.below(70)) - 35);
            break;
        case 2:
            how = Strategy::ScalarInteresting;
            out = rng_.pick(width <= 4 ? detail::interesting32() : detail::interesting64());
            break;
        case 3:
            how = Strategy::ScalarRandom;
            out = rng_.next();
            break;
        default:
            how = Strategy::ScalarDictionary;
            out = rng_.pick(*dict);
            break;
        }
        out &= detail::widthMask(width);
        a.value = out;
        record(i, how, -1, before, out);
    }

    void mutateArray(W32k::EventInfo &ev, std::size_t i)
    {
        auto &a = ev.args[i];
        if (!a.has_data() || skipPointee(a))
        {
            mutatePointerValue(ev, i);
            return;
        }

        const auto link = detail::findLengthArg(ev, i, false);
        const std::size_t es = detail::granularity(a.data.size(), link);
        resizeAndDesync(ev, i, link, es);

        // Element-wise: walk the whole array rather than only its head.
        const std::size_t n = a.data.size() / es;
        for (std::size_t k = 0; k < n; ++k)
        {
            if (!roll())
                continue;
            // Elements wider than 8 bytes are structs: hit one DWORD inside.
            const int w = es <= 8 ? static_cast<int>(es) : 4;
            const std::size_t off = k * es + (es <= 8 ? 0 : 4 * rng_.below(es / 4));
            const std::uint64_t before = detail::readAt(a.data, off, w);
            const std::uint64_t after = rng_.pick(w <= 4 ? detail::interesting32() : detail::interesting64());
            detail::writeAt(a.data, off, w, after);
            record(i, Strategy::ArrayElement, static_cast<int>(off), before, after, "element " + std::to_string(k));
        }
        mutateNested(ev, i);
        mutatePointerValue(ev, i);
    }

    void mutateBuffer(W32k::EventInfo &ev, std::size_t i)
    {
        auto &a = ev.args[i];
        if (!a.has_data() || skipPointee(a))
        {
            mutatePointerValue(ev, i);
            return;
        }

        // A buffer with a byte-length argument can be resized/desynced like an array.
        const auto link = detail::findLengthArg(ev, i, true);
        if (link.arg >= 0)
            resizeAndDesync(ev, i, link, detail::granularity(a.data.size(), link));

        // No recovered layout: treat it as a struct of DWORD / pointer-sized fields,
        // leaving the slots that a nested entry already describes to mutateNested.
        mutateFields(a.data, i, -1, nestedOffsets(ev, i));
        mutateNested(ev, i);
        mutatePointerValue(ev, i);
    }

    void mutateString(W32k::EventInfo &ev, std::size_t i)
    {
        auto &a = ev.args[i];
        if (!a.has_data() || skipPointee(a))
        {
            mutatePointerValue(ev, i);
            return;
        }

        if (a.capture_type == W32k::CaptureType::UnicodeString && a.data.size() >= sizeof(W32k::UnicodeStringBlob))
        {
            const auto hdr = *a.unicode_header();
            // Length that matches neither the buffer nor MaximumLength, or is odd.
            if (roll())
            {
                const std::vector<std::uint64_t> lengths{
                    0, 1, 0x101, 0xFFFF, 0xFFFE, static_cast<std::uint64_t>(hdr.maximum_length + 2u)};
                const auto after = static_cast<std::uint16_t>(rng_.pick(lengths));
                detail::writeAt(a.data, 0, 2, after);
                record(i, Strategy::StringLength, 0, hdr.length, after,
                       (after & 1) ? "odd byte length" : "length vs maximum");
            }
            if (roll())
            {
                const std::uint64_t wild = rng_.pick(detail::interestingPointers());
                detail::writeAt(a.data, 8, 8, wild);
                record(i, Strategy::StringBuffer, 8, hdr.buffer, wild, "Buffer repointed");
            }
            if (a.data.size() > sizeof(W32k::UnicodeStringBlob) && roll())
                corruptByte(a.data, i, -1, sizeof(W32k::UnicodeStringBlob), Strategy::StringContent, {});
            mutatePointerValue(ev, i);
            return;
        }

        // Counted or NUL-terminated character buffer: corrupt, or drop the terminator.
        if (!a.data.empty() && roll())
            corruptByte(a.data, i, -1, 0, Strategy::StringContent, {});

        const std::size_t cw = a.capture_type == W32k::CaptureType::CStringW ? 2 : 1;
        if (a.data.size() >= cw && detail::readAt(a.data, a.data.size() - cw, static_cast<int>(cw)) == 0 && roll())
        {
            const auto before = a.data.size();
            a.data.resize(a.data.size() - cw);
            a.requested_length = static_cast<std::uint32_t>(a.data.size());
            a.capture_flags.bits |= detail::kCapfUnterminated;
            record(i, Strategy::StringTerminator, static_cast<int>(a.data.size()), before, a.data.size(),
                   "NUL terminator stripped");
        }
        mutatePointerValue(ev, i);
    }

    void mutateOpaque(W32k::EventInfo &ev, std::size_t i)
    {
        auto &a = ev.args[i];
        if (!a.has_data() || a.data.empty() || skipPointee(a))
        {
            mutatePointerValue(ev, i);
            return;
        }
        if (roll())
            corruptByte(a.data, i, -1, 0, Strategy::OpaqueBytes, "no layout recovered");
        mutateNested(ev, i);
        mutatePointerValue(ev, i);
    }

    void mutatePointerValue(W32k::EventInfo &ev, std::size_t i)
    {
        auto &a = ev.args[i];
        if (!cfg_.mutate_pointers || !detail::isPointerKind(a.kind))
            return;
        if (!roll())
            return;

        const std::uint64_t before = a.value;
        const std::uint64_t wild = rng_.pick(detail::interestingPointers());
        detail::setRawPointer(a, wild);

        // The pointee is gone, so whatever was captured behind it is stale.
        const auto dropped = std::count_if(ev.nested.begin(), ev.nested.end(),
                                           [&](const W32k::NestedInfo &n) { return n.arg_index == i; });
        ev.nested.erase(std::remove_if(ev.nested.begin(), ev.nested.end(),
                                       [&](const W32k::NestedInfo &n) { return n.arg_index == i; }),
                        ev.nested.end());
        std::string note = "argument pointer replaced";
        if (dropped)
            note += ", " + std::to_string(dropped) + " nested entr" + (dropped == 1 ? "y" : "ies") + " dropped";
        record(i, detail::pointerStrategy(wild), -1, before, wild, std::move(note));
    }

    // ---- shared pieces ----------------------------------------------------

    /// Resize FIRST, then desync: the resize rewrites the count to match, so doing it
    /// after a desync would silently undo the desync.
    void resizeAndDesync(W32k::EventInfo &ev, std::size_t i, const detail::LengthLink &link, std::size_t es)
    {
        auto &a = ev.args[i];

        if (cfg_.resize_arrays && roll())
        {
            const std::size_t oldBytes = a.data.size();
            const std::size_t oldN = oldBytes / es;
            std::size_t cap = std::min(cfg_.max_array_bytes / es, cfg_.max_array_elements);
            if (maxSize_)
                cap = std::min(cap, std::max<std::size_t>(1, (maxSize_ / 2) / es));
            const std::size_t newN = detail::pickElementCount(rng_, oldN, std::max<std::size_t>(cap, 1));

            // Grow by repeating the existing elements: realistic content, new length.
            std::vector<std::uint8_t> nb(newN * es);
            for (std::size_t b = 0; b < nb.size(); ++b)
                nb[b] = oldBytes ? a.data[b % oldBytes] : static_cast<std::uint8_t>(rng_.next());
            a.data = std::move(nb);
            a.requested_length = static_cast<std::uint32_t>(a.data.size());
            a.capture_flags.bits &= ~(detail::kCapfTruncated | detail::kCapfFault);
            dropNestedBeyond(ev, i, a.data.size());

            std::string note;
            if (link.arg >= 0)
            {
                auto &c = ev.args[static_cast<std::size_t>(link.arg)];
                c.value = (a.data.size() / link.unit) & detail::widthMask(detail::argWidth(c));
                note = "count in a" + std::to_string(link.arg) + " kept in sync";
            }
            record(i, Strategy::ArrayResize, -1, oldN, newN, std::move(note));
        }

        // Desynchronising the count from the buffer is the point of knowing the link.
        if (cfg_.desync_counts && link.arg >= 0 && roll())
        {
            auto &c = ev.args[static_cast<std::size_t>(link.arg)];
            const std::uint64_t before = c.value;
            const std::uint64_t claimed = rng_.pick(detail::interesting32()) & detail::widthMask(detail::argWidth(c));
            c.value = claimed;
            record(i, Strategy::ArrayCountDesync, -1, before, claimed,
                   "count in a" + std::to_string(link.arg) + ", buffer holds " +
                       std::to_string(a.data.size() / link.unit) + " unit(s) of " + std::to_string(link.unit));
        }
    }

    /// Field-wise mutation of a blob with no recovered layout.
    void mutateFields(std::vector<std::uint8_t> &blob, std::size_t arg, int nested,
                      const std::vector<std::uint32_t> &skip)
    {
        const auto covered = [&](std::size_t off, std::size_t w) {
            return std::any_of(skip.begin(), skip.end(),
                               [&](std::uint32_t p) { return off < p + 8u && p < off + w; });
        };

        // A leading size field equal to the blob size is a caller-seeded constant.
        int cbWidth = 0;
        if (blob.size() >= 4 && detail::readAt(blob, 0, 4) == blob.size())
            cbWidth = 4;
        else if (blob.size() >= 2 && detail::readAt(blob, 0, 2) == blob.size())
            cbWidth = 2;

        std::size_t off = 0;
        while (off + 4 <= blob.size())
        {
            if (budgetExhausted())
                return;
            const bool ptrField = off % 8 == 0 && off + 8 <= blob.size() &&
                                  detail::looksLikeUserPointer(detail::readAt(blob, off, 8));
            const std::size_t w = ptrField ? 8 : 4;
            const std::size_t here = off;
            off += w;
            if (covered(here, w) || !roll())
                continue;

            const int iw = static_cast<int>(w);
            if (here == 0 && cbWidth)
            {
                const std::uint64_t k = blob.size();
                const std::vector<std::uint64_t> around{k - 1, k + 1, 0, ~0ull, k << 1, 0x7FFFFFFF};
                const std::uint64_t before = detail::readAt(blob, 0, cbWidth);
                const std::uint64_t after = rng_.pick(around) & detail::widthMask(cbWidth);
                detail::writeAt(blob, 0, cbWidth, after);
                record(arg, Strategy::StructSizeField, 0, before, after, "cbSize-like, caller wrote " + std::to_string(k),
                       nested);
                continue;
            }
            const std::uint64_t before = detail::readAt(blob, here, iw);
            if (ptrField)
            {
                const std::uint64_t wild = rng_.pick(detail::interestingPointers());
                detail::writeAt(blob, here, iw, wild);
                record(arg, Strategy::StructPointerField, static_cast<int>(here), before, wild,
                       "inline pointer-like field", nested);
                continue;
            }
            const std::uint64_t after = rng_.pick(detail::interesting32());
            detail::writeAt(blob, here, iw, after);
            record(arg, Strategy::StructField, static_cast<int>(here), before, after, "4 bytes", nested);
        }
        if (blob.size() % 4 && roll())
            corruptByte(blob, arg, nested, blob.size() - blob.size() % 4, Strategy::OpaqueBytes, "tail byte");
    }

    /// Nested pointers: the double-fetch surface. Repoint them, or mutate what they hold.
    void mutateNested(W32k::EventInfo &ev, std::size_t i)
    {
        auto &parent = ev.args[i].data;
        for (std::size_t n = 0; n < ev.nested.size(); ++n)
        {
            if (budgetExhausted())
                return;
            auto &ne = ev.nested[n];
            if (ne.arg_index != i)
                continue;

            if (cfg_.mutate_pointers && roll())
            {
                const std::uint64_t before = ne.pointer_value;
                const std::uint64_t wild = rng_.pick(detail::interestingPointers());
                detail::setRawPointer(ne, wild);
                detail::writeAt(parent, ne.parent_offset, 8, wild); // keep the parent's copy in step
                record(i, Strategy::StructPointerField, static_cast<int>(ne.parent_offset), before, wild,
                       "nested pointer repointed", static_cast<int>(n));
                continue;
            }
            if (!ne.data.empty() && (ne.direction != Dir::Out || cfg_.mutate_out_pointee))
                mutateFields(ne.data, i, static_cast<int>(n), {});
        }
    }

    static std::vector<std::uint32_t> nestedOffsets(const W32k::EventInfo &ev, std::size_t i)
    {
        std::vector<std::uint32_t> out;
        for (const auto &ne : ev.nested)
            if (ne.arg_index == i)
                out.push_back(ne.parent_offset);
        return out;
    }

    static void dropNestedBeyond(W32k::EventInfo &ev, std::size_t i, std::size_t size)
    {
        ev.nested.erase(std::remove_if(ev.nested.begin(), ev.nested.end(),
                                       [&](const W32k::NestedInfo &n) {
                                           return n.arg_index == i && n.parent_offset + 8u > size;
                                       }),
                        ev.nested.end());
    }

    void corruptByte(std::vector<std::uint8_t> &blob, std::size_t arg, int nested, std::size_t from, Strategy how,
                     std::string note)
    {
        if (from >= blob.size())
            return;
        const std::size_t at = from + rng_.below(blob.size() - from);
        const std::uint64_t before = blob[at];
        const auto after = static_cast<std::uint8_t>(rng_.next());
        blob[at] = after;
        record(arg, how, static_cast<int>(at), before, after, std::move(note), nested);
    }

    void record(std::size_t arg, Strategy s, int off, std::uint64_t before, std::uint64_t after,
                std::string note = {}, int nested = -1)
    {
        log_.records.push_back(
            detail::MutationRecord{eventIndex_, ssn_, arg, nested, s, off, before, after, std::move(note)});
    }
};

} // namespace Syscall

REGISTER_MUTATOR(Syscall::SyscallMutator_t, "syscall", "Specialised mutator for syscalls");
