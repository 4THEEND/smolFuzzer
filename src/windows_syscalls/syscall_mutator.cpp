// syscall_mutator.cpp - type-aware mutation of syscall traces, delivered as patch programs.
//
// Port of the win32k_mutate tactics (NtFuzz section VI-B1) onto the wire model of
// w32k_decode.hpp. The strategy for an argument is chosen from its ArgKind, not from
// its bytes.
//
// What goes to the VM is NOT a mutated frame any more. The corpus stores a mutation
// program (W32k::Program): a short list of patches, each one addressing a live call by
//
//      (ssn, thread fingerprint, occurrence)   -- the n-th PRE call of `ssn` by that thread
//
// and saying what to change in it (set an argument, write N bytes into its pointee or a
// nested pointee, or swap its buffer for a resized copy). The harness lets the target run
// for real and applies the patches as the calls go by (w32k_mutate.c).
//
// The captured trace is still what the tactics are derived from, but it stays on the host:
//
//   * baseline        - the dummy input runs unpatched; the driver dumps its trace, which
//                       comes back here as a W32B batch. It is put in the TraceStore and a
//                       program referencing it (by hash) is emitted.
//   * rebase          - when a program run diverges, the driver dumps
//                       [program][trace it produced]. The program keeps its records and is
//                       re-pointed at the new trace, records whose call no longer exists are
//                       dropped, and new records are written against what really happened.
//   * no trace        - if the reference trace is unknown (other process, restart without
//                       W32K_TRACE_DIR), existing records are still mutated in place.
//
// Tactics re-derived from the captured data, as before:
//
//   * observed literals - the dictionary for (ssn, arg) is built from the values seen
//                         in this trace and in one other corpus entry's trace.
//   * linked counts     - an Array/Buffer's count argument is found by looking for a
//                         nearby scalar whose value divides the blob size into a
//                         plausible element size; count and buffer can be desynchronised.
//   * caller constants  - a leading DWORD equal to the blob size is treated as a
//                         cbSize field and mutated around its known-good value.
//   * direction         - Dir::Out pointees are kernel-written; only the pointer is
//                         mutated unless MutationConfig::mutate_out_pointee is set.
//
// Each generation pass works on a shadow copy of the event, so later tactics in the same
// call see earlier ones (e.g. element writes land inside a resized array) and the records
// are emitted in the order the driver must apply them.

#include "../mutator.hpp"
#include "w32k_decode.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
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
            template <typename T>
            const T &pick(const std::vector<T> &v) { return v[below(v.size())]; }
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
            /// Per-candidate probability; re-drawn per pass by pickProbability().
            double probability = 0.01;
            bool mutate_handles = false;     ///< a bad handle short-circuits the syscall
            bool mutate_out_pointee = false; ///< the kernel writes there; mutating it is wasted
            bool mutate_pointers = true;     ///< replace the pointer itself with a wild address
            bool resize_arrays = true;
            bool desync_counts = true;
            bool use_dictionary = true;      ///< prefer literals other callers were seen to pass
            std::size_t max_dictionary = 16; ///< a larger value set means "unconstrained"
            /// Ceiling on an array's SIZE in bytes (the unit that matters), plus a backstop.
            std::size_t max_array_bytes = 0x1000;
            std::size_t max_array_elements = 4096;
            std::size_t max_mutations = 1; ///< new records per pass, so one input stays explainable
            /// At low probability most passes change nothing; force one mutation instead of
            /// burning an execution on an unchanged input.
            bool ensure_progress = true;

            // ---- program-level ------------------------------------------------
            std::size_t max_records = 64;    ///< program cap; the oldest records are dropped
            double p_generate = 0.7;         ///< chance to add records when the program has some
            double p_edit = 0.3;             ///< chance to also edit an existing record
            double every_call_chance = 0.02; ///< new record applies to every call, not one
            /// Guards make a record fire only if the live value still matches the trace,
            /// which protects against occurrence drift but drops patches whose argument
            /// legitimately varies between runs.
            bool guard_scalars = false;
            bool guard_writes = false;
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

        enum class Strategy : std::uint8_t
        {
            ScalarBitFlip,
            ScalarArithmetic,
            ScalarInteresting,
            ScalarDictionary,
            ScalarRandom,
            StructField,
            StructSizeField,
            StructPointerField,
            ArrayElement,
            ArrayResize,
            ArrayCountDesync,
            StringLength,
            StringBuffer,
            StringContent,
            StringTerminator,
            PointerWild,
            PointerNull,
            PointerUnaligned,
            OpaqueBytes,
            // edits of an existing record (no trace needed)
            RecordValue,
            RecordOccurrence,
            RecordEveryCall,
            RecordOffset,
            RecordDelete,
            RecordSplice
        };

        inline const char *strategyName(Strategy s)
        {
            switch (s)
            {
            case Strategy::ScalarBitFlip:
                return "scalar.bitflip";
            case Strategy::ScalarArithmetic:
                return "scalar.arith";
            case Strategy::ScalarInteresting:
                return "scalar.interesting";
            case Strategy::ScalarDictionary:
                return "scalar.dictionary";
            case Strategy::ScalarRandom:
                return "scalar.random";
            case Strategy::StructField:
                return "struct.field";
            case Strategy::StructSizeField:
                return "struct.size_field";
            case Strategy::StructPointerField:
                return "struct.pointer_field";
            case Strategy::ArrayElement:
                return "array.element";
            case Strategy::ArrayResize:
                return "array.resize";
            case Strategy::ArrayCountDesync:
                return "array.count_desync";
            case Strategy::StringLength:
                return "string.length";
            case Strategy::StringBuffer:
                return "string.buffer";
            case Strategy::StringContent:
                return "string.content";
            case Strategy::StringTerminator:
                return "string.terminator";
            case Strategy::PointerWild:
                return "pointer.wild";
            case Strategy::PointerNull:
                return "pointer.null";
            case Strategy::PointerUnaligned:
                return "pointer.unaligned";
            case Strategy::OpaqueBytes:
                return "opaque.bytes";
            case Strategy::RecordValue:
                return "record.value";
            case Strategy::RecordOccurrence:
                return "record.occurrence";
            case Strategy::RecordEveryCall:
                return "record.every_call";
            case Strategy::RecordOffset:
                return "record.offset";
            case Strategy::RecordDelete:
                return "record.delete";
            case Strategy::RecordSplice:
                return "record.splice";
            }
            return "?";
        }

        /// Strategies whose value is an address: re-rolled from interestingPointers().
        inline bool isPointerStrategy(std::uint8_t s)
        {
            switch (static_cast<Strategy>(s))
            {
            case Strategy::StructPointerField:
            case Strategy::StringBuffer:
            case Strategy::PointerWild:
            case Strategy::PointerNull:
            case Strategy::PointerUnaligned:
                return true;
            default:
                return false;
            }
        }

        struct LogEntry
        {
            Strategy strategy = Strategy::ScalarRandom;
            W32k::MutRecord record;  ///< the record as emitted / after the edit
            std::uint64_t before = 0; ///< value seen in the trace (or before the edit)
            long event = -1;          ///< trace event index, -1 for edits
            std::string detail;

            std::string describe() const
            {
                std::ostringstream o;
                if (event >= 0)
                    o << 'e' << event << ' ';
                o << strategyName(strategy) << ": " << W32k::Describe(record) << "  (was 0x" << std::hex << before
                  << std::dec << ')';
                if (!detail.empty())
                    o << "  " << detail;
                return o.str();
            }
        };

        struct MutationLog
        {
            std::uint64_t seed = 0;
            double probability = 0;
            std::uint64_t trace = 0;
            std::size_t records = 0; ///< program size after the pass
            std::vector<LogEntry> entries;

            bool empty() const { return entries.empty(); }
            std::string describe() const
            {
                std::ostringstream o;
                o << "seed=0x" << std::hex << seed << " trace=0x" << trace << std::dec << " p=" << probability
                  << " changes=" << entries.size() << " records=" << records << '\n';
                for (const auto &e : entries)
                    o << "  " << e.describe() << '\n';
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
            case 1:
            case 2:
            case 4:
            case 8:
                return a.size;
            default:
                return 8;
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

        // ============================================================ trace store ==

        inline std::uint64_t fnv1a(const std::uint8_t *p, std::size_t n)
        {
            std::uint64_t h = 0xCBF29CE484222325ull;
            for (std::size_t i = 0; i < n; ++i)
                h = (h ^ p[i]) * 0x100000001B3ull;
            return h ? h : 1;
        }

        /// Reference traces, keyed by the hash of their wire bytes. Programs only carry
        /// the key. Process-wide; persisted to $W32K_TRACE_DIR when set, so that other
        /// worker processes and restarts can resolve a program's trace.
        class TraceStore
        {
        public:
            using Trace = std::shared_ptr<const std::vector<W32k::EventInfo>>;

            static TraceStore &instance()
            {
                static TraceStore s;
                return s;
            }

            /// Register the batch at raw[off..]; returns its id, 0 if it does not decode.
            /// `baseline`: the trace of an unpatched run (a bare dump), as opposed to the
            /// trace a program produced. Only baselines are valid for a brand-new program.
            std::uint64_t put(const std::vector<std::uint8_t> &raw, std::size_t off = 0, bool baseline = false)
            {
                if (off >= raw.size() || raw.size() - off < 12)
                    return 0;
                std::uint32_t total = 0;
                std::memcpy(&total, raw.data() + off + 8, 4); // W32K_BATCH_HEADER.TotalSize
                if (total < 24 || total > raw.size() - off)
                    return 0;
                std::vector<std::uint8_t> bytes(raw.begin() + static_cast<std::ptrdiff_t>(off),
                                                raw.begin() + static_cast<std::ptrdiff_t>(off + total));
                const std::uint64_t id = fnv1a(bytes.data(), bytes.size());
                {
                    std::lock_guard<std::mutex> g(m_);
                    if (map_.count(id))
                    {
                        if (baseline)
                            baselines_.insert(id);
                        return id;
                    }
                }
                auto decoded = W32k::DecodeBatch(bytes);
                if (decoded.events.empty()) // a partially decoded batch is still usable
                    return 0;
                std::lock_guard<std::mutex> g(m_);
                insert(id, std::make_shared<const std::vector<W32k::EventInfo>>(std::move(decoded.events)));
                if (baseline)
                    baselines_.insert(id);
                persist(id, bytes);
                return id;
            }

            Trace get(std::uint64_t id)
            {
                if (!id)
                    return nullptr;
                std::lock_guard<std::mutex> g(m_);
                if (const auto it = map_.find(id); it != map_.end())
                    return it->second;
                if (dir_.empty())
                    return nullptr;
                std::ifstream f(path(id), std::ios::binary);
                if (!f)
                    return nullptr;
                std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
                auto decoded = W32k::DecodeBatch(bytes);
                if (decoded.events.empty())
                    return nullptr;
                auto t = std::make_shared<const std::vector<W32k::EventInfo>>(std::move(decoded.events));
                insert(id, t);
                return t;
            }

            /// The most recent baseline trace, for inputs that carry none (the dummy).
            /// A trace produced under some program is no use here: its occurrences were
            /// counted with that program's patches applied, and a new program without
            /// them would follow the baseline path, so its records would never fire.
            std::pair<std::uint64_t, Trace> latestBaseline()
            {
                std::lock_guard<std::mutex> g(m_);
                for (auto it = order_.rbegin(); it != order_.rend(); ++it)
                    if (baselines_.count(*it))
                        return {*it, map_.at(*it)};
                return {0, nullptr};
            }

        private:
            static constexpr std::size_t kMaxTraces = 256;

            TraceStore()
            {
                if (const char *d = std::getenv("W32K_TRACE_DIR"))
                    dir_ = d;
            }

            void insert(std::uint64_t id, Trace t)
            {
                if (map_.emplace(id, std::move(t)).second)
                    order_.push_back(id);
                while (order_.size() > kMaxTraces)
                {
                    map_.erase(order_.front());
                    baselines_.erase(order_.front());
                    order_.pop_front();
                }
            }

            std::string path(std::uint64_t id) const
            {
                char name[32];
                std::snprintf(name, sizeof(name), "/%016llx.w32b", static_cast<unsigned long long>(id));
                return dir_ + name;
            }

            void persist(std::uint64_t id, const std::vector<std::uint8_t> &bytes) const
            {
                if (dir_.empty())
                    return;
                std::ofstream f(path(id), std::ios::binary | std::ios::trunc);
                f.write(reinterpret_cast<const char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
            }

            std::mutex m_;
            std::string dir_;
            std::unordered_map<std::uint64_t, Trace> map_;
            std::deque<std::uint64_t> order_;
            std::unordered_set<std::uint64_t> baselines_;
        };

        /// A corpus entry resolved to its program and (if known) its reference trace.
        struct Source
        {
            W32k::Program program;
            TraceStore::Trace trace;
        };

        /// Same thread identity as the trace shows it. The host has no areAlikes(); a record's
        /// fingerprint is copied from a trace event, so exact equality is the right test here.
        inline bool sameThread(const W32k::Fingerprint &a, const W32k::Fingerprint &b)
        {
            return a.exact == b.exact && a.index == b.index;
        }

        /// Does the trace contain the call this record designates (same syscall, same
        /// thread, same occurrence; any occurrence for an every-call record)?
        inline bool targetsTrace(const W32k::MutRecord &r, const std::vector<W32k::EventInfo> &trace)
        {
            return std::any_of(trace.begin(), trace.end(),
                               [&](const W32k::EventInfo &e)
                               {
                                   return e.is_pre() && e.ssn == r.ssn && sameThread(e.fingerprint, r.fingerprint) &&
                                          (r.every_call() || e.occurrence == r.occurrence);
                               });
        }

        /// Accepts a bare trace (baseline dump), a program, or a program followed by the
        /// trace it produced (divergence dump). Anything else (the dummy input) is rejected.
        inline bool resolve(const std::vector<std::uint8_t> &d, Source &out)
        {
            auto &store = TraceStore::instance();
            out = Source{};
            if (W32k::IsBatch(d))
            {
                out.program.trace_id = store.put(d, 0, /*baseline=*/true);
                out.trace = store.get(out.program.trace_id);
                return out.trace != nullptr;
            }
            if (!W32k::IsProgram(d))
                return false;
            auto pr = W32k::DecodeProgram(d);
            if (!pr.ok)
                return false;
            out.program = std::move(pr.program);
            if (W32k::IsBatch(d, pr.consumed))
            {
                // Rebase: the trace that this very program produced is the better reference.
                if (const auto id = store.put(d, pr.consumed))
                {
                    out.program.trace_id = id;
                    out.trace = store.get(id);
                    // Keep a record only if its call still exists in what actually ran,
                    // for the same thread: a record left pointing at nothing never fires,
                    // so every later run of the program would "diverge" and dump again.
                    auto &recs = out.program.records;
                    const auto &evs = *out.trace;
                    recs.erase(std::remove_if(recs.begin(), recs.end(),
                                              [&](const W32k::MutRecord &r) { return !targetsTrace(r, evs); }),
                               recs.end());
                    return true;
                }
            }
            out.trace = store.get(out.program.trace_id);
            return true;
        }

    } // namespace detail

    // ================================================================ mutator ==

    class SyscallMutator_t final : public Mutator_t
    {
        using ArgKind = W32k::ArgKind;
        using Dir = W32k::Dir;
        using Strategy = detail::Strategy;
        using Trace = detail::TraceStore::Trace;

    public:
        Input_t emptyInput() override { return Input_t{0xef, 0xbe, 0xad, 0xde}; };

        void mutate(Input_t &d, MutatorContext_t &ctx) override
        {
            DebugPrint<0>("Syscall", "Size {}\n", d.size());

            detail::Source src;
            if (!detail::resolve(d, src))
            {
                // The dummy (or anything unrecognised): write a fresh program against the
                // newest known trace instead of re-running the baseline. Only the very
                // first execution, before any trace exists, goes through unchanged.
                auto [id, trace] = detail::TraceStore::instance().latestBaseline();
                if (!trace)
                {
                    DebugPrint<1>("Syscall", "No trace known yet, running the baseline ({} bytes)\n", d.size());
                    return;
                }
                src = detail::Source{};
                src.program.trace_id = id;
                src.trace = std::move(trace);
            }
            if (!src.trace && src.program.records.empty())
                return; // nothing to write records against, nothing to edit

            maxSize_ = ctx.maxSize;
            // Another corpus entry: its trace feeds the dictionary, its records can be spliced.
            const auto donor = pickDonor(ctx);

            // A program that grows past the VM's payload limit is discarded and retried
            // with a fresh seed rather than truncated.
            for (int attempt = 0; attempt < kMaxAttempts; ++attempt)
            {
                const auto seed = static_cast<std::uint64_t>(ctx.rng());
                rng_ = detail::Rng(seed);
                cfg_.probability = detail::pickProbability(rng_);
                program_ = src.program;
                program_.seed = seed;
                log_ = detail::MutationLog{};
                log_.seed = seed;
                log_.probability = cfg_.probability;
                log_.trace = program_.trace_id;
                budget_ = cfg_.max_mutations;

                buildDictionary(src.trace, donor.trace);

                const bool canGenerate = src.trace != nullptr;
                const bool hasRecords = !program_.records.empty();
                const bool generateNow = canGenerate && (!hasRecords || rng_.chance(cfg_.p_generate));
                if (generateNow)
                    generate(*src.trace);
                if (hasRecords && (!generateNow || rng_.chance(cfg_.p_edit)))
                    editRecord(donor, src.trace);

                if (log_.empty() && cfg_.ensure_progress)
                {
                    if (canGenerate)
                        forceOne(*src.trace);
                    if (log_.empty() && !program_.records.empty())
                        editRecord(donor, src.trace);
                }
                if (log_.empty())
                    return; // nothing mutable under the current config

                trim();
                log_.records = program_.records.size();

                auto out = W32k::EncodeProgram(program_);
                if (maxSize_ && out.size() > maxSize_)
                    continue;

                if constexpr (kTrace)
                    DebugPrint<0>("agent", "{}", log_.describe());
                d = Input_t(out.begin(), out.end());
                return;
            }
        }

        const detail::MutationLog &lastLog() const { return log_; }
        const W32k::Program &lastProgram() const { return program_; }
        detail::MutationConfig &config() { return cfg_; }

    private:
        static constexpr int kMaxAttempts = 4;
        static constexpr bool kTrace = true;

        using DictKey = std::pair<std::uint16_t, std::size_t>; // (ssn, arg index)

        detail::Rng rng_;
        detail::MutationConfig cfg_;
        detail::MutationLog log_;
        W32k::Program program_;
        std::size_t budget_ = 0;
        std::size_t maxSize_ = 0;
        std::map<DictKey, std::vector<std::uint64_t>> dict_;

        /// The trace event the generator is currently writing records for (shadow copy).
        const W32k::EventInfo *cur_ = nullptr;
        long curIndex_ = -1;

        // ---- program-level ----------------------------------------------------

        static bool eligible(const W32k::EventInfo &ev)
        {
            // Post events are the kernel's answer; a saturated occurrence cannot be addressed.
            return ev.is_pre() && ev.has_occurrence();
        }

        std::size_t generated() const
        {
            return static_cast<std::size_t>(std::count_if(log_.entries.begin(), log_.entries.end(),
                                                          [](const detail::LogEntry &e)
                                                          { return e.event >= 0; }));
        }
        bool budgetExhausted() const { return generated() >= budget_; }
        bool roll() { return !budgetExhausted() && rng_.chance(cfg_.probability); }

        detail::Source pickDonor(MutatorContext_t &ctx)
        {
            detail::Source s;
            if (!ctx.pickOther)
                return s;
            const auto other = ctx.pickOther();
            if (!other)
                return s;
            if (!detail::resolve(*other, s))
                return detail::Source{};
            return s;
        }

        /// Observed literals: every value passed for (ssn, arg) by any caller we have seen.
        void buildDictionary(const Trace &trace, const Trace &donor)
        {
            dict_.clear();
            if (!cfg_.use_dictionary)
                return;
            auto add = [&](const Trace &t)
            {
                if (!t)
                    return;
                for (const auto &ev : *t)
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
            add(trace);
            add(donor);
            for (auto it = dict_.begin(); it != dict_.end();)
                it = it->second.size() > cfg_.max_dictionary ? dict_.erase(it) : std::next(it);
        }

        /// Walk the reference trace and write new records, at the pass probability.
        void generate(const std::vector<W32k::EventInfo> &trace)
        {
            for (std::size_t e = 0; e < trace.size() && !budgetExhausted(); ++e)
            {
                if (!eligible(trace[e]))
                    continue;
                W32k::EventInfo shadow = trace[e];
                cur_ = &shadow;
                curIndex_ = static_cast<long>(e);
                for (std::size_t i = 0; i < shadow.args.size() && !budgetExhausted(); ++i)
                    mutateArg(shadow, i);
            }
            cur_ = nullptr;
        }

        /// Exactly one new record on a random eligible argument, at a raised probability.
        void forceOne(const std::vector<W32k::EventInfo> &trace)
        {
            std::vector<std::pair<std::size_t, std::size_t>> cands;
            for (std::size_t e = 0; e < trace.size(); ++e)
            {
                if (!eligible(trace[e]))
                    continue;
                for (std::size_t i = 0; i < trace[e].args.size(); ++i)
                    if (trace[e].args[i].kind != ArgKind::Handle || cfg_.mutate_handles)
                        cands.emplace_back(e, i);
            }
            if (cands.empty())
                return;

            const double savedP = cfg_.probability;
            const std::size_t savedBudget = budget_;
            cfg_.probability = 0.5;
            budget_ = generated() + 1;
            for (int c = 0; c < 4 && log_.empty(); ++c)
            {
                const auto [e, i] = cands[rng_.below(cands.size())];
                W32k::EventInfo shadow = trace[e];
                cur_ = &shadow;
                curIndex_ = static_cast<long>(e);
                for (int t = 0; t < 32 && log_.empty(); ++t)
                    mutateArg(shadow, i);
            }
            cur_ = nullptr;
            cfg_.probability = savedP;
            budget_ = savedBudget;
        }

        /// The program cap: the oldest records go first.
        void trim()
        {
            auto &r = program_.records;
            if (r.size() > cfg_.max_records)
                r.erase(r.begin(), r.begin() + static_cast<std::ptrdiff_t>(r.size() - cfg_.max_records));
        }

        // ---- editing existing records (works without a trace) ------------------

        std::uint64_t rerollValue(const W32k::MutRecord &r, std::uint64_t v)
        {
            const int w = r.width >= 1 && r.width <= 8 ? r.width : 8;
            if (detail::isPointerStrategy(r.strategy))
                return rng_.pick(detail::interestingPointers());
            switch (rng_.below(4))
            {
            case 0:
                v ^= 1ull << rng_.below(static_cast<std::uint64_t>(w) * 8);
                break;
            case 1:
                v += static_cast<std::uint64_t>(static_cast<std::int64_t>(rng_.below(70)) - 35);
                break;
            case 2:
                v = rng_.pick(w <= 4 ? detail::interesting32() : detail::interesting64());
                break;
            default:
                v = rng_.next();
                break;
            }
            return v & detail::widthMask(w);
        }

        /// With the reference trace known, every edit keeps the record pointing at a call
        /// that exists in it: a record aimed at nothing never fires and only makes the run
        /// look divergent.
        void editRecord(const detail::Source &donor, const Trace &trace)
        {
            auto &recs = program_.records;
            if (recs.empty())
                return;
            const std::size_t idx = rng_.below(recs.size());
            auto &r = recs[idx];
            // Donor records come from other traces; only those that address a call in ours.
            std::vector<const W32k::MutRecord *> spliceable;
            for (const auto &dr : donor.program.records)
                if (!trace || detail::targetsTrace(dr, *trace))
                    spliceable.push_back(&dr);
            const bool canSplice = !spliceable.empty();

            detail::LogEntry le;
            switch (rng_.below(canSplice ? 6 : 5))
            {
            case 0:
            value:
                le.strategy = Strategy::RecordValue;
                if (r.op == W32k::MutOp::Resize)
                {
                    le.before = r.length;
                    const std::size_t cap = std::max<std::size_t>(cfg_.max_array_bytes, 1);
                    for (int t = 0; t < 8 && r.length == le.before; ++t)
                        r.length = static_cast<std::uint32_t>(detail::pickElementCount(rng_, r.length, cap));
                    le.detail = "new buffer size, count left as is";
                }
                else
                {
                    le.before = r.value;
                    for (int t = 0; t < 8 && r.value == le.before; ++t)
                        r.value = rerollValue(r, r.value);
                }
                break;
            case 1:
                if (r.every_call())
                    goto value;
                {
                    le.strategy = Strategy::RecordOccurrence;
                    le.before = r.occurrence;
                    if (trace)
                    {
                        // Only calls this thread really makes; the nearest ones first.
                        std::vector<std::uint32_t> occ;
                        for (const auto &e : *trace)
                            if (e.is_pre() && e.ssn == r.ssn && detail::sameThread(e.fingerprint, r.fingerprint) &&
                                e.occurrence != r.occurrence && e.has_occurrence())
                                occ.push_back(e.occurrence);
                        if (occ.empty())
                            goto value;
                        std::sort(occ.begin(), occ.end(),
                                  [&](std::uint32_t a, std::uint32_t b)
                                  {
                                      const auto da = a > r.occurrence ? a - r.occurrence : r.occurrence - a;
                                      const auto db = b > r.occurrence ? b - r.occurrence : r.occurrence - b;
                                      return da < db;
                                  });
                        r.occurrence = occ[rng_.below(std::min<std::size_t>(occ.size(), 4))];
                    }
                    else
                    {
                        static const std::vector<std::int64_t> d{-2, -1, 1, 2};
                        const std::int64_t n = static_cast<std::int64_t>(r.occurrence) + rng_.pick(d);
                        r.occurrence = static_cast<std::uint32_t>(std::max<std::int64_t>(n, 0));
                        if (r.occurrence == le.before)
                            r.occurrence = static_cast<std::uint32_t>(le.before + 1);
                    }
                    le.detail = "patch moved to a neighbouring call";
                }
                break;
            case 2:
                le.strategy = Strategy::RecordEveryCall;
                le.before = r.flags;
                r.flags ^= W32k::MutFlag::EveryCall;
                if (trace && !detail::targetsTrace(r, *trace))
                {
                    // Back to one call, but the stored occurrence is not in this trace.
                    r.flags = static_cast<std::uint8_t>(le.before);
                    goto value;
                }
                le.detail = r.every_call() ? "now sticky" : "now one call";
                break;
            case 3:
                if (r.op != W32k::MutOp::Write)
                    goto value;
                {
                    const std::int64_t w = r.width;
                    const std::vector<std::int64_t> d{-w, w, -1, 1};
                    le.strategy = Strategy::RecordOffset;
                    le.before = r.offset;
                    const std::int64_t n = static_cast<std::int64_t>(r.offset) + rng_.pick(d);
                    r.offset = static_cast<std::uint32_t>(std::max<std::int64_t>(n, 0));
                    if (r.offset == le.before)
                        r.offset = static_cast<std::uint32_t>(le.before + static_cast<std::uint64_t>(w));
                }
                break;
            case 4:
                if (recs.size() == 1)
                    goto value; // deleting the only record would turn the input back into the baseline
                le.strategy = Strategy::RecordDelete;
                le.record = r;
                le.before = idx;
                recs.erase(recs.begin() + static_cast<std::ptrdiff_t>(idx));
                log_.entries.push_back(std::move(le));
                return;
            default:
            {
                le.strategy = Strategy::RecordSplice;
                recs.push_back(*spliceable[rng_.below(spliceable.size())]);
                le.record = recs.back();
                le.detail = "from donor program";
                log_.entries.push_back(std::move(le));
                return;
            }
            }
            le.record = r;
            log_.entries.push_back(std::move(le));
        }

        // ---- record emission ---------------------------------------------------

        /// Key of the call currently being generated for, plus the per-record flags.
        W32k::MutRecord key(Strategy s, std::size_t arg)
        {
            W32k::MutRecord r;
            r.ssn = cur_->ssn;
            r.occurrence = cur_->occurrence;
            r.fingerprint = cur_->fingerprint;
            r.arg = static_cast<std::uint8_t>(arg);
            r.strategy = static_cast<std::uint8_t>(s);
            if (rng_.chance(cfg_.every_call_chance))
                r.flags |= W32k::MutFlag::EveryCall;
            return r;
        }

        void push(W32k::MutRecord r, Strategy s, std::uint64_t before, std::string note)
        {
            program_.records.push_back(r);
            detail::LogEntry le;
            le.strategy = s;
            le.record = std::move(r);
            le.before = before;
            le.event = curIndex_;
            le.detail = std::move(note);
            log_.entries.push_back(std::move(le));
        }

        void emitSetArg(std::size_t arg, int width, std::uint64_t before, std::uint64_t after, Strategy s,
                        std::string note = {})
        {
            if ((after & detail::widthMask(width)) == (before & detail::widthMask(width)))
                return; // would change nothing: not worth an execution
            auto r = key(s, arg);
            r.op = W32k::MutOp::SetArg;
            r.width = static_cast<std::uint8_t>(width);
            r.value = after & detail::widthMask(width);
            r.expect = before & detail::widthMask(width);
            if (cfg_.guard_scalars && !detail::isPointerStrategy(r.strategy))
                r.flags |= W32k::MutFlag::Guard;
            push(r, s, before, std::move(note));
        }

        /// A write at `blobOff` in the captured blob of argument `arg` (or of its nested
        /// entry `nested`), translated to the live memory layout the driver will see.
        void emitWrite(std::size_t arg, int nested, std::size_t blobOff, int width, std::uint64_t before,
                       std::uint64_t after, Strategy s, std::string note = {})
        {
            if ((after & detail::widthMask(width)) == (before & detail::widthMask(width)))
                return;
            auto r = key(s, arg);
            r.op = W32k::MutOp::Write;
            r.width = static_cast<std::uint8_t>(width);
            r.value = after & detail::widthMask(width);
            r.expect = before & detail::widthMask(width);
            const auto &a = cur_->args[arg];
            if (nested >= 0)
            {
                r.flags |= W32k::MutFlag::Nested;
                r.parent_offset = cur_->nested[static_cast<std::size_t>(nested)].parent_offset;
                r.offset = static_cast<std::uint32_t>(blobOff);
            }
            else if (a.capture_type == W32k::CaptureType::UnicodeString && blobOff >= sizeof(W32k::UnicodeStringBlob))
            {
                // Blob = 16-byte header (same offsets as the live UNICODE_STRING) + chars,
                // so characters live behind UNICODE_STRING.Buffer at +8.
                r.flags |= W32k::MutFlag::Nested;
                r.parent_offset = 8;
                r.offset = static_cast<std::uint32_t>(blobOff - sizeof(W32k::UnicodeStringBlob));
            }
            else
            {
                r.offset = static_cast<std::uint32_t>(blobOff);
            }
            if (cfg_.guard_writes)
                r.flags |= W32k::MutFlag::Guard;
            push(r, s, before, std::move(note));
        }

        void emitResize(std::size_t arg, std::size_t oldBytes, std::size_t newBytes, int countArg,
                        std::uint64_t countValue, std::uint64_t oldN, std::string note)
        {
            auto r = key(Strategy::ArrayResize, arg);
            r.op = W32k::MutOp::Resize;
            r.length = static_cast<std::uint32_t>(newBytes);
            r.source_length = static_cast<std::uint32_t>(oldBytes);
            r.count_arg = static_cast<std::int8_t>(countArg);
            r.value = countValue;
            push(r, Strategy::ArrayResize, oldN, std::move(note));
        }

        /// Change the shadow blob and emit the matching write record.
        void patch(std::vector<std::uint8_t> &blob, std::size_t arg, int nested, std::size_t off, int w,
                   std::uint64_t after, Strategy s, std::string note = {})
        {
            const std::uint64_t before = detail::readAt(blob, off, w);
            detail::writeAt(blob, off, w, after);
            emitWrite(arg, nested, off, w, before, after, s, std::move(note));
        }

        // ---- per-argument tactics (unchanged logic, now emitting records) -------

        void mutateArg(W32k::EventInfo &ev, std::size_t i)
        {
            switch (ev.args[i].kind)
            {
            case ArgKind::Handle:
                if (cfg_.mutate_handles)
                    mutateScalar(ev, i);
                break;
            case ArgKind::Scalar:
                mutateScalar(ev, i);
                break;
            case ArgKind::Array:
                mutateArray(ev, i);
                break;
            case ArgKind::Buffer:
                mutateBuffer(ev, i);
                break;
            case ArgKind::String:
                mutateString(ev, i);
                break;
            case ArgKind::Pointer:
                mutateOpaque(ev, i);
                break;
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
            if (out == (before & detail::widthMask(width)))
                out = (before ^ (1ull << rng_.below(static_cast<std::uint64_t>(width) * 8))) & detail::widthMask(width);
            a.value = out;
            emitSetArg(i, width, before, out, how);
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
                const std::uint64_t after = rng_.pick(w <= 4 ? detail::interesting32() : detail::interesting64());
                patch(a.data, i, -1, off, w, after, Strategy::ArrayElement, "element " + std::to_string(k));
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
                    patch(a.data, i, -1, 0, 2, after, Strategy::StringLength,
                          (after & 1) ? "odd byte length" : "length vs maximum");
                }
                if (roll())
                {
                    const std::uint64_t wild = rng_.pick(detail::interestingPointers());
                    patch(a.data, i, -1, 8, 8, wild, Strategy::StringBuffer, "Buffer repointed");
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
                // Live equivalent of stripping the NUL: overwrite it, the kernel reads on.
                patch(a.data, i, -1, a.data.size() - cw, static_cast<int>(cw), 0x41, Strategy::StringTerminator,
                      "NUL terminator overwritten");
                a.capture_flags.bits |= detail::kCapfUnterminated;
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
            std::uint64_t wild = before;
            for (int t = 0; t < 8 && wild == before; ++t)
                wild = rng_.pick(detail::interestingPointers());
            if (wild == before)
                return;
            detail::setRawPointer(a, wild);

            // The pointee is gone, so whatever was captured behind it is stale.
            const auto dropped = std::count_if(ev.nested.begin(), ev.nested.end(),
                                               [&](const W32k::NestedInfo &n)
                                               { return n.arg_index == i; });
            ev.nested.erase(std::remove_if(ev.nested.begin(), ev.nested.end(),
                                           [&](const W32k::NestedInfo &n)
                                           { return n.arg_index == i; }),
                            ev.nested.end());
            std::string note = "argument pointer replaced";
            if (dropped)
                note += ", " + std::to_string(dropped) + " nested entr" + (dropped == 1 ? "y" : "ies") + " ignored";
            emitSetArg(i, 8, before, wild, detail::pointerStrategy(wild), std::move(note));
        }

        // ---- shared pieces ----------------------------------------------------

        /// Resize FIRST, then desync: the resize rewrites the count to match, so doing it
        /// after a desync would silently undo the desync. The driver applies the records
        /// in the same order.
        void resizeAndDesync(W32k::EventInfo &ev, std::size_t i, const detail::LengthLink &link, std::size_t es)
        {
            auto &a = ev.args[i];

            if (cfg_.resize_arrays && roll())
            {
                const std::size_t oldBytes = a.data.size();
                const std::size_t oldN = oldBytes / es;
                std::size_t cap = std::min(cfg_.max_array_bytes / es, cfg_.max_array_elements);
                std::size_t newN = oldN;
                for (int t = 0; t < 8 && newN == oldN; ++t)
                    newN = detail::pickElementCount(rng_, oldN, std::max<std::size_t>(cap, 1));

                if (newN != oldN) // the same size would only cost an execution
                {
                    // Shadow: grow by repeating the existing elements, as the driver will.
                    std::vector<std::uint8_t> nb(newN * es);
                    for (std::size_t b = 0; b < nb.size(); ++b)
                        nb[b] = oldBytes ? a.data[b % oldBytes] : 0;
                    a.data = std::move(nb);
                    a.requested_length = static_cast<std::uint32_t>(a.data.size());
                    a.capture_flags.bits &= ~(detail::kCapfTruncated | detail::kCapfFault);
                    dropNestedBeyond(ev, i, a.data.size());

                    std::string note;
                    std::uint64_t count = 0;
                    if (link.arg >= 0)
                    {
                        auto &c = ev.args[static_cast<std::size_t>(link.arg)];
                        count = (a.data.size() / link.unit) & detail::widthMask(detail::argWidth(c));
                        c.value = count;
                        note = "count in a" + std::to_string(link.arg) + " kept in sync";
                    }
                    emitResize(i, oldBytes, a.data.size(), link.arg, count, oldN,
                               "-> " + std::to_string(newN) + " element(s)" + (note.empty() ? "" : ", " + note));
                }
            }

            // Desynchronising the count from the buffer is the point of knowing the link.
            if (cfg_.desync_counts && link.arg >= 0 && roll())
            {
                auto &c = ev.args[static_cast<std::size_t>(link.arg)];
                const int cw = detail::argWidth(c);
                const std::uint64_t before = c.value;
                const std::uint64_t claimed = rng_.pick(detail::interesting32()) & detail::widthMask(cw);
                c.value = claimed;
                emitSetArg(static_cast<std::size_t>(link.arg), cw, before, claimed, Strategy::ArrayCountDesync,
                           "buffer a" + std::to_string(i) + " holds " + std::to_string(a.data.size() / link.unit) +
                               " unit(s) of " + std::to_string(link.unit));
            }
        }

        /// Field-wise mutation of a blob with no recovered layout.
        void mutateFields(std::vector<std::uint8_t> &blob, std::size_t arg, int nested,
                          const std::vector<std::uint32_t> &skip)
        {
            const auto covered = [&](std::size_t off, std::size_t w)
            {
                return std::any_of(skip.begin(), skip.end(),
                                   [&](std::uint32_t p)
                                   { return off < p + 8u && p < off + w; });
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
                    const std::uint64_t after = rng_.pick(around) & detail::widthMask(cbWidth);
                    patch(blob, arg, nested, 0, cbWidth, after, Strategy::StructSizeField,
                          "cbSize-like, caller wrote " + std::to_string(k));
                    continue;
                }
                if (ptrField)
                {
                    const std::uint64_t wild = rng_.pick(detail::interestingPointers());
                    patch(blob, arg, nested, here, iw, wild, Strategy::StructPointerField, "inline pointer-like field");
                    continue;
                }
                const std::uint64_t after = rng_.pick(detail::interesting32());
                patch(blob, arg, nested, here, iw, after, Strategy::StructField, "4 bytes");
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
                    // The live pointer sits in the parent's pointee: overwrite it there.
                    const std::uint64_t before = ne.pointer_value;
                    std::uint64_t wild = before;
                    for (int t = 0; t < 8 && wild == before; ++t)
                        wild = rng_.pick(detail::interestingPointers());
                    if (wild == before)
                        continue;
                    detail::setRawPointer(ne, wild);
                    detail::writeAt(parent, ne.parent_offset, 8, wild);
                    emitWrite(i, -1, ne.parent_offset, 8, before, wild, Strategy::StructPointerField,
                              "nested pointer repointed");
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
                                           [&](const W32k::NestedInfo &n)
                                           {
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
            const auto after = static_cast<std::uint8_t>(rng_.next());
            patch(blob, arg, nested, at, 1, after, how, std::move(note));
        }
    };

} // namespace Syscall

REGISTER_MUTATOR(Syscall::SyscallMutator_t, "syscall", "Specialised mutator for syscalls");
