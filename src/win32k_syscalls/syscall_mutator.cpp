// The "syscall" mutator: builds and edits win32k syscall programs.
//
// An input is a serialised win32k::prog::Program (syscall_program.hpp). Calls
// are built from the generated table (win32k_syscall_table.hpp); every
// argument comes from one of these sources, chosen at random:
//   - the sysmon argument pool, looked up by the argument's C type; the program
//     is then sent to the thread that argument was recorded on,
//   - the return value of an earlier call in the same program (handles),
//   - literals seen at user-mode call sites, boundary values, random values,
//   - memory built from what the table knows about the pointee.
#include "syscall_mutator.hpp"

#include <algorithm>
#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "../mutator.hpp"
#include "syscall_program.hpp"
#include "sysmon_argpool.hpp"
#include "win32k_syscall_table.hpp"

namespace
{

    using namespace win32k;
    using prog::Call;
    using prog::Program;
    using prog::Reloc;
    using prog::Value;

    constexpr std::size_t kTargetCalls = 32;

    static sysmon::ArgPool g_ArgPool; 
    std::atomic<const sysmon::ArgPool *> g_pool{nullptr};
    std::atomic<std::shared_mutex *> g_poolGuard{nullptr};

    // ---------------------------------------------------------------- table

    const SyscallDesc *findSyscall(uint16_t ssn)
    {
        const SyscallDesc *end = kSyscalls + kNumSyscalls;
        const SyscallDesc *it = std::lower_bound(kSyscalls, end, ssn,
                                                 [](const SyscallDesc &s, uint16_t v) { return s.ssn < v; });
        return it != end && it->ssn == ssn ? it : nullptr;
    }

    const ArgDesc &argOf(const SyscallDesc &sc, std::size_t i) { return kArgs[sc.firstArg + i]; }

    struct TableIndex_t
    {
        std::vector<const SyscallDesc *> producers;                             // enabled syscalls returning a handle
        std::map<std::string_view, std::vector<const SyscallDesc *>> consumers; // argument type -> syscalls taking it

        TableIndex_t()
        {
            for (const SyscallDesc &sc : kSyscalls)
            {
                if (!sc.enabled)
                    continue;
                if (sc.ret == Ret::Handle)
                    producers.push_back(&sc);
                for (std::size_t i = 0; i < sc.numArgs; ++i)
                {
                    auto &list = consumers[argOf(sc, i).type];
                    if (list.empty() || list.back() != &sc)
                        list.push_back(&sc);
                }
            }
        }
    };

    const TableIndex_t &tableIndex()
    {
        static const TableIndex_t index;
        return index;
    }

    bool isPointerKind(Kind k) { return k == Kind::Pointer || k == Kind::Buffer || k == Kind::Array || k == Kind::String; }
    bool isStringStruct(Text t) { return t == Text::UnicodeString || t == Text::AnsiString || t == Text::LargeString; }

    // Can a handle returned as `retType` be passed where `argType` is expected?
    bool handleFits(std::string_view retType, std::string_view argType)
    {
        if (retType == argType || argType == "HANDLE" || argType == "HGDIOBJ")
            return true;
        return (retType == "HICON" && argType == "HCURSOR") || (retType == "HCURSOR" && argType == "HICON");
    }

    // ------------------------------------------------------------ primitives

    // State of one mutate() call.
    // How much of the budget each syscall gets when a new call is chosen.
    //
    // Executions are expensive, so calls that cannot teach much get less of them:
    //   - no arguments: nothing to vary, running it a few times says it all;
    //   - only plain numbers: little for the kernel to parse or get wrong;
    //   - pointers, and even more so structs the kernel is known to read fields
    //     of or follow pointers in: the most validation code per call.
    // The caller's focus (setSyscallFocus) multiplies the result.
    struct Weights_t
    {
        std::vector<double> weight;     // per entry of kSyscalls; 0 = never chosen
        std::vector<double> cumulative; // running sum of `weight`
        double maxWeight = 0;
        std::size_t usable = 0;         // entries with a non-zero weight

        explicit Weights_t(const std::vector<std::pair<std::string, double>> &focus)
        {
            for (const SyscallDesc &sc : kSyscalls)
            {
                double w = 1.0;
                bool anyPointer = false, anyStruct = false;
                for (std::size_t i = 0; i < sc.numArgs; ++i)
                {
                    const ArgDesc &d = kArgs[sc.firstArg + i];
                    anyPointer |= d.kind == Kind::Pointer || d.kind == Kind::Buffer || d.kind == Kind::Array || d.kind == Kind::String;
                    anyStruct |= d.numFields != 0 || d.numNested != 0;
                }
                if (sc.numArgs == 0)
                    w = 0.05;
                else if (anyStruct)
                    w = 3.0;
                else if (anyPointer)
                    w = 2.0;
                else
                {
                    bool anyHandle = false;
                    for (std::size_t i = 0; i < sc.numArgs; ++i)
                        anyHandle |= kArgs[sc.firstArg + i].kind == Kind::Handle;
                    w = anyHandle ? 1.0 : 0.5;
                }

                // The longest matching name prefix decides the focus multiplier.
                std::size_t best = 0;
                double multiplier = 1.0;
                bool matched = false;
                for (const auto &[prefix, m] : focus)
                {
                    if (sc.name.substr(0, prefix.size()) == prefix && (!matched || prefix.size() > best))
                    {
                        best = prefix.size();
                        multiplier = m;
                        matched = true;
                    }
                }
                w = sc.enabled && multiplier > 0 ? w * multiplier : 0.0;

                weight.push_back(w);
                cumulative.push_back((cumulative.empty() ? 0.0 : cumulative.back()) + w);
                maxWeight = std::max(maxWeight, w);
                usable += w > 0;
            }
        }
    };

    std::mutex g_weightsLock;
    std::shared_ptr<const Weights_t> g_weights; // null until first use or setSyscallFocus()

    std::shared_ptr<const Weights_t> currentWeights()
    {
        std::lock_guard<std::mutex> lock(g_weightsLock);
        if (!g_weights)
            g_weights = std::make_shared<const Weights_t>(std::vector<std::pair<std::string, double>>{});
        return g_weights;
    }

    struct Gen_t
    {
        Rng_t &rng;
        const sysmon::ArgPool *pool;       // may be null
        std::optional<uint64_t> thread;    // the program's thread: prefer pool arguments it passed
        const Weights_t *weights;          // never null
    };

    double unitRandom(Rng_t &rng) { return static_cast<double>(rng() >> 11) * 0x1.0p-53; } // [0, 1)

    uint64_t mask(uint64_t v, std::size_t width) { return width >= 8 ? v : v & ((1ull << (width * 8)) - 1); }

    void store(std::vector<uint8_t> &b, std::size_t offset, uint64_t v, std::size_t width)
    {
        for (std::size_t i = 0; i < width; ++i)
            b[offset + i] = static_cast<uint8_t>(v >> (8 * i));
    }

    std::vector<uint8_t> randomBytes(Rng_t &rng, std::size_t n)
    {
        std::vector<uint8_t> b(n);
        for (uint8_t &x : b)
            x = static_cast<uint8_t>(rng());
        return b;
    }

    // A value worth trying for an integer of `width` bytes.
    uint64_t interestingInt(Rng_t &rng, std::size_t width)
    {
        const std::size_t bits = width * 8;
        uint64_t v = 0;
        switch (randBelow(rng, 6))
        {
        case 0: // small
            v = randBelow(rng, 17);
            break;
        case 1: // small negative
            v = 0 - static_cast<uint64_t>(1 + randBelow(rng, 4));
            break;
        case 2: // around a power of two
            v = (1ull << randBelow(rng, bits)) + randBelow(rng, 3) - 1;
            break;
        case 3: // signed limits
            v = (1ull << (bits - 1)) - randBelow(rng, 2);
            break;
        case 4: // ids, messages, flag words
            v = randBelow(rng, 0x10000);
            break;
        default:
            v = rng();
            break;
        }
        return mask(v, width);
    }

    // NULL most of the time, otherwise an address the kernel must reject.
    uint64_t badPointer(Rng_t &rng)
    {
        static constexpr uint64_t kBad[] = {0, 0, 0, 0, 1, 0xFFFF, 0x10000, 0x00007FFFFFFEFFFFull,
                                            0x00007FFFFFFF0000ull, 0xFFFF800000000000ull, ~0ull};
        return kBad[randBelow(rng, std::size(kBad))];
    }

    // Turn zero-filled memory into explicit bytes so they can be edited.
    void materialize(Value &m)
    {
        if (m.data.size() != m.size)
            m.data.assign(m.size, 0);
    }

    // Characters of a string, `elem` bytes each, without terminator.
    std::vector<uint8_t> genChars(Rng_t &rng, std::size_t elem)
    {
        static constexpr std::string_view kStrings[] = {
            "", "A", "Button", "Edit", "Static", "ListBox", "ComboBox", "ScrollBar", "MDIClient",
            "#32768", "#32769", "#32770", "#32771", "#32772", "Message", "IME", "tooltips_class32",
            "DISPLAY", "\\\\.\\DISPLAY1", "WinSta0", "Default", "Arial", "Segoe UI", "Marlett"};

        if (elem == 0)
            elem = 1;
        std::vector<uint8_t> out;
        const auto put = [&](uint64_t ch) {
            for (std::size_t k = 0; k < elem; ++k)
                out.push_back(static_cast<uint8_t>(ch >> (8 * k)));
        };
        if (coinFlip(rng))
        {
            for (const char c : kStrings[randBelow(rng, std::size(kStrings))])
                put(static_cast<unsigned char>(c));
        }
        else
        {
            const std::size_t n = randBelow(rng, 4) == 0 ? randBelow(rng, 257) : randBelow(rng, 33);
            const bool printable = randBelow(rng, 4) != 0;
            for (std::size_t i = 0; i < n; ++i)
                put(printable ? 0x20 + randBelow(rng, 0x5F) : rng());
        }
        return out;
    }

    // UNICODE_STRING / ANSI_STRING / LARGE_STRING around `chars`: a 16-byte
    // header with the lengths and, at offset 8, a pointer to the characters.
    Value wrapString(Text text, std::vector<uint8_t> chars, std::size_t elem)
    {
        if (elem == 0)
            elem = 1;
        chars.resize(std::min(chars.size(), prog::kMaxMem - elem) / elem * elem);
        const std::size_t length = chars.size();
        chars.insert(chars.end(), elem, 0); // terminator, counted in MaximumLength only

        std::vector<uint8_t> header(16);
        if (text == Text::LargeString)
        {
            store(header, 0, length, 4);
            store(header, 4, (length + elem) | (elem == 1 ? 0x80000000u : 0), 4); // MaximumLength:31, bAnsi:1
        }
        else
        {
            store(header, 0, length, 2);
            store(header, 2, length + elem, 2);
        }
        Value v = prog::Mem(std::move(header));
        v.relocs.push_back(Reloc{8, prog::Mem(std::move(chars))});
        return v;
    }

    // Contents of an input struct of `size` bytes, steered by the fields the kernel reads.
    std::vector<uint8_t> fillStruct(Rng_t &rng, const ArgDesc &d, std::size_t size)
    {
        std::vector<uint8_t> b = randBelow(rng, 3) == 0 ? randomBytes(rng, size) : std::vector<uint8_t>(size);
        for (std::size_t i = 0; i < d.numFields; ++i)
        {
            const FieldDesc &f = kFields[d.firstField + i];
            if (static_cast<std::size_t>(f.offset) + f.size > size)
                continue;
            if (f.size > 8)
            {
                if (coinFlip(rng))
                    for (std::size_t k = 0; k < f.size; ++k)
                        b[f.offset + k] = static_cast<uint8_t>(rng());
            }
            else if (f.hasConst && randBelow(rng, 10) != 0)
                store(b, f.offset, f.constValue, f.size);
            else if (randBelow(rng, 4) != 0)
                store(b, f.offset, interestingInt(rng, f.size), f.size);
        }
        // Win32 convention: many structs start with their own size.
        const bool sizeKnown = d.numFields != 0 && kFields[d.firstField].offset == 0 && kFields[d.firstField].hasConst;
        if (!sizeKnown && size >= 4 && randBelow(rng, 4) == 0)
            store(b, 0, size, 4);
        return b;
    }

    // Memory for a pointer argument, built from the table alone.
    Value buildMem(Rng_t &rng, const ArgDesc &d)
    {
        const bool out = d.dir == Dir::Out;
        if (isStringStruct(d.text))
            return wrapString(d.text, genChars(rng, d.elemSize), d.elemSize);

        if (d.text == Text::NulTerminated && !out)
        {
            std::vector<uint8_t> chars = genChars(rng, d.elemSize);
            if (randBelow(rng, 10) != 0)
                chars.insert(chars.end(), d.elemSize, 0);
            return prog::Mem(std::move(chars));
        }

        if (d.elemSize != 0)
        {
            const std::size_t elem = d.elemSize;
            const std::size_t count = std::min(prog::kMaxMem / elem,
                                               randBelow(rng, 4) == 0 ? randBelow(rng, 257) : randBelow(rng, 9));
            if (out)
                return prog::ZeroMem(count * elem);
            if (elem <= 2 && coinFlip(rng))
                return prog::Mem(genChars(rng, elem));
            std::vector<uint8_t> bytes = elem <= 8 ? std::vector<uint8_t>(count * elem) : randomBytes(rng, count * elem);
            for (std::size_t i = 0; elem <= 8 && i < count; ++i)
                store(bytes, i * elem, interestingInt(rng, elem), elem);
            return prog::Mem(std::move(bytes));
        }

        static constexpr uint16_t kSizes[] = {4, 8, 16, 24, 32, 48, 64, 128, 256, 512, 1024};
        std::size_t size = d.pointeeSize != 0 ? d.pointeeSize : kSizes[randBelow(rng, std::size(kSizes))];
        for (std::size_t i = 0; i < d.numNested; ++i)
            size = std::max<std::size_t>(size, kNested[d.firstNested + i].atOffset + 8);

        Value m = out ? prog::ZeroMem(size) : prog::Mem(fillStruct(rng, d, size));
        for (std::size_t i = 0; i < d.numNested; ++i)
        {
            const NestedDesc &n = kNested[d.firstNested + i];
            m.relocs.push_back(Reloc{n.atOffset, coinFlip(rng) ? prog::Mem(randomBytes(rng, n.size)) : prog::ZeroMem(n.size)});
        }
        return m;
    }

    // ------------------------------------------------------------------ pool

    const sysmon::PooledArg *pickPooled(Gen_t &g, std::string_view type)
    {
        if (g.pool == nullptr)
            return nullptr;
        const sysmon::PooledArg *p = g.thread ? g.pool->Pick(type, g.rng, g.thread) : nullptr;
        if (p == nullptr)
            p = g.pool->Pick(type, g.rng);
        if (p != nullptr && !g.thread)
            g.thread = p->threadId; // first recorded argument: the program moves to its thread
        return p;
    }

    // A pooled argument as a program value for parameter `d`, or nothing if it
    // cannot be replayed (a pointer whose target was not captured).
    std::optional<Value> fromPool(Gen_t &g, const ArgDesc &d, const sysmon::PooledArg &p)
    {
        const sysmon::Arg &a = p.arg;
        const bool captured = (a.capture == sysmon::Capture::Ok || a.capture == sysmon::Capture::Truncated) && a.data.size() != 0;
        if (captured && d.size == 8)
        {
            // The recorded address means nothing in the guest: ship the bytes it pointed to.
            const auto *first = reinterpret_cast<const uint8_t *>(a.data.data());
            std::vector<uint8_t> bytes(first, first + std::min<std::size_t>(a.data.size(), prog::kMaxMem));
            if (isStringStruct(d.text))
            {
                // Text captures hold the characters. A bare 16-byte capture is the
                // struct itself, whose buffer pointer is stale: give it new characters.
                if (!a.isText && bytes.size() == 16)
                    bytes = genChars(g.rng, d.elemSize);
                return wrapString(d.text, std::move(bytes), d.elemSize);
            }
            Value m = prog::Mem(std::move(bytes));
            for (std::size_t i = 0; i < d.numNested; ++i)
            {
                // Pointers inside the captured struct are stale too: point them at fresh memory.
                const NestedDesc &n = kNested[d.firstNested + i];
                if (static_cast<std::size_t>(n.atOffset) + 8 <= m.size)
                    m.relocs.push_back(Reloc{n.atOffset, prog::Mem(randomBytes(g.rng, n.size))});
            }
            return m;
        }
        if (isPointerKind(d.kind) && a.value >= 0x10000)
            return std::nullopt;
        return prog::Imm(mask(a.value, d.size)); // handles, scalars, NULL, atoms, resource ids
    }

    std::optional<Value> tryPool(Gen_t &g, const ArgDesc &d, std::string_view type)
    {
        const sysmon::PooledArg *p = pickPooled(g, type);
        return p != nullptr ? fromPool(g, d, *p) : std::nullopt;
    }

    // -------------------------------------------------------------- arguments

    // An earlier call (before `callIdx`) returning a handle usable as `type`; any handle if `type` is empty.
    std::optional<std::size_t> findProducer(Gen_t &g, const Program &p, std::size_t callIdx, std::string_view type)
    {
        std::optional<std::size_t> found;
        std::size_t seen = 0;
        for (std::size_t j = 0; j < callIdx && j < p.calls.size(); ++j)
        {
            const SyscallDesc *sc = findSyscall(p.calls[j].ssn);
            if (sc == nullptr || sc->ret != Ret::Handle || (!type.empty() && !handleFits(sc->retType, type)))
                continue;
            if (randBelow(g.rng, ++seen) == 0) // reservoir sampling: each candidate equally likely
                found = j;
        }
        return found;
    }

    Value genHandle(Gen_t &g, const Program &p, std::size_t callIdx, const ArgDesc &d)
    {
        const std::size_t roll = randBelow(g.rng, 100);
        const auto producer = findProducer(g, p, callIdx, d.type);
        if (roll < 35 && producer)
            return prog::Result(*producer);
        if (roll < 85)
        {
            if (auto v = tryPool(g, d, d.type))
                return *v;
            if (producer)
                return prog::Result(*producer);
        }
        // NULL / desktop, HWND_BROADCAST, HWND_TOPMOST .. HWND_MESSAGE, stock-object-like small values.
        static constexpr uint64_t kSpecial[] = {0, 0, 1, 0xFFFF, ~0ull, ~0ull - 1, ~0ull - 2};
        if (randBelow(g.rng, 4) != 0)
            return prog::Imm(mask(kSpecial[randBelow(g.rng, std::size(kSpecial))], d.size));
        return prog::Imm(interestingInt(g.rng, d.size));
    }

    Value genScalar(Gen_t &g, const ArgDesc &d)
    {
        const std::size_t roll = randBelow(g.rng, 100);
        if (roll < 40)
        {
            if (auto v = tryPool(g, d, d.type))
                return *v;
        }
        if (roll < 75 && d.numValues != 0)
            return prog::Imm(mask(static_cast<uint64_t>(kValues[d.firstValue + randBelow(g.rng, d.numValues)]), d.size));
        return prog::Imm(interestingInt(g.rng, d.size));
    }

    Value genPointer(Gen_t &g, const ArgDesc &d)
    {
        const std::size_t roll = randBelow(g.rng, 100);
        if (roll < 40)
        {
            if (auto v = tryPool(g, d, d.type))
                return *v;
        }
        if (roll >= 95)
            return prog::Imm(badPointer(g.rng));
        return buildMem(g.rng, d);
    }

    // An argument the table could not type (ULONG_PTR): it may be a handle, a pointer or a number.
    Value genUntyped(Gen_t &g, const Program &p, std::size_t callIdx, const ArgDesc &d)
    {
        static constexpr std::string_view kHandleTypes[] = {"HWND", "HDC", "HANDLE", "HMENU", "HBITMAP", "HRGN"};
        const std::size_t roll = randBelow(g.rng, 100);
        if (roll < 30)
        {
            if (auto v = tryPool(g, d, d.type))
                return *v;
        }
        else if (roll < 45)
        {
            if (auto v = tryPool(g, d, kHandleTypes[randBelow(g.rng, std::size(kHandleTypes))]))
                return *v;
        }
        else if (roll < 60)
        {
            if (const auto producer = findProducer(g, p, callIdx, {}))
                return prog::Result(*producer);
        }
        else if (roll < 75 && d.size == 8)
            return buildMem(g.rng, d);
        return prog::Imm(interestingInt(g.rng, d.size));
    }

    // A value for parameter `d` of the call at position `callIdx` of `p`.
    Value genArg(Gen_t &g, const Program &p, std::size_t callIdx, const ArgDesc &d)
    {
        switch (d.kind)
        {
        case Kind::Handle:
            return genHandle(g, p, callIdx, d);
        case Kind::Scalar:
            return d.type == "ULONG_PTR" ? genUntyped(g, p, callIdx, d) : genScalar(g, d);
        case Kind::Unknown:
            return genUntyped(g, p, callIdx, d);
        default:
            return genPointer(g, d);
        }
    }

    // If argument `i` is an array whose element count lives in another
    // argument, make that argument agree with the array's current size.
    void syncCount(const SyscallDesc &sc, Call &c, std::size_t i)
    {
        const ArgDesc &d = argOf(sc, i);
        if (d.countArg < 0 || d.elemSize == 0 || !c.args[i].IsMem())
            return;
        const auto j = static_cast<std::size_t>(d.countArg);
        if (j < c.args.size())
            c.args[j] = prog::Imm(mask(c.args[i].size / d.elemSize, argOf(sc, j).size));
    }

    Call genCall(Gen_t &g, const Program &p, std::size_t callIdx, const SyscallDesc &sc)
    {
        Call c;
        c.ssn = sc.ssn;
        for (std::size_t i = 0; i < sc.numArgs; ++i)
            c.args.push_back(genArg(g, p, callIdx, argOf(sc, i)));
        for (std::size_t i = 0; i < sc.numArgs; ++i)
        {
            if (randBelow(g.rng, 8) != 0) // now and then leave count and buffer in disagreement
                syncCount(sc, c, i);
        }
        return c;
    }

    // The syscall for a new call at position `pos`.
    const SyscallDesc &pickSyscall(Gen_t &g, const Program &p, std::size_t pos)
    {
        const TableIndex_t &index = tableIndex();
        const Weights_t &w = *g.weights;
        // A member of `list`, each in proportion to its weight; null if none is found quickly.
        const auto fromList = [&](const std::vector<const SyscallDesc *> &list) -> const SyscallDesc * {
            for (int tries = 0; tries < 8 && !list.empty(); ++tries)
            {
                const SyscallDesc *sc = list[randBelow(g.rng, list.size())];
                if (unitRandom(g.rng) * w.maxWeight < w.weight[static_cast<std::size_t>(sc - kSyscalls)])
                    return sc;
            }
            return nullptr;
        };
        const auto consumerOf = [&](std::string_view type) -> const SyscallDesc * {
            const auto it = index.consumers.find(type);
            return it == index.consumers.end() ? nullptr : fromList(it->second);
        };

        const std::size_t roll = randBelow(g.rng, 100);
        if (roll < 10)
        {
            // Something that creates a handle for later calls to use.
            if (const SyscallDesc *sc = fromList(index.producers))
                return *sc;
        }
        else if (roll < 40)
        {
            // Something that takes a handle an earlier call creates.
            if (const auto producer = findProducer(g, p, pos, {}))
            {
                if (const SyscallDesc *sc = consumerOf(findSyscall(p.calls[*producer].ssn)->retType))
                    return *sc;
            }
        }
        else if (roll < 60 && g.pool != nullptr)
        {
            // Something that takes a type the pool has real arguments for.
            const std::vector<std::string_view> types = g.pool->Types(g.thread);
            if (!types.empty())
            {
                if (const SyscallDesc *sc = consumerOf(types[randBelow(g.rng, types.size())]))
                    return *sc;
            }
        }
        // Any syscall, in proportion to its weight.
        const double r = unitRandom(g.rng) * w.cumulative.back();
        std::size_t i = static_cast<std::size_t>(std::upper_bound(w.cumulative.begin(), w.cumulative.end(), r) - w.cumulative.begin());
        while (i >= kNumSyscalls || w.weight[i] <= 0) // rounding at the very end of the range
            i = i == 0 ? kNumSyscalls - 1 : i - 1;
        return kSyscalls[i];
    }

    // -------------------------------------------------------- program editing

    template <typename F>
    void forEachValue(Value &v, F &&f)
    {
        f(v);
        for (Reloc &r : v.relocs)
            forEachValue(r.target, f);
    }

    template <typename F>
    void forEachValue(Call &c, F &&f)
    {
        for (Value &v : c.args)
            forEachValue(v, f);
    }

    // `count` calls are about to be inserted at `pos`: keep later calls pointing at the same results.
    void shiftRefs(Program &p, std::size_t pos, std::size_t count)
    {
        for (std::size_t c = pos; c < p.calls.size(); ++c)
            forEachValue(p.calls[c], [&](Value &v) {
                if (v.tag == Value::Tag::Result && v.value >= pos)
                    v.value += count;
            });
    }

    void insertCallAt(Program &p, std::size_t pos, Call call)
    {
        shiftRefs(p, pos, 1);
        p.calls.insert(p.calls.begin() + static_cast<std::ptrdiff_t>(pos), std::move(call));
    }

    void removeCallAt(Program &p, std::size_t k)
    {
        p.calls.erase(p.calls.begin() + static_cast<std::ptrdiff_t>(k));
        for (std::size_t c = k; c < p.calls.size(); ++c)
            forEachValue(p.calls[c], [&](Value &v) {
                if (v.tag != Value::Tag::Result)
                    return;
                if (v.value == k)
                    v = prog::Imm(0); // its result is gone
                else if (v.value > k)
                    --v.value;
            });
    }

    // Make a parsed program safe to edit and to run: only enabled syscalls of
    // this table, the right number of arguments, results taken from earlier calls only.
    void sanitize(Gen_t &g, Program &p)
    {
        for (std::size_t i = 0; i < p.calls.size();)
        {
            const SyscallDesc *sc = findSyscall(p.calls[i].ssn);
            if (sc == nullptr || !sc->enabled)
            {
                removeCallAt(p, i);
                continue;
            }
            std::vector<Value> &args = p.calls[i].args;
            if (args.size() > sc->numArgs)
                args.resize(sc->numArgs);
            while (args.size() < sc->numArgs)
                args.push_back(genArg(g, p, i, argOf(*sc, args.size())));
            forEachValue(p.calls[i], [&](Value &v) {
                if (v.tag == Value::Tag::Result && v.value >= i)
                    v = prog::Imm(0);
            });
            ++i;
        }
    }

    bool insertCall(Gen_t &g, Program &p)
    {
        if (p.calls.size() >= prog::kMaxCalls)
            return false;
        const std::size_t pos = coinFlip(g.rng) ? p.calls.size() : randBelow(g.rng, p.calls.size() + 1);
        insertCallAt(p, pos, genCall(g, p, pos, pickSyscall(g, p, pos)));
        return true;
    }

    bool removeCall(Gen_t &g, Program &p)
    {
        if (p.calls.size() < 2)
            return false;
        removeCallAt(p, randBelow(g.rng, p.calls.size()));
        return true;
    }

    bool duplicateCall(Gen_t &g, Program &p)
    {
        if (p.calls.size() >= prog::kMaxCalls)
            return false;
        const std::size_t k = randBelow(g.rng, p.calls.size());
        insertCallAt(p, k + 1, Call(p.calls[k]));
        return true;
    }

    // Insert a run of calls taken from another corpus entry.
    bool spliceOther(Gen_t &g, Program &p, MutatorContext_t &ctx)
    {
        const InputPtr other = ctx.pickOther ? ctx.pickOther() : nullptr;
        if (!other || p.calls.size() >= prog::kMaxCalls)
            return false;
        Program q;
        prog::Parse(other->data(), other->size(), q);
        sanitize(g, q);
        if (q.calls.empty())
            return false;

        const std::size_t count = 1 + randBelow(g.rng, std::min({prog::kMaxCalls - p.calls.size(), q.calls.size(), std::size_t{4}}));
        const std::size_t first = randBelow(g.rng, q.calls.size() - count + 1);
        const std::size_t pos = randBelow(g.rng, p.calls.size() + 1);
        shiftRefs(p, pos, count);
        for (std::size_t i = 0; i < count; ++i)
        {
            Call c = std::move(q.calls[first + i]);
            forEachValue(c, [&](Value &v) {
                if (v.tag != Value::Tag::Result)
                    return;
                if (v.value >= first)
                    v.value = v.value - first + pos; // producer travels along
                else
                    v = prog::Imm(0); // producer left behind
            });
            p.calls.insert(p.calls.begin() + static_cast<std::ptrdiff_t>(pos + i), std::move(c));
        }
        return true;
    }

    // A random call that has arguments, and one of its arguments.
    bool pickArg(Gen_t &g, const Program &p, std::size_t &call, std::size_t &arg)
    {
        const std::size_t start = randBelow(g.rng, p.calls.size());
        for (std::size_t k = 0; k < p.calls.size(); ++k)
        {
            call = (start + k) % p.calls.size();
            if (!p.calls[call].args.empty())
            {
                arg = randBelow(g.rng, p.calls[call].args.size());
                return true;
            }
        }
        return false;
    }

    // Draw a fresh value for one argument (this is where pool arguments enter existing programs).
    bool replaceArg(Gen_t &g, Program &p)
    {
        std::size_t c = 0, i = 0;
        if (!pickArg(g, p, c, i))
            return false;
        const SyscallDesc &sc = *findSyscall(p.calls[c].ssn);
        p.calls[c].args[i] = genArg(g, p, c, argOf(sc, i));
        if (randBelow(g.rng, 8) != 0)
            syncCount(sc, p.calls[c], i);
        return true;
    }

    void tweakImm(Gen_t &g, const ArgDesc *d, Value &v)
    {
        const std::size_t width = d != nullptr ? d->size : 8;
        switch (randBelow(g.rng, d != nullptr && d->numValues != 0 ? 5 : 4))
        {
        case 0:
            v.value += 1 + randBelow(g.rng, 16);
            break;
        case 1:
            v.value -= 1 + randBelow(g.rng, 16);
            break;
        case 2:
            v.value ^= 1ull << randBelow(g.rng, width * 8);
            break;
        case 3:
            v.value = interestingInt(g.rng, width);
            break;
        default:
            v.value = static_cast<uint64_t>(kValues[d->firstValue + randBelow(g.rng, d->numValues)]);
            break;
        }
        v.value = mask(v.value, width);
    }

    void resizeMem(Gen_t &g, const ArgDesc *d, Value &m)
    {
        const std::size_t step = d != nullptr && d->elemSize != 0 ? d->elemSize : (coinFlip(g.rng) ? 1 : 8);
        std::size_t n = m.size;
        switch (randBelow(g.rng, 6))
        {
        case 0:
            n += step;
            break;
        case 1:
            n = n >= step ? n - step : 0;
            break;
        case 2:
            n /= 2;
            break;
        case 3:
            n = n != 0 ? n * 2 : step;
            break;
        case 4:
            n = 0;
            break;
        default:
            n = randBelow(g.rng, prog::kMaxMem + 1);
            break;
        }
        n = std::min(n, prog::kMaxMem);
        if (!m.data.empty())
            m.data.resize(n, static_cast<uint8_t>(g.rng()));
        m.size = static_cast<uint16_t>(n);
        std::erase_if(m.relocs, [&](const Reloc &r) { return static_cast<std::size_t>(r.offset) + 8 > n; });
    }

    void tweakMem(Gen_t &g, const ArgDesc *d, Value &m)
    {
        auto &rng = g.rng;
        switch (randBelow(rng, 6))
        {
        case 0: // edit what a pointer inside this memory leads to
            if (!m.relocs.empty())
            {
                Value &target = m.relocs[randBelow(rng, m.relocs.size())].target;
                if (target.IsMem())
                    tweakMem(g, nullptr, target);
                else
                    target = prog::Imm(badPointer(rng));
                break;
            }
            [[fallthrough]];
        case 1:
        case 2: // overwrite a few bytes
        {
            if (m.size == 0)
            {
                resizeMem(g, d, m);
                break;
            }
            materialize(m);
            for (std::size_t n = 1 + randBelow(rng, 4); n != 0; --n)
            {
                std::size_t width = std::size_t{1} << randBelow(rng, 4);
                if (width > m.size)
                    width = 1;
                store(m.data, randBelow(rng, m.size - width + 1), coinFlip(rng) ? interestingInt(rng, width) : rng(), width);
            }
            break;
        }
        case 3: // set a field the kernel is known to read
            if (d != nullptr && d->numFields != 0)
            {
                const FieldDesc &f = kFields[d->firstField + randBelow(rng, d->numFields)];
                if (f.size <= 8 && static_cast<std::size_t>(f.offset) + f.size <= m.size)
                {
                    materialize(m);
                    store(m.data, f.offset, interestingInt(rng, f.size), f.size);
                    break;
                }
            }
            [[fallthrough]];
        case 4:
            resizeMem(g, d, m);
            break;
        default: // break a pointer, or switch between initialised and zero-filled
            if (!m.relocs.empty())
            {
                const std::size_t k = randBelow(rng, m.relocs.size());
                if (coinFlip(rng))
                    m.relocs.erase(m.relocs.begin() + static_cast<std::ptrdiff_t>(k)); // leaves the bytes underneath
                else
                    m.relocs[k].target = prog::Imm(badPointer(rng));
            }
            else if (m.data.empty())
                m.data = randomBytes(rng, m.size);
            else
                m.data.clear();
            break;
        }
    }

    // Small change to an existing argument, keeping where it came from.
    bool tweakArg(Gen_t &g, Program &p)
    {
        std::size_t c = 0, i = 0;
        if (!pickArg(g, p, c, i))
            return false;
        const SyscallDesc &sc = *findSyscall(p.calls[c].ssn);
        const ArgDesc &d = argOf(sc, i);
        Value &v = p.calls[c].args[i];
        switch (v.tag)
        {
        case Value::Tag::Imm:
            tweakImm(g, &d, v);
            break;
        case Value::Tag::Result:
        {
            // Another producer of the same kind if there is one, otherwise a new value.
            const auto producer = findProducer(g, p, c, d.kind == Kind::Handle ? d.type : std::string_view{});
            v = producer && *producer != v.value ? prog::Result(*producer) : genArg(g, p, c, d);
            break;
        }
        case Value::Tag::Mem:
            tweakMem(g, &d, v);
            if (randBelow(g.rng, 4) != 0)
                syncCount(sc, p.calls[c], i);
            break;
        }
        return true;
    }

    // Run the same calls on another recorded thread: its handles now belong to someone else.
    bool changeThread(Gen_t &g)
    {
        if (g.pool == nullptr)
            return false;
        const std::vector<uint64_t> threads = g.pool->Threads();
        if (threads.empty())
            return false;
        const uint64_t thread = threads[randBelow(g.rng, threads.size())];
        if (g.thread && *g.thread == thread)
            return false;
        g.thread = thread;
        return true;
    }

    bool mutateOnce(Gen_t &g, Program &p, MutatorContext_t &ctx)
    {
        const std::size_t roll = randBelow(g.rng, 100);
        if (roll < 25)
        {
            // The longer the program, the more often this removes instead of adding,
            // so programs settle around half of kTargetCalls rather than at the limit.
            return randBelow(g.rng, kTargetCalls) < p.calls.size() ? removeCall(g, p) : insertCall(g, p);
        }
        if (roll < 50)
            return replaceArg(g, p);
        if (roll < 80)
            return tweakArg(g, p);
        if (roll < 88)
            return removeCall(g, p);
        if (roll < 92)
            return duplicateCall(g, p);
        if (roll < 95)
            return changeThread(g);
        return spliceOther(g, p, ctx);
    }

    // Serialise `p` into `out`, giving things up until it fits in `maxSize`.
    void emit(Program &p, std::size_t maxSize, Input_t &out)
    {
        prog::Serialize(p, out);
        while (out.size() > maxSize && p.calls.size() > 1)
        {
            p.calls.pop_back(); // nothing earlier depends on the last call
            prog::Serialize(p, out);
        }
        if (out.size() > maxSize)
        {
            // A single oversized call: keep its shape, drop the buffer contents.
            for (Call &c : p.calls)
                forEachValue(c, [](Value &v) { v.data.clear(); });
            prog::Serialize(p, out);
        }
        if (out.size() > maxSize)
        {
            p.calls.clear();
            prog::Serialize(p, out);
        }
        if (out.size() > maxSize)
            out.clear();
    }

    class SyscallMutator_t final : public Mutator_t
    {
    private:
        void loadArgPool()
        {
            std::shared_ptr<sysmon::ArgPool> pool{};
            const std::string growthPath = "pool_growth.csv";
            std::ofstream growth(growthPath, std::ios::binary | std::ios::trunc);
            if (!growth)
            {
                DebugPrint<0>("ArgPool", "[-] Cannot create {} \n", growthPath);
                return;
            }

            sysmon::PoolGrowthLog growthLog(growth);

            std::ifstream fileBuffer("/home/ism/Bureau/nyx/windows/fuzz/dump/argpool.bin", std::ios::in | std::ios::binary);
            if (!fileBuffer)
            {
                DebugPrint<0>("ArgPool", "Failed to open input argpool\n");
                return;
            }

            fileBuffer.seekg(0, std::ios::end);
            const std::streamoff size = fileBuffer.tellg();
            if (size < 0)
            {
                DebugPrint<0>("ArgPool", "Failed to determine input size\n");
                return;
            }
            fileBuffer.seekg(0, std::ios::beg);

            const size_t bytes = static_cast<size_t>(size);
            const size_t count = bytes / sizeof(SYSMON_RECORD);
            if (bytes % sizeof(SYSMON_RECORD) != 0)
            {
                DebugPrint<0>("ArgPool", "Trailing partial record ignored\n");
            }

            std::vector<SYSMON_RECORD> records(count);
            const std::streamsize toRead =
                static_cast<std::streamsize>(count * sizeof(SYSMON_RECORD));
            if (!fileBuffer.read(reinterpret_cast<char *>(records.data()), toRead))
            {
                DebugPrint<0>("ArgPool", "Failed to read input argpool\n");
                return;
            }

            for (size_t i = 0; i < count; ++i)
            {
                growthLog.Add(g_ArgPool, sysmon::Decode(records[i]));
            }

            growth.flush();
            if (!growth)
            {
                DebugPrint<0>("ArgPool", "Failed writing {}\n", growthPath);
                return;
            }

            DebugPrint<0>("ArgPool", "ArgPool loaded!!\n");
            setSyscallArgPool(&g_ArgPool);   
        }

    public:
        void mutate(Input_t &d, MutatorContext_t &ctx) override
        {
            std::shared_lock<std::shared_mutex> lock;
            if (std::shared_mutex *guard = g_poolGuard.load())
                lock = std::shared_lock(*guard);
            Program p;
            prog::Parse(d.data(), d.size(), p); // on damage, keeps the calls before it

            if(!g_pool.load())
                loadArgPool();

            if(!g_pool.load()){
                DebugPrint<1>("Mutator", "ArgPool is nullptr");
                return;
            }

            // A program runs on one guest thread. It gets that thread from the first
            // pooled argument it uses, and from then on prefers arguments the same
            // thread passed, so handles are used by the thread that owns them.
            const std::shared_ptr<const Weights_t> weights = currentWeights();
            Gen_t g{ctx.rng, g_pool.load(), std::nullopt, weights.get()};
            if (p.thread != 0)
                g.thread = p.thread;
            sanitize(g, p);

            if (p.calls.empty())
            {
                // Empty or foreign input: start a new program.
                for (std::size_t n = 1 + randBelow(g.rng, 8); n != 0; --n)
                    insertCallAt(p, p.calls.size(), genCall(g, p, p.calls.size(), pickSyscall(g, p, p.calls.size())));
            }
            else
            {
                unsigned edits = 1;
                while (edits < 4 && coinFlip(g.rng))
                    ++edits;
                for (unsigned tries = 0; edits != 0 && tries < 16; ++tries)
                {
                    if (mutateOnce(g, p, ctx))
                        --edits;
                }
            }
            p.thread = static_cast<uint32_t>(g.thread.value_or(0));
            emit(p, ctx.maxSize, d);
        }

        // A valid program with no calls, so the agent never sees an unparsable payload.
        Input_t emptyInput() override
        {
            Input_t out;
            prog::Serialize(Program{}, out);
            return out;
        }
    };

} // namespace

void setSyscallArgPool(const sysmon::ArgPool *pool, std::shared_mutex *guard)
{
    g_poolGuard.store(guard);
    g_pool.store(pool);
}

std::size_t setSyscallFocus(const std::vector<std::pair<std::string, double>> &prefixes)
{
    auto weights = std::make_shared<const Weights_t>(prefixes);
    const std::size_t usable = weights->usable;
    if (usable != 0) // a focus that excludes everything is ignored
    {
        std::lock_guard<std::mutex> lock(g_weightsLock);
        g_weights = std::move(weights);
    }
    return usable;
}

REGISTER_MUTATOR(SyscallMutator_t, "syscall", "win32k syscall programs with arguments from the sysmon pool");
