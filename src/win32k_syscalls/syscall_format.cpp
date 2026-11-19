// The "W3KP" input format for the reproducer and the minimizer: lists a
// win32k syscall program in readable form and reduces one structurally
// (whole calls, then arguments, then the memory they point to).
#include <algorithm>
#include <cstring>

#include "../format.hpp"
#include "syscall_program.hpp"
#include "win32k_syscall_table.hpp"

namespace
{

    using namespace win32k;
    using prog::Call;
    using prog::Program;
    using prog::Reloc;
    using prog::Value;

    const SyscallDesc *findSyscall(uint16_t ssn)
    {
        const SyscallDesc *end = kSyscalls + kNumSyscalls;
        const SyscallDesc *it = std::lower_bound(kSyscalls, end, ssn,
                                                 [](const SyscallDesc &s, uint16_t v)
                                                 { return s.ssn < v; });
        return it != end && it->ssn == ssn ? it : nullptr;
    }

    // ---------------------------------------------------------------- listing

    void describeValue(std::string &out, const Value &v, std::size_t indent)
    {
        switch (v.tag)
        {
        case Value::Tag::Imm:
            out += fmt::format("{:#x}\n", v.value);
            return;
        case Value::Tag::Result:
            out += fmt::format("result of #{}\n", v.value);
            return;
        case Value::Tag::Mem:
            if (v.data.empty())
                out += fmt::format("mem[{}] zero-filled\n", v.size);
            else
                out += fmt::format("mem[{}] {}\n", v.size, hexPreview(v.data));
            for (const Reloc &r : v.relocs)
            {
                out += fmt::format("{:{}}+{:#x} -> ", "", indent + 2, r.offset);
                describeValue(out, r.target, indent + 2);
            }
            return;
        }
    }

    std::string describeProgram(const Program &p, bool wellFormed, std::size_t bytes)
    {
        std::string out = fmt::format("win32k syscall program, {} bytes, {} call(s), thread {}{}\n",
                                      bytes, p.calls.size(), p.thread, p.thread == 0 ? " (no preference)" : "");
        if (!wellFormed)
            out += "  (payload is damaged: these are the calls before the damage)\n";
        for (std::size_t c = 0; c < p.calls.size(); ++c)
        {
            const Call &call = p.calls[c];
            const SyscallDesc *sc = findSyscall(call.ssn);
            out += fmt::format("  #{} {} (ssn {:#x}){}{}\n", c, sc ? sc->name : std::string_view("<unknown>"), call.ssn,
                               sc ? " -> " : "", sc ? sc->retType : std::string_view());
            for (std::size_t a = 0; a < call.args.size(); ++a)
            {
                const std::string_view type = sc && a < sc->numArgs ? kArgs[sc->firstArg + a].type : std::string_view("?");
                out += fmt::format("       a{} {} = ", a, type);
                describeValue(out, call.args[a], 7);
            }
        }
        return out;
    }

    // -------------------------------------------------------------- reduction

    // Same bookkeeping as the mutator: later calls keep pointing at the same results.
    template <typename F>
    void forEachValue(Value &v, F &&f)
    {
        f(v);
        for (Reloc &r : v.relocs)
            forEachValue(r.target, f);
    }

    void removeCallAt(Program &p, std::size_t k)
    {
        p.calls.erase(p.calls.begin() + static_cast<std::ptrdiff_t>(k));
        for (std::size_t c = k; c < p.calls.size(); ++c)
            for (Value &arg : p.calls[c].args)
                forEachValue(arg, [&](Value &v)
                             {
                    if (v.tag != Value::Tag::Result)
                        return;
                    if (v.value == k)
                        v = prog::Imm(0); // its result is gone
                    else if (v.value > k)
                        --v.value; });
    }

    // Where a value sits in a program: call, argument, then one relocation index per level of nesting.
    struct Path_t
    {
        std::size_t call, arg;
        std::vector<std::size_t> relocs;
    };

    Value &at(Program &p, const Path_t &path)
    {
        Value *v = &p.calls[path.call].args[path.arg];
        for (const std::size_t k : path.relocs)
            v = &v->relocs[k].target;
        return *v;
    }

    class Reducer_t
    {
    public:
        Reducer_t(Program start, const MinimizeTest_t &test) : Best_(std::move(start)), Test_(test) {}

        Program run()
        {
            // Every step can enable an earlier one (an argument that no longer
            // uses a result frees the call that produced it), so go round
            // until nothing changes. Unchanged candidates are answered from
            // the caller's cache, so the last, idle round is cheap.
            bool changed = true;
            while (changed)
            {
                changed = removeCalls();
                changed |= dropThread();
                for (std::size_t c = 0; c < Best_.calls.size(); ++c)
                    for (std::size_t a = 0; a < Best_.calls[c].args.size(); ++a)
                        changed |= simplify(Path_t{c, a, {}});
            }
            return std::move(Best_);
        }

    private:
        bool accept(const Program &cand)
        {
            prog::Serialize(cand, Buf_);
            if (!Test_(Buf_))
                return false;
            Best_ = cand;
            return true;
        }

        // Apply `edit` to the value at `path` in a copy of the best program; keep the copy if the bug survives.
        template <typename F>
        bool tryEdit(const Path_t &path, F &&edit)
        {
            Program cand = Best_;
            edit(at(cand, path));
            return accept(cand);
        }

        // Back to front: calls after the faulting one never ran and go first,
        // and a consumer is tried before the call that produces its handle.
        bool removeCalls()
        {
            bool changed = false;
            for (std::size_t i = Best_.calls.size(); i-- > 0;)
            {
                Program cand = Best_;
                removeCallAt(cand, i);
                changed |= accept(cand);
            }
            return changed;
        }

        bool dropThread()
        {
            if (Best_.thread == 0)
                return false;
            Program cand = Best_;
            cand.thread = 0;
            return accept(cand);
        }

        bool simplify(const Path_t &path)
        {
            const Value::Tag tag = at(Best_, path).tag;
            if (tag == Value::Tag::Imm)
                return at(Best_, path).value != 0 && tryEdit(path, [](Value &v) { v.value = 0; });
            if (tag == Value::Tag::Result)
                return tryEdit(path, [](Value &v) { v = prog::Imm(0); });

            // Memory. Best case, the bug does not need the pointer at all.
            if (tryEdit(path, [](Value &v) { v = prog::Imm(0); }))
                return true;

            bool changed = false;

            // Pointers stored inside: remove them (the bytes underneath show
            // through), then simplify what the remaining ones lead to.
            for (std::size_t k = at(Best_, path).relocs.size(); k-- > 0;)
                changed |= tryEdit(path, [k](Value &v) { v.relocs.erase(v.relocs.begin() + static_cast<std::ptrdiff_t>(k)); });
            for (std::size_t k = 0; k < at(Best_, path).relocs.size(); ++k)
            {
                Path_t inner = path;
                inner.relocs.push_back(k);
                changed |= simplify(inner);
            }

            // Cut the tail off, in halves, without losing a pointer that just proved necessary.
            std::size_t floor = 0;
            for (const Reloc &r : at(Best_, path).relocs)
                floor = std::max<std::size_t>(floor, r.offset + 8);
            for (std::size_t cut = (at(Best_, path).size - floor + 1) / 2; cut != 0;)
            {
                const std::size_t size = at(Best_, path).size;
                if (size - floor < cut)
                {
                    cut = size - floor;
                    continue;
                }
                const bool ok = tryEdit(path, [&](Value &v)
                                        {
                    v.size = static_cast<uint16_t>(size - cut);
                    if (!v.data.empty())
                        v.data.resize(v.size); });
                if (ok)
                    changed = true;
                else
                    cut /= 2;
            }

            // Contents: all zeros if possible, otherwise zero everything the bug does not look at.
            if (!at(Best_, path).data.empty())
            {
                if (tryEdit(path, [](Value &v) { v.data.clear(); }))
                    return true;
                std::vector<uint8_t> data = at(Best_, path).data;
                const std::vector<uint8_t> before = data;
                zeroUnneeded(data, 0, data.size(), [&](const std::vector<uint8_t> &cand)
                             { return tryEdit(path, [&](Value &v) { v.data = cand; }); });
                changed |= data != before;
            }
            return changed;
        }

        Program Best_;
        const MinimizeTest_t &Test_;
        Input_t Buf_;
    };

    class SyscallFormat_t final : public InputFormat_t
    {
    public:
        bool matches(std::span<const uint8_t> data) const override
        {
            static constexpr uint8_t kMagicBytes[] = {'W', '3', 'K', 'P'};
            return data.size() >= sizeof kMagicBytes && std::memcmp(data.data(), kMagicBytes, sizeof kMagicBytes) == 0;
        }

        std::string describe(std::span<const uint8_t> data) const override
        {
            Program p;
            const bool ok = prog::Parse(data.data(), data.size(), p);
            return describeProgram(p, ok, data.size());
        }

        Input_t minimize(Input_t data, const MinimizeTest_t &test) const override
        {
            // Work on the parsed program. Parsing and re-encoding normalises the
            // payload (and, if it is damaged, keeps only the calls before the
            // damage); if that alone loses the bug, the bug lives in the raw
            // bytes and only byte-level reduction can keep it.
            Program p;
            prog::Parse(data.data(), data.size(), p);
            Input_t clean;
            prog::Serialize(p, clean);
            if (clean != data && !test(clean))
                return minimizeBytes(std::move(data), test);

            p = Reducer_t(std::move(p), test).run();
            prog::Serialize(p, clean);
            return clean;
        }
    };

} // namespace

REGISTER_FORMAT(SyscallFormat_t);
