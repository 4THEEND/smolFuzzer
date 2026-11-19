// syscall_program.hpp - a sequence of win32k syscalls as a fuzzer input.
//
// Shared by the host (the "syscall" mutator builds and edits programs) and the
// guest agent (which parses the payload and issues the calls). Header-only,
// C++17, standard library only, so it can be compiled into the agent as is.
//
// Wire format (little-endian, no padding):
//
//   Program : u32 magic "W3KP" | u8 version | u32 thread | u8 numCalls | Call[numCalls]
//   Call    : u16 ssn | u8 numArgs | Value[numArgs]
//   Value   : u8 tag, then
//               tag 0 IMM    : u64 value
//               tag 1 RESULT : u8 callIndex
//               tag 2 MEM    : u16 size | u8 flags | u8 bytes[size] (only if flags & 1)
//                              | u8 numRelocs | Reloc[numRelocs]
//   Reloc   : u16 offset | Value
//
// What the agent does with it:
//
//   thread  Id of the guest thread that must issue the calls, 0 = no
//           preference. Window handles and most USER state belong to a thread,
//           so arguments recorded from a thread are replayed on that thread.
//           syscall_exec.hpp implements all of this for a client inside a DLL.
//
//   IMM     Pass `value` (the kernel ignores the bits above the argument's width).
//   RESULT  Pass the value an earlier call of this program returned in RAX.
//           If callIndex is not an earlier call, pass 0.
//   MEM     Take `size` bytes of user memory, fill them with `bytes` (or zeros
//           when flags & 1 is clear), then for every Reloc store the 8-byte
//           value of its Value at `offset`. Pass the address of the memory.
//           A Reloc's Value is usually another MEM (a pointer inside a struct,
//           e.g. UNICODE_STRING.Buffer) but may be an IMM or a RESULT too.
//           Keep the memory alive until the program ends: the kernel can hold
//           on to user pointers across calls.
//
//   Arguments 0-3 go in R10/RDX/R8/R9, the rest on the stack from [RSP+0x28],
//   one 8-byte slot each; EAX = ssn.
//
// Parse() only accepts payloads that respect the limits below, so the agent
// can size its scratch memory from them.
#pragma once

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace win32k::prog {

constexpr std::uint32_t kMagic = 0x504B3357;   // "W3KP"
constexpr std::uint8_t  kVersion = 2;
constexpr std::size_t   kHeaderSize = 10;

constexpr std::size_t kMaxCalls = 32;     // calls per program
constexpr std::size_t kMaxArgs = 24;      // arguments per call
constexpr std::size_t kMaxMem = 4096;     // bytes per MEM value
constexpr std::size_t kMaxRelocs = 8;     // relocations per MEM value
constexpr std::size_t kMaxDepth = 3;      // MEM inside MEM inside MEM ...

struct Reloc;

struct Value {
    enum class Tag : std::uint8_t { Imm = 0, Result = 1, Mem = 2 };

    Tag           tag = Tag::Imm;
    std::uint64_t value = 0;            // Imm: the value. Result: index of the call.
    std::uint16_t size = 0;             // Mem: size in bytes
    std::vector<std::uint8_t> data;     // Mem: `size` bytes, or empty = zero-filled
    std::vector<Reloc>        relocs;   // Mem: pointers/values patched into it

    bool IsMem() const { return tag == Tag::Mem; }
};

struct Reloc {
    std::uint16_t offset = 0;           // offset + 8 <= size
    Value         target;
};

struct Call {
    std::uint16_t      ssn = 0;
    std::vector<Value> args;
};

struct Program {
    std::uint32_t     thread = 0;   // thread to run on, 0 = no preference
    std::vector<Call> calls;
};

inline Value Imm(std::uint64_t v) {
    Value x;
    x.value = v;
    return x;
}

inline Value Result(std::size_t callIndex) {
    Value x;
    x.tag = Value::Tag::Result;
    x.value = callIndex;
    return x;
}

// Memory initialised with `bytes` (cut at kMaxMem).
inline Value Mem(std::vector<std::uint8_t> bytes) {
    if (bytes.size() > kMaxMem) bytes.resize(kMaxMem);
    Value x;
    x.tag = Value::Tag::Mem;
    x.size = static_cast<std::uint16_t>(bytes.size());
    x.data = std::move(bytes);
    return x;
}

// Zero-filled memory; costs no payload bytes, so use it for output buffers.
inline Value ZeroMem(std::size_t size) {
    Value x;
    x.tag = Value::Tag::Mem;
    x.size = static_cast<std::uint16_t>(size < kMaxMem ? size : kMaxMem);
    return x;
}

namespace detail {

inline void Put(std::vector<std::uint8_t>& out, std::uint64_t v, std::size_t width) {
    for (std::size_t i = 0; i < width; ++i) out.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
}

inline void PutValue(std::vector<std::uint8_t>& out, const Value& v, std::size_t depth) {
    if (v.tag == Value::Tag::Imm || (v.tag == Value::Tag::Mem && depth > kMaxDepth)) {
        out.push_back(0);
        Put(out, v.tag == Value::Tag::Imm ? v.value : 0, 8);
        return;
    }
    if (v.tag == Value::Tag::Result) {
        out.push_back(1);
        out.push_back(static_cast<std::uint8_t>(v.value));
        return;
    }
    const std::size_t size = v.size < kMaxMem ? v.size : kMaxMem;
    const bool hasData = size != 0 && v.data.size() >= size;
    out.push_back(2);
    Put(out, size, 2);
    out.push_back(hasData ? 1 : 0);
    if (hasData) out.insert(out.end(), v.data.begin(), v.data.begin() + static_cast<std::ptrdiff_t>(size));

    const std::size_t countAt = out.size();
    out.push_back(0);
    std::size_t count = 0;
    for (const Reloc& r : v.relocs) {
        if (count == kMaxRelocs) break;
        if (static_cast<std::size_t>(r.offset) + 8 > size) continue;   // would not fit: drop it
        Put(out, r.offset, 2);
        PutValue(out, r.target, depth + 1);
        ++count;
    }
    out[countAt] = static_cast<std::uint8_t>(count);
}

struct Reader {
    const std::uint8_t* p;
    std::size_t         left;

    bool Get(std::uint64_t& v, std::size_t width) {
        if (left < width) return false;
        v = 0;
        for (std::size_t i = 0; i < width; ++i) v |= static_cast<std::uint64_t>(p[i]) << (8 * i);
        p += width;
        left -= width;
        return true;
    }
};

inline bool GetValue(Reader& in, Value& v, std::size_t depth) {
    std::uint64_t tag = 0, x = 0;
    if (!in.Get(tag, 1)) return false;
    switch (tag) {
    case 0:
        v.tag = Value::Tag::Imm;
        return in.Get(v.value, 8);
    case 1:
        v.tag = Value::Tag::Result;
        return in.Get(v.value, 1);
    case 2: {
        if (depth > kMaxDepth) return false;
        std::uint64_t size = 0, flags = 0, numRelocs = 0;
        if (!in.Get(size, 2) || size > kMaxMem || !in.Get(flags, 1) || flags > 1) return false;
        v.tag = Value::Tag::Mem;
        v.size = static_cast<std::uint16_t>(size);
        if (flags & 1) {
            if (in.left < size) return false;
            v.data.assign(in.p, in.p + size);
            in.p += size;
            in.left -= size;
        }
        if (!in.Get(numRelocs, 1) || numRelocs > kMaxRelocs) return false;
        v.relocs.resize(numRelocs);
        for (Reloc& r : v.relocs) {
            if (!in.Get(x, 2) || x + 8 > size) return false;
            r.offset = static_cast<std::uint16_t>(x);
            if (!GetValue(in, r.target, depth + 1)) return false;
        }
        return true;
    }
    default:
        return false;
    }
}

}  // namespace detail

// Encode `program`. The output always parses: calls and arguments beyond the
// limits are left out, as are relocations that do not fit their memory.
inline void Serialize(const Program& program, std::vector<std::uint8_t>& out) {
    out.clear();
    const std::size_t numCalls = program.calls.size() < kMaxCalls ? program.calls.size() : kMaxCalls;
    detail::Put(out, kMagic, 4);
    out.push_back(kVersion);
    detail::Put(out, program.thread, 4);
    out.push_back(static_cast<std::uint8_t>(numCalls));
    for (std::size_t c = 0; c < numCalls; ++c) {
        const Call& call = program.calls[c];
        const std::size_t numArgs = call.args.size() < kMaxArgs ? call.args.size() : kMaxArgs;
        detail::Put(out, call.ssn, 2);
        out.push_back(static_cast<std::uint8_t>(numArgs));
        for (std::size_t a = 0; a < numArgs; ++a) detail::PutValue(out, call.args[a], 0);
    }
}

// Decode a payload. Returns false if it is not a well-formed program; `out`
// then holds the calls that precede the damage (possibly none), which are
// safe to use.
inline bool Parse(const std::uint8_t* bytes, std::size_t size, Program& out) {
    out.thread = 0;
    out.calls.clear();
    detail::Reader in{bytes, size};
    std::uint64_t magic = 0, version = 0, thread = 0, numCalls = 0;
    if (!in.Get(magic, 4) || magic != kMagic || !in.Get(version, 1) || version != kVersion) return false;
    if (!in.Get(thread, 4)) return false;
    out.thread = static_cast<std::uint32_t>(thread);
    if (!in.Get(numCalls, 1) || numCalls > kMaxCalls) return false;
    for (std::uint64_t c = 0; c < numCalls; ++c) {
        Call call;
        std::uint64_t ssn = 0, numArgs = 0;
        if (!in.Get(ssn, 2) || !in.Get(numArgs, 1) || numArgs > kMaxArgs) return false;
        call.ssn = static_cast<std::uint16_t>(ssn);
        call.args.resize(numArgs);
        for (Value& v : call.args) {
            if (!detail::GetValue(in, v, 0)) return false;
        }
        out.calls.push_back(std::move(call));
    }
    return in.left == 0;
}

}  // namespace win32k::prog
