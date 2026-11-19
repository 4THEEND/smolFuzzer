// sysmon_decode.hpp - turns SYSMON_RECORDs from the driver into typed values.
// Portable C++17, no dependencies beyond the standard library.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "sysmon_wire.h"

namespace sysmon {

enum class Kind : std::uint8_t { Unknown, Scalar, Handle, Pointer, Buffer, Array, String };

enum class Capture : std::uint8_t {
    None,       // nothing was captured for this argument (scalar, NULL, output-only...)
    Ok,         // all pointed-to data is in `data`
    Truncated,  // only the first bytes are in `data`
    Fault,      // the pointer was unreadable when the syscall was made
};

// One field of a captured struct, as described by the syscall database.
struct Field {
    std::uint32_t    offset = 0;
    std::uint32_t    size = 0;
    std::string_view type;          // e.g. "ULONG", "BYTE[16]"
    std::string_view name;          // often empty: the database rarely knows it
    bool             isInteger = false;   // size is 1/2/4/8 -> `value` is valid
    std::uint64_t    value = 0;           // little-endian integer value
};

struct Arg {
    unsigned         index = 0;
    std::string_view type;          // C type from the database, "?" if unknown syscall
    Kind             kind = Kind::Unknown;
    unsigned         size = 8;      // significant bytes of `value`
    bool             in = false, out = false;
    std::uint64_t    value = 0;     // raw argument (the address, for pointers)
    bool             isAtom = false;  // string argument that holds a class atom instead

    Capture                   capture = Capture::None;
    std::vector<std::uint8_t> data;       // raw captured bytes
    bool                      isText = false;
    std::string               text;       // UTF-8, when isText
    std::vector<Field>        fields;     // when the pointee is a struct
};

struct Call {
    std::uint64_t    sequence = 0;
    std::int64_t     timestamp = 0;       // 100 ns since 1601-01-01 UTC (FILETIME)
    std::uint64_t    processId = 0, threadId = 0;
    std::uint32_t    ssn = 0;
    bool             known = false;       // ssn found in the database
    std::string_view name;                // "NtUser..." or empty
    std::string_view returnType;
    bool             kernelCaller = false;  // pointers were not followed
    bool             blobFull = false;      // some captures were skipped for lack of room
    bool             malformed = false;     // record failed validation; decoded as far as possible
    std::vector<Arg> args;
};

// Decode one record. Never throws on bad input and never reads outside *rec.
Call Decode(const SYSMON_RECORD& rec);

// Multi-line, human-readable rendering of a decoded call.
std::string Format(const Call& call);

// Name of a syscall number, or an empty view if it is not in the database.
std::string_view SyscallName(std::uint32_t ssn);

// "2026-11-17 09:12:03.1234567" (UTC) from a record timestamp.
std::string FormatTimestamp(std::int64_t timestamp);

}  // namespace sysmon
