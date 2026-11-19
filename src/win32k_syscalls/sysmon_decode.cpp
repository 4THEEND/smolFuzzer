// sysmon_decode.cpp - see sysmon_decode.hpp.
#include "sysmon_decode.hpp"

#include <algorithm>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <iterator>

namespace sysmon {
namespace {

// Must match the flag values in syscall_monitor.h / gen_table.py.
enum : std::uint8_t {
    kIn = 0x01, kOut = 0x02, kStruct = 0x04, kUstr = 0x08,
    kStrz = 0x10, kCounted = 0x20, kText = 0x40, kLstr = 0x80,
};

struct FieldInfo   { std::uint16_t offset, size; const char* type; const char* name; };
struct ArgInfo     { const char* type; std::uint8_t kind, size, flags, elemSize;
                     std::uint16_t firstField, numFields; };
struct SyscallInfo { std::uint32_t ssn; const char* name; const char* returnType;
                     std::uint16_t firstArg; std::uint8_t numArgs; };

#include "win32k_decode_table.inc"

const SyscallInfo* Lookup(std::uint32_t ssn) {
    auto it = std::lower_bound(std::begin(kSyscalls), std::end(kSyscalls), ssn,
                               [](const SyscallInfo& s, std::uint32_t v) { return s.ssn < v; });
    return (it != std::end(kSyscalls) && it->ssn == ssn) ? &*it : nullptr;
}

std::uint64_t ReadLe(const std::uint8_t* p, unsigned size) {
    std::uint64_t v = 0;
    for (unsigned i = 0; i < size; ++i) v |= std::uint64_t{p[i]} << (8 * i);
    return v;
}

void AppendUtf8(std::string& out, std::uint32_t cp) {
    if (cp < 0x80) {
        out += static_cast<char>(cp);
    } else if (cp < 0x800) {
        out += static_cast<char>(0xC0 | (cp >> 6));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
        out += static_cast<char>(0xE0 | (cp >> 12));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    } else {
        out += static_cast<char>(0xF0 | (cp >> 18));
        out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    }
}

// UTF-16LE bytes -> UTF-8. Unpaired surrogates become U+FFFD; an odd trailing
// byte is dropped. The input is attacker-controlled, so nothing is assumed.
std::string Utf16ToUtf8(const std::vector<std::uint8_t>& bytes) {
    std::string out;
    const std::size_t n = bytes.size() / 2;
    for (std::size_t i = 0; i < n; ++i) {
        std::uint32_t cp = static_cast<std::uint32_t>(ReadLe(&bytes[2 * i], 2));
        if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < n) {
            const std::uint32_t lo = static_cast<std::uint32_t>(ReadLe(&bytes[2 * (i + 1)], 2));
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                ++i;
            } else {
                cp = 0xFFFD;
            }
        } else if (cp >= 0xD800 && cp <= 0xDFFF) {
            cp = 0xFFFD;
        }
        AppendUtf8(out, cp);
    }
    return out;
}

// The code page of an ANSI string is not known here: keep ASCII, and map the
// rest as Latin-1 so no byte is lost.
std::string AnsiToUtf8(const std::vector<std::uint8_t>& bytes) {
    std::string out;
    for (std::uint8_t b : bytes) AppendUtf8(out, b);
    return out;
}

template <typename... T>
void Appendf(std::string& out, const char* fmt, T... args) {
    char buf[160];
    const int n = std::snprintf(buf, sizeof buf, fmt, args...);
    if (n > 0) out.append(buf, std::min<std::size_t>(static_cast<std::size_t>(n), sizeof buf - 1));
}

void AppendHex(std::string& out, const std::uint8_t* p, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) Appendf(out, i ? " %02x" : "%02x", p[i]);
}

// Printable rendering of text that came from another process.
void AppendQuoted(std::string& out, const std::string& text) {
    out += '"';
    for (unsigned char c : text) {
        if (c == '"' || c == '\\') { out += '\\'; out += static_cast<char>(c); }
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else if (c < 0x20 || c == 0x7F) Appendf(out, "\\x%02x", static_cast<unsigned>(c));
        else out += static_cast<char>(c);
    }
    out += '"';
}

bool IsSignedType(std::string_view t) {
    return t == "INT" || t == "LONG" || t == "LPARAM" || t == "LRESULT";
}

void AppendValue(std::string& out, std::string_view type, Kind kind, unsigned size, std::uint64_t v) {
    if (kind == Kind::Scalar || kind == Kind::Unknown) {
        if (type == "BOOL") {
            Appendf(out, v == 0 ? "FALSE" : v == 1 ? "TRUE" : "0x%" PRIx64, v);
        } else if (IsSignedType(type)) {
            const std::int64_t s = (size >= 8) ? static_cast<std::int64_t>(v)
                : static_cast<std::int64_t>(v << (64 - 8 * size)) >> (64 - 8 * size);
            Appendf(out, "%" PRId64 " (0x%" PRIx64 ")", s, v);
        } else {
            Appendf(out, "0x%" PRIx64 " (%" PRIu64 ")", v, v);
        }
    } else if (v == 0) {
        out += "NULL";
    } else {
        Appendf(out, "0x%" PRIx64, v);
    }
}

void DecodeCapture(Arg& arg, const ArgInfo* info, bool ansi) {
    if (arg.capture == Capture::None || arg.capture == Capture::Fault || info == nullptr) return;

    if (info->flags & kText) {
        arg.isText = true;
        arg.text = (info->elemSize == 2 && !ansi) ? Utf16ToUtf8(arg.data) : AnsiToUtf8(arg.data);
    } else if (info->flags & kStruct) {
        for (unsigned i = 0; i < info->numFields; ++i) {
            const FieldInfo& fi = kFields[info->firstField + i];
            if (std::size_t{fi.offset} + fi.size > arg.data.size()) continue;   // not captured
            Field f;
            f.offset = fi.offset;
            f.size = fi.size;
            f.type = fi.type;
            f.name = fi.name;
            f.isInteger = fi.size == 1 || fi.size == 2 || fi.size == 4 || fi.size == 8;
            if (f.isInteger) f.value = ReadLe(&arg.data[fi.offset], fi.size);
            arg.fields.push_back(f);
        }
    }
}

}  // namespace

std::string_view SyscallName(std::uint32_t ssn) {
    const SyscallInfo* s = Lookup(ssn);
    return s ? std::string_view{s->name} : std::string_view{};
}

Call Decode(const SYSMON_RECORD& rec) {
    Call call;
    call.sequence = rec.Sequence;
    call.timestamp = rec.Timestamp;
    call.processId = rec.ProcessId;
    call.threadId = rec.ThreadId;
    call.ssn = rec.Ssn;
    call.kernelCaller = (rec.Flags & SYSMON_REC_KERNEL_CALLER) != 0;
    call.blobFull = (rec.Flags & SYSMON_REC_BLOB_FULL) != 0;

    const SyscallInfo* sc = Lookup(rec.Ssn);
    if (sc != nullptr) {
        call.known = true;
        call.name = sc->name;
        call.returnType = sc->returnType;
    }

    unsigned numArgs = rec.NumArgs;
    if (numArgs > SYSMON_MAX_ARGS) { numArgs = SYSMON_MAX_ARGS; call.malformed = true; }
    // A count that disagrees with the database means driver and decoder were
    // built from different tables: show raw values rather than mislabel them.
    if (sc != nullptr && sc->numArgs != numArgs) { sc = nullptr; call.malformed = true; }

    call.args.resize(numArgs);
    for (unsigned i = 0; i < numArgs; ++i) {
        Arg& a = call.args[i];
        a.index = i;
        a.value = rec.Args[i];
        a.type = "?";
        if (sc != nullptr) {
            const ArgInfo& ai = kArgs[sc->firstArg + i];
            a.type = ai.type;
            a.kind = static_cast<Kind>(ai.kind);
            a.size = ai.size;
            a.in = (ai.flags & kIn) != 0;
            a.out = (ai.flags & kOut) != 0;
            // win32k passes a class atom in place of the string pointer.
            a.isAtom = (ai.flags & kLstr) != 0 && a.value != 0 && a.value < 0x10000;
        }
    }

    // Walk the capture blob, trusting none of its lengths.
    std::size_t used = rec.BlobUsed;
    if (used > SYSMON_BLOB_BYTES) { used = SYSMON_BLOB_BYTES; call.malformed = true; }
    for (std::size_t off = 0; off < used;) {
        SYSMON_CAPTURE cap;
        if (used - off < sizeof cap) { call.malformed = true; break; }
        std::memcpy(&cap, rec.Blob + off, sizeof cap);
        off += sizeof cap;
        const unsigned status = cap.Status & SYSMON_CAP_STATUS_MASK;
        if (cap.Length > used - off || cap.ArgIndex >= numArgs || status > SYSMON_CAP_FAULT) {
            call.malformed = true;
            break;
        }
        Arg& a = call.args[cap.ArgIndex];
        a.capture = status == SYSMON_CAP_OK ? Capture::Ok
                  : status == SYSMON_CAP_TRUNCATED ? Capture::Truncated : Capture::Fault;
        a.data.assign(rec.Blob + off, rec.Blob + off + cap.Length);
        DecodeCapture(a, sc ? &kArgs[sc->firstArg + cap.ArgIndex] : nullptr,
                      (cap.Status & SYSMON_CAP_ANSI) != 0);
        off += (std::size_t{cap.Length} + 3) & ~std::size_t{3};
    }
    return call;
}

std::string FormatTimestamp(std::int64_t timestamp) {
    if (timestamp < 0) return "invalid";
    const std::int64_t kTicksPerDay = 864000000000LL;
    std::int64_t days = timestamp / kTicksPerDay;        // since 1601-01-01
    std::int64_t ticks = timestamp % kTicksPerDay;

    // Civil-from-days (proleptic Gregorian), shifted so day 0 is 0000-03-01.
    days += 584694;                                       // days from 0000-03-01 to 1601-01-01
    const std::int64_t era = days / 146097;
    const std::int64_t doe = days % 146097;
    const std::int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const std::int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const std::int64_t mp = (5 * doy + 2) / 153;
    const std::int64_t day = doy - (153 * mp + 2) / 5 + 1;
    const std::int64_t month = mp < 10 ? mp + 3 : mp - 9;
    const std::int64_t year = yoe + era * 400 + (month <= 2 ? 1 : 0);

    std::string out;
    Appendf(out, "%04lld-%02lld-%02lld %02lld:%02lld:%02lld.%07lld",
            static_cast<long long>(year), static_cast<long long>(month), static_cast<long long>(day),
            static_cast<long long>(ticks / 36000000000LL),
            static_cast<long long>(ticks / 600000000LL % 60),
            static_cast<long long>(ticks / 10000000LL % 60),
            static_cast<long long>(ticks % 10000000LL));
    return out;
}

std::string Format(const Call& call) {
    std::string out;
    Appendf(out, "#%" PRIu64 " %s pid=%" PRIu64 " tid=%" PRIu64 " ",
            call.sequence, FormatTimestamp(call.timestamp).c_str(), call.processId, call.threadId);
    if (call.known) {
        out.append(call.name);
        Appendf(out, " (0x%X) -> ", call.ssn);
        out.append(call.returnType);
    } else {
        Appendf(out, "<unknown syscall 0x%X>", call.ssn);
    }
    if (call.kernelCaller) out += " [kernel caller]";
    if (call.blobFull) out += " [captures incomplete]";
    if (call.malformed) out += " [malformed record]";
    out += '\n';

    for (const Arg& a : call.args) {
        Appendf(out, "  a%-2u ", a.index);
        out.append(a.type);
        out += " = ";
        if (a.isAtom) Appendf(out, "atom 0x%" PRIx64, a.value);
        else AppendValue(out, a.type, a.kind, a.size, a.value);

        if (a.capture == Capture::Fault) {
            out += " -> <unreadable>";
        } else if (a.capture != Capture::None) {
            out += " -> ";
            if (a.isText) {
                AppendQuoted(out, a.text);
            } else if (a.fields.empty()) {
                Appendf(out, "%zu bytes: ", a.data.size());
                AppendHex(out, a.data.data(), a.data.size());
            } else {
                Appendf(out, "%zu bytes", a.data.size());
            }
            if (a.capture == Capture::Truncated) out += " (truncated)";
            for (const Field& f : a.fields) {
                Appendf(out, "\n        +0x%02x ", f.offset);
                out.append(f.type);
                if (!f.name.empty()) { out += ' '; out.append(f.name); }
                out += " = ";
                if (f.isInteger) Appendf(out, "0x%" PRIx64, f.value);
                else AppendHex(out, &a.data[f.offset], f.size);
            }
        }
        out += '\n';
    }
    return out;
}

}  // namespace sysmon
