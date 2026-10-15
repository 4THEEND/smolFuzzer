/*
 * w32k_decode.cpp  --  HOST ONLY
 *
 * Implementation of w32k_decode.hpp.
 * Compile as C++17: g++ -std=c++17 -O2 -I. w32k_decode.cpp
 */

#include "w32k_decode.hpp"

/* Pull in the C wire-format structs and the two name tables.
 * These are C headers with extern "C" / #pragma pack; safe to include here. */
#include "w32k_wire_host.h"
#include "w32k_names_host.h"
#include "nt_names_host.h"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace W32k
{

    /* -------------------------------------------------------------------- */
    /* Internal: safe buffer cursor                                          */
    /* -------------------------------------------------------------------- */

    class Cursor
    {
    public:
        Cursor(const uint8_t *base, uint32_t size) noexcept
            : base_(base), size_(size) {}

        bool ok() const noexcept { return ok_; }
        uint32_t pos() const noexcept { return pos_; }
        uint32_t remaining() const noexcept { return ok_ ? size_ - pos_ : 0u; }

        /* Read a trivially-copyable T from the current position. */
        template <typename T>
        bool read(T &out) noexcept
        {
            static_assert(std::is_trivially_copyable_v<T>);
            if (!ok_ || size_ - pos_ < sizeof(T))
            {
                ok_ = false;
                return false;
            }
            std::memcpy(&out, base_ + pos_, sizeof(T));
            pos_ += static_cast<uint32_t>(sizeof(T));
            return true;
        }

        /* Return a pointer into the base buffer at offset without advancing. */
        const uint8_t *at(uint32_t offset, uint32_t len) const noexcept
        {
            if (offset > size_ || size_ - offset < len)
                return nullptr;
            return base_ + offset;
        }

        /* Copy bytes [offset, offset+len) into a vector. */
        std::vector<uint8_t> copy(uint32_t offset, uint32_t len) const
        {
            const uint8_t *p = at(offset, len);
            if (!p || len == 0)
                return {};
            return {p, p + len};
        }

    private:
        const uint8_t *base_;
        uint32_t size_;
        uint32_t pos_ = 0;
        bool ok_ = true;
    };

    /* -------------------------------------------------------------------- */
    /* Internal: string helpers                                              */
    /* -------------------------------------------------------------------- */

    static std::string hex_dump(const std::vector<uint8_t> &data, std::size_t max_bytes)
    {
        std::ostringstream ss;
        std::size_t n = std::min(data.size(), max_bytes);
        ss << std::hex << std::uppercase << std::setfill('0');
        for (std::size_t i = 0; i < n; ++i)
            ss << std::setw(2) << static_cast<unsigned>(data[i]);
        if (n < data.size())
            ss << "...";
        return ss.str();
    }

    /* Decode UTF-16LE bytes to a printable std::string.
     * ASCII printable chars are kept as-is; others become \uXXXX. */
    static std::string decode_utf16le(const uint8_t *p, std::size_t byte_len)
    {
        std::string result;
        result.reserve(byte_len / 2);
        for (std::size_t i = 0; i + 1 < byte_len; i += 2)
        {
            uint16_t cp = static_cast<uint16_t>(p[i]) |
                          (static_cast<uint16_t>(p[i + 1]) << 8);
            if (cp == 0)
                break;
            if (cp >= 0x20 && cp < 0x7f && cp != '"' && cp != '\\')
            {
                result += static_cast<char>(cp);
            }
            else
            {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04X", cp);
                result += buf;
            }
        }
        return result;
    }

    static std::string decode_ansi(const uint8_t *p, std::size_t len)
    {
        std::string result;
        result.reserve(len);
        for (std::size_t i = 0; i < len; ++i)
        {
            uint8_t c = p[i];
            if (c == 0)
                break;
            if (c >= 0x20 && c < 0x7f && c != '"' && c != '\\')
            {
                result += static_cast<char>(c);
            }
            else
            {
                char buf[6];
                std::snprintf(buf, sizeof(buf), "\\x%02X", c);
                result += buf;
            }
        }
        return result;
    }

    /* -------------------------------------------------------------------- */
    /* ArgInfo member implementations                                        */
    /* -------------------------------------------------------------------- */

    std::string ArgInfo::as_ansi() const
    {
        if (data.empty())
            return {};
        return decode_ansi(data.data(), data.size());
    }

    std::string ArgInfo::as_wide() const
    {
        if (data.empty())
            return {};
        if (capture_type == CaptureType::UnicodeString)
        {
            return unicode_chars();
        }
        return decode_utf16le(data.data(), data.size());
    }

    std::optional<UnicodeStringBlob> ArgInfo::unicode_header() const noexcept
    {
        if (data.size() < sizeof(UnicodeStringBlob))
            return std::nullopt;
        UnicodeStringBlob hdr;
        std::memcpy(&hdr, data.data(), sizeof(hdr));
        return hdr;
    }

    std::string ArgInfo::unicode_chars() const
    {
        if (data.size() <= sizeof(UnicodeStringBlob))
            return {};
        const uint8_t *chars = data.data() + sizeof(UnicodeStringBlob);
        std::size_t bytes = data.size() - sizeof(UnicodeStringBlob);
        return decode_utf16le(chars, bytes);
    }

    std::string ArgInfo::hex(std::size_t max_bytes) const
    {
        return hex_dump(data, max_bytes);
    }

    /* -------------------------------------------------------------------- */
    /* NestedInfo member implementations                                     */
    /* -------------------------------------------------------------------- */

    std::string NestedInfo::hex(std::size_t max_bytes) const
    {
        return hex_dump(data, max_bytes);
    }

    /* -------------------------------------------------------------------- */
    /* Name lookup                                                           */
    /* -------------------------------------------------------------------- */

    std::string SyscallName(uint16_t ssn)
    {
        /* The C name-table functions use a static buffer for unknown SSNs.
         * Copy into a std::string immediately so the result is owned. */
        return ssn < 0x1000u ? NtNameFromSsn(ssn) : W32kNameFromSsn(ssn);
    }

    /* -------------------------------------------------------------------- */
    /* Core decoder                                                          */
    /* -------------------------------------------------------------------- */

    static ArgInfo decode_arg(const W32K_EVENT_ARG &a,
                              const uint8_t *ev_base, uint32_t ev_size)
    {
        ArgInfo info;
        info.value = a.Value;
        info.kind = static_cast<ArgKind>(a.Kind);
        info.size = a.Size;
        info.direction = static_cast<Dir>(a.Direction);
        info.capture_type = static_cast<CaptureType>(a.CaptureType);
        info.capture_flags = {a.CaptureFlags};
        info.status = a.Status;
        info.requested_length = a.RequestedLength;

        if (a.DataLength > 0 &&
            static_cast<uint64_t>(a.DataOffset) + a.DataLength <= ev_size)
        {
            info.data.assign(ev_base + a.DataOffset,
                             ev_base + a.DataOffset + a.DataLength);
        }
        return info;
    }

    static NestedInfo decode_nested(const W32K_EVENT_NESTED &n,
                                    const uint8_t *ev_base, uint32_t ev_size)
    {
        NestedInfo info;
        info.arg_index = n.ArgIndex;
        info.direction = static_cast<Dir>(n.Direction);
        info.parent_offset = n.ParentOffset;
        info.pointer_value = n.PointerValue;
        info.capture_flags = {n.CaptureFlags};
        info.status = n.Status;
        info.requested_length = n.RequestedLength;

        if (n.DataLength > 0 &&
            static_cast<uint64_t>(n.DataOffset) + n.DataLength <= ev_size)
        {
            info.data.assign(ev_base + n.DataOffset,
                             ev_base + n.DataOffset + n.DataLength);
        }
        return info;
    }

    static std::optional<EventInfo>
    decode_event(const uint8_t *p, uint32_t remaining, std::string &err)
    {
        if (remaining < sizeof(W32K_EVENT_HEADER))
        {
            err = "truncated event header";
            return std::nullopt;
        }

        W32K_EVENT_HEADER h;
        std::memcpy(&h, p, sizeof(h));

        if (h.Magic != W32K_EVENT_MAGIC ||
            h.Version != W32K_EVENT_VERSION ||
            h.HeaderSize != sizeof(W32K_EVENT_HEADER))
        {
            err = "bad event magic/version/headersize";
            return std::nullopt;
        }
        if (h.TotalSize < sizeof(h) || h.TotalSize > remaining || (h.TotalSize & 7))
        {
            err = "bad event TotalSize";
            return std::nullopt;
        }

        const uint64_t args_end =
            static_cast<uint64_t>(h.ArgsOffset) + static_cast<uint64_t>(h.ArgCount) * sizeof(W32K_EVENT_ARG);
        const uint64_t nest_end =
            static_cast<uint64_t>(h.NestedOffset) + static_cast<uint64_t>(h.NestedCount) * sizeof(W32K_EVENT_NESTED);
        if (args_end > h.TotalSize || nest_end > h.TotalSize)
        {
            err = "event arg/nested table overflows TotalSize";
            return std::nullopt;
        }

        EventInfo ev;
        ev.sequence = h.Sequence;
        ev.timestamp = h.Timestamp;
        ev.process_id = h.ProcessId;
        ev.thread_id = h.ThreadId;
        ev.return_value = h.ReturnValue;
        ev.ssn = h.Ssn;
        ev.phase = static_cast<Phase>(h.Phase);
        ev.flags = h.Flags;
        ev.name = SyscallName(h.Ssn);

        ev.args.reserve(h.ArgCount);
        for (uint8_t i = 0; i < h.ArgCount; ++i)
        {
            W32K_EVENT_ARG a;
            std::memcpy(&a, p + h.ArgsOffset + i * sizeof(a), sizeof(a));
            ev.args.push_back(decode_arg(a, p, h.TotalSize));
        }

        ev.nested.reserve(h.NestedCount);
        for (uint16_t i = 0; i < h.NestedCount; ++i)
        {
            W32K_EVENT_NESTED n;
            std::memcpy(&n, p + h.NestedOffset + i * sizeof(n), sizeof(n));
            ev.nested.push_back(decode_nested(n, p, h.TotalSize));
        }

        return ev;
    }

    BatchResult DecodeBatch(const std::vector<uint8_t> &buf)
    {
        BatchResult result;

        if (buf.size() < sizeof(W32K_BATCH_HEADER))
        {
            result.error_msg = "buffer smaller than batch header (" + std::to_string(buf.size()) + " bytes)";
            return result;
        }

        W32K_BATCH_HEADER bh;
        std::memcpy(&bh, buf.data(), sizeof(bh));

        if (bh.Magic != W32K_BATCH_MAGIC || bh.Version != W32K_BATCH_VERSION)
        {
            result.error_msg = "invalid batch magic/version";
            return result;
        }
        if (bh.TotalSize < sizeof(bh) ||
            static_cast<uint64_t>(bh.TotalSize) > buf.size())
        {
            result.error_msg = "batch TotalSize out of range";
            return result;
        }

        result.dropped = bh.Dropped;
        result.total_size = bh.TotalSize;
        result.events.reserve(bh.EventCount);

        uint32_t off = sizeof(W32K_BATCH_HEADER);
        while (off < bh.TotalSize)
        {
            std::string err;
            auto ev = decode_event(buf.data() + off, bh.TotalSize - off, err);
            if (!ev)
            {
                result.error_msg = "malformed event at offset " + std::to_string(off) + ": " + err;
                break;
            }
            uint32_t ev_size = 0;
            W32K_EVENT_HEADER tmp;
            std::memcpy(&tmp, buf.data() + off, sizeof(tmp));
            ev_size = tmp.TotalSize;

            result.events.push_back(std::move(*ev));
            off += ev_size;
        }

        result.ok = result.error_msg.empty();
        return result;
    }

    /* -------------------------------------------------------------------- */
    /* Pretty-printer                                                        */
    /* -------------------------------------------------------------------- */

    static const char *kind_name(ArgKind k) noexcept
    {
        static const char *names[] = {
            "scalar", "handle", "pointer", "buffer", "array", "string", "unknown"};
        auto idx = static_cast<std::size_t>(k);
        return idx < 7 ? names[idx] : "?";
    }

    static const char *dir_name(Dir d) noexcept
    {
        switch (d)
        {
        case Dir::In:
            return "in";
        case Dir::Out:
            return "out";
        case Dir::InOut:
            return "inout";
        }
        return "?";
    }

    static void print_arg_data(const ArgInfo &a, std::ostream &out)
    {
        const auto &cf = a.capture_flags;
        if (cf.null())
        {
            out << " NULL";
            return;
        }
        if (cf.skipped_phase())
        {
            out << " (not this phase)";
            return;
        }
        if (cf.skipped_irql())
        {
            out << " (irql)";
            return;
        }
        if (cf.no_size())
        {
            out << " (size unknown)";
            return;
        }
        if (cf.fault())
            out << " FAULT(0x" << std::hex << std::setw(8) << std::setfill('0')
                << static_cast<uint32_t>(a.status) << std::dec << ")";
        if (a.data.empty())
            return;

        switch (a.capture_type)
        {
        case CaptureType::UnicodeString:
        {
            auto hdr = a.unicode_header();
            if (hdr)
            {
                out << " US{len=" << hdr->length
                    << " buf=0x" << std::hex << hdr->buffer << std::dec << "} \""
                    << a.unicode_chars() << '"';
            }
            break;
        }
        case CaptureType::CStringW:
            out << " L\"" << a.as_wide() << '"';
            break;
        case CaptureType::CStringA:
            out << " \"" << a.as_ansi() << '"';
            break;
        default:
            out << " [" << a.data.size() << '/' << a.requested_length << " B] "
                << a.hex(24);
            break;
        }
        if (cf.truncated() || cf.unterminated())
            out << " (truncated)";
    }

    void Print(const EventInfo &ev, std::ostream &out)
    {
        out << "  #" << ev.sequence << ' '
            << (ev.is_pre() ? "PRE " : "POST")
            << " pid=" << std::left << std::setw(6) << ev.process_id
            << " tid=" << std::setw(6) << ev.thread_id
            << std::left << std::setw(42) << ev.name
            << std::right
            << " (0x" << std::hex << std::setw(4) << std::setfill('0') << ev.ssn
            << std::dec << std::setfill(' ') << ")";
        if (ev.is_post())
            out << " -> 0x" << std::hex << static_cast<uint64_t>(ev.return_value) << std::dec;
        if (ev.flags)
            out << " [flags=0x" << std::hex << ev.flags << std::dec << "]";
        out << '\n';

        for (std::size_t i = 0; i < ev.args.size(); ++i)
        {
            const auto &a = ev.args[i];
            out << "    a" << std::left << std::setw(3) << i
                << std::setw(8) << kind_name(a.kind)
                << std::setw(6) << dir_name(a.direction)
                << std::right /* right-pad hex */
                << "0x" << std::hex << std::setw(16) << std::setfill('0')
                << a.value << std::dec << std::setfill(' ') << std::left;
            print_arg_data(a, out);
            out << '\n';
        }

        for (const auto &n : ev.nested)
        {
            const auto &cf = n.capture_flags;
            out << "      a" << static_cast<unsigned>(n.arg_index)
                << std::left << '+' << std::setw(5) << n.parent_offset
                << "-> " << std::setw(5) << dir_name(n.direction)
                << std::right /* right-pad hex */
                << " 0x" << std::hex << std::setw(16) << std::setfill('0')
                << n.pointer_value << std::dec << std::setfill(' ') << std::left;
            if (cf.ptr_from_user())
                out << " (re-read)";
            if (cf.parent_null())
            {
                out << " (parent NULL)\n";
                continue;
            }
            if (cf.skipped_irql())
            {
                out << " (irql)\n";
                continue;
            }
            if (cf.fault())
                out << " FAULT(0x" << std::hex << static_cast<uint32_t>(n.status) << std::dec << ")";
            if (cf.null())
            {
                out << " NULL\n";
                continue;
            }
            if (cf.skipped_phase())
            {
                out << " (not this phase)\n";
                continue;
            }
            if (!n.data.empty())
            {
                out << " [" << n.data.size() << '/' << n.requested_length << " B] "
                    << n.hex(24);
            }
            if (cf.truncated())
                out << " (truncated)";
            out << '\n';
        }
    }

    void Print(const BatchResult &batch, std::ostream &out)
    {
        if (!batch.ok && batch.events.empty())
        {
            out << "[w32k] error: " << batch.error_msg << '\n';
            return;
        }

        out << "[batch] " << batch.events.size() << " events"
            << ", " << batch.dropped << " dropped"
            << ", " << batch.total_size << " bytes";
        if (!batch.ok)
            out << " (partial: " << batch.error_msg << ")";
        out << '\n';

        for (const auto &ev : batch.events)
            Print(ev, out);
    }

} // namespace W32k
