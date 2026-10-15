/*
 * w32k_decode.hpp  --  HOST ONLY
 *
 * C++17 decoder for batches delivered by dumpToHost().
 * Takes a std::vector<uint8_t> (the raw buffer) and returns structured data.
 *
 * Usage:
 *   void dumpToHost(const char *, const void *buf, uint64_t len) {
 *       std::vector<uint8_t> v(static_cast<const uint8_t*>(buf),
 *                              static_cast<const uint8_t*>(buf) + len);
 *       auto batch = W32k::DecodeBatch(v);
 *       W32k::Print(batch, std::cout);
 *   }
 */

#pragma once

#include <cstdint>
#include <optional>
#include <ostream>
#include <string>
#include <vector>

namespace W32k
{

    /* -------------------------------------------------------------------- */
    /* Constants that mirror the wire format (copied to avoid pulling in    */
    /* the C wire header in user code).                                     */
    /* -------------------------------------------------------------------- */

    // W32K_ARG_KIND values
    enum class ArgKind : uint8_t
    {
        Scalar = 0,
        Handle = 1,
        Pointer = 2,
        Buffer = 3,
        Array = 4,
        String = 5,
        Unknown = 6,
    };

    // W32K_ARG_DIR values
    enum class Dir : uint8_t
    {
        In = 0,
        Out = 1,
        InOut = 2
    };

    // W32K_PHASE values
    enum class Phase : uint8_t
    {
        Pre = 0,
        Post = 1
    };

    // W32K_CAPTURE_* values
    enum class CaptureType : uint8_t
    {
        None = 0,
        Bytes = 1,
        Array = 2,
        UnicodeString = 3,
        CStringA = 4,
        CStringW = 5,
    };

    // W32K_CAPF_* bitmask
    struct CaptureFlags
    {
        uint32_t bits = 0;
        bool null() const noexcept { return bits & 0x0001u; }
        bool truncated() const noexcept { return bits & 0x0002u; }
        bool fault() const noexcept { return bits & 0x0004u; }
        bool skipped_phase() const noexcept { return bits & 0x0008u; }
        bool skipped_irql() const noexcept { return bits & 0x0010u; }
        bool no_size() const noexcept { return bits & 0x0020u; }
        bool no_space() const noexcept { return bits & 0x0040u; }
        bool unterminated() const noexcept { return bits & 0x0080u; }
        bool ptr_from_user() const noexcept { return bits & 0x0100u; }
        bool parent_null() const noexcept { return bits & 0x0200u; }
        bool has_data() const noexcept { return !(null() | skipped_phase() |
                                                  skipped_irql() | no_size()); }
    };

    /* -------------------------------------------------------------------- */
    /* Unicode string blob header (first 16 bytes of a UnicodeString blob)  */
    /* -------------------------------------------------------------------- */

    struct UnicodeStringBlob
    {
        uint16_t length; // byte length of characters (from caller)
        uint16_t maximum_length;
        uint32_t reserved;
        uint64_t buffer; // caller's buffer address
    };
    static_assert(sizeof(UnicodeStringBlob) == 16, "layout");

    /* -------------------------------------------------------------------- */
    /* Decoded argument                                                      */
    /* -------------------------------------------------------------------- */

    struct ArgInfo
    {
        uint64_t value = 0;
        ArgKind kind = ArgKind::Unknown;
        uint8_t size = 8;
        Dir direction = Dir::In;
        CaptureType capture_type = CaptureType::None;
        CaptureFlags capture_flags = {};
        int32_t status = 0;
        uint32_t requested_length = 0;
        std::vector<uint8_t> data; // captured blob (may be empty)

        // ---- Convenience accessors ----------------------------------------

        // True if the pointer was NULL (no blob expected)
        bool is_null() const noexcept { return capture_flags.null(); }
        // True if the blob was cut short by the per-arg cap or event cap
        bool is_truncated() const noexcept { return capture_flags.truncated(); }
        // True if user memory access faulted
        bool faulted() const noexcept { return capture_flags.fault(); }
        // True if a blob was captured (data may still be empty if len==0)
        bool has_data() const noexcept { return capture_flags.has_data(); }

        // For CStringA: raw bytes as a std::string (NUL included if present)
        std::string as_ansi() const;

        // For CStringW or UnicodeString chars: UTF-16LE -> printable std::string
        // Non-ASCII codepoints are escaped as \uXXXX.
        std::string as_wide() const;

        // For UnicodeString blobs: the wire header (first 16 bytes)
        // Returns nullopt if data is too small to hold the header.
        std::optional<UnicodeStringBlob> unicode_header() const noexcept;

        // For UnicodeString blobs: the character bytes after the 16-byte header.
        // Same as as_wide() but only over the character portion.
        std::string unicode_chars() const;

        // Hex dump of data (up to max_bytes bytes), e.g. "AABBCCDD..."
        std::string hex(std::size_t max_bytes = 24) const;
    };

    /* -------------------------------------------------------------------- */
    /* Decoded nested pointer entry                                          */
    /* -------------------------------------------------------------------- */

    struct NestedInfo
    {
        uint8_t arg_index = 0;
        Dir direction = Dir::In;
        uint32_t parent_offset = 0;
        uint64_t pointer_value = 0;
        CaptureFlags capture_flags = {};
        int32_t status = 0;
        uint32_t requested_length = 0;
        std::vector<uint8_t> data;

        bool is_null() const noexcept { return capture_flags.null(); }
        bool is_truncated() const noexcept { return capture_flags.truncated(); }
        bool faulted() const noexcept { return capture_flags.fault(); }

        std::string hex(std::size_t max_bytes = 24) const;
    };

    /* -------------------------------------------------------------------- */
    /* Decoded event                                                         */
    /* -------------------------------------------------------------------- */

    struct EventInfo
    {
        uint64_t sequence = 0;
        int64_t timestamp = 0; // 100-ns intervals since 1601-01-01 UTC
        uint64_t process_id = 0;
        uint64_t thread_id = 0;
        int64_t return_value = 0; // meaningful only for Phase::Post
        uint16_t ssn = 0;
        Phase phase = Phase::Pre;
        uint32_t flags = 0; // W32K_EVENT_FLAG_* bitmask
        std::string name;   // "NtDeviceIoControlFile", "<nt:0x0055>", etc.

        std::vector<ArgInfo> args;
        std::vector<NestedInfo> nested;

        bool is_pre() const noexcept { return phase == Phase::Pre; }
        bool is_post() const noexcept { return phase == Phase::Post; }
        bool is_nt() const noexcept { return ssn < 0x1000u; }
        bool is_win32k() const noexcept { return ssn >= 0x1000u; }
    };

    /* -------------------------------------------------------------------- */
    /* Batch result                                                          */
    /* -------------------------------------------------------------------- */

    struct BatchResult
    {
        bool ok = false; // false: parse error; check error_msg
        std::string error_msg;

        uint32_t dropped = 0; // events dropped in the driver
        uint32_t total_size = 0;
        std::vector<EventInfo> events;
    };

    /* -------------------------------------------------------------------- */
    /* API                                                                   */
    /* -------------------------------------------------------------------- */

    /*
     * Decode one complete dumpToHost() buffer.
     * On parse error, returns BatchResult{ok=false, error_msg=...}.
     * Individual malformed events are skipped with a note in error_msg;
     * events decoded before the error are still present.
     */
    BatchResult DecodeBatch(const std::vector<uint8_t> &buf);

    /*
     * Print a decoded batch/event to a stream.
     * Produces the same human-readable format as the C decoder.
     */
    void Print(const BatchResult &batch, std::ostream &out);
    void Print(const EventInfo &event, std::ostream &out);

    /*
     * Syscall name lookup by SSN (works for both NT and win32k).
     * Returns "NtDeviceIoControlFile", "<nt:0x0055>", "<w32k:0x1042>", etc.
     */
    std::string SyscallName(uint16_t ssn);

    /* -------------------------------------------------------------------- */
    /* Encoder: convert structured data back to wire format                 */
    /* -------------------------------------------------------------------- */

    /*
     * Encode one event to its wire representation.
     * The returned bytes can be written directly into a batch buffer, or
     * round-tripped through DecodeBatch after wrapping with EncodeBatch.
     *
     * All fields of EventInfo are preserved exactly (sequence, timestamp,
     * flags, ssn, phase, return_value, args, nested).  DataOffset values
     * in the emitted W32K_EVENT_ARG / W32K_EVENT_NESTED entries are
     * recomputed from the blob vectors; the caller never needs to touch them.
     */
    std::vector<uint8_t> EncodeEvent(const EventInfo &event);

    /*
     * Encode a full batch to wire format.
     * The result is a buffer that DecodeBatch() accepts unchanged.
     *
     * EncodeBatch(batch) preserves batch.dropped.
     * EncodeBatch(events) sets dropped = 0.
     */
    std::vector<uint8_t> EncodeBatch(const BatchResult &batch);
    std::vector<uint8_t> EncodeBatch(const std::vector<EventInfo> &events,
                                     uint32_t dropped = 0);

} // namespace W32k
