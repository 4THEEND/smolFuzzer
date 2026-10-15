/*
 * w32k_wire_host.h  --  HOST ONLY
 *
 * Same wire format as w32k_wire_km.h, using stdint types.
 * No WDK headers, no Windows headers required.
 * Safe to include on Linux, macOS, or any other host.
 */

#ifndef W32K_WIRE_HOST_H
#define W32K_WIRE_HOST_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef C_ASSERT
#ifdef __cplusplus
#define C_ASSERT(e) static_assert(e, #e)
#else
#define C_ASSERT(e) _Static_assert(e, #e)
#endif
#endif

/* -------------------------------------------------------------------- */
/* Batch                                                                 */
/* -------------------------------------------------------------------- */

#define W32K_BATCH_MAGIC   0x42323357u
#define W32K_BATCH_VERSION 1u


/* If the kernel wire header is present in this TU, its typedefs already
 * define these names using WDK types. Skip the host redefinition. */
#ifndef W32K_WIRE_KM_H
#pragma pack(push, 8)
typedef struct W32K_BATCH_HEADER {
    uint32_t Magic;
    uint32_t Version;
    uint32_t TotalSize;
    uint32_t EventCount;
    uint32_t Dropped;
    uint32_t Reserved;
} W32K_BATCH_HEADER;
#pragma pack(pop)
C_ASSERT(sizeof(W32K_BATCH_HEADER) == 24);

/* -------------------------------------------------------------------- */
/* Event                                                                 */
/* -------------------------------------------------------------------- */

#define W32K_EVENT_MAGIC   0x4B323357u
#define W32K_EVENT_VERSION 2u

#define W32K_PHASE_PRE     0u
#define W32K_PHASE_POST    1u

#define W32K_EVENT_FLAG_UNKNOWN_SSN    0x0001u
#define W32K_EVENT_FLAG_ARGS_TRUNCATED 0x0002u
#define W32K_EVENT_FLAG_DATA_TRUNCATED 0x0004u
#define W32K_EVENT_FLAG_USER_SKIPPED   0x0008u

#define W32K_CAPTURE_NONE           0u
#define W32K_CAPTURE_BYTES          1u
#define W32K_CAPTURE_ARRAY          2u
#define W32K_CAPTURE_UNICODE_STRING 3u
#define W32K_CAPTURE_CSTRING_A      4u
#define W32K_CAPTURE_CSTRING_W      5u

#define W32K_CAPF_NULL           0x0001u
#define W32K_CAPF_TRUNCATED      0x0002u
#define W32K_CAPF_FAULT          0x0004u
#define W32K_CAPF_SKIPPED_PHASE  0x0008u
#define W32K_CAPF_SKIPPED_IRQL   0x0010u
#define W32K_CAPF_NO_SIZE        0x0020u
#define W32K_CAPF_NO_SPACE       0x0040u
#define W32K_CAPF_UNTERMINATED   0x0080u
#define W32K_CAPF_PTR_FROM_USER  0x0100u
#define W32K_CAPF_PARENT_NULL    0x0200u

#pragma pack(push, 8)
typedef struct W32K_EVENT_HEADER {
    uint32_t Magic;
    uint16_t Version;
    uint16_t HeaderSize;
    uint32_t TotalSize;
    uint32_t Flags;
    uint64_t Sequence;
    int64_t  Timestamp;
    uint64_t ProcessId;
    uint64_t ThreadId;
    int64_t  ReturnValue;
    uint16_t Ssn;
    uint8_t  Phase;
    uint8_t  ArgCount;
    uint32_t ArgsOffset;
    uint32_t NestedOffset;
    uint16_t NestedCount;
    uint16_t Reserved;
} W32K_EVENT_HEADER;

typedef struct W32K_EVENT_ARG {
    uint64_t Value;
    uint8_t  Kind;
    uint8_t  Size;
    uint8_t  Direction;
    uint8_t  CaptureType;
    int32_t  Status;
    uint32_t DataOffset;
    uint32_t DataLength;
    uint32_t RequestedLength;
    uint32_t CaptureFlags;
} W32K_EVENT_ARG;

typedef struct W32K_EVENT_NESTED {
    uint8_t  ArgIndex;
    uint8_t  Direction;
    uint16_t Reserved;
    uint32_t ParentOffset;
    uint64_t PointerValue;
    int32_t  Status;
    uint32_t CaptureFlags;
    uint32_t DataOffset;
    uint32_t DataLength;
    uint32_t RequestedLength;
    uint32_t Reserved2;
} W32K_EVENT_NESTED;

typedef struct W32K_WIRE_UNICODE_STRING {
    uint16_t Length;
    uint16_t MaximumLength;
    uint32_t Reserved;
    uint64_t Buffer;
} W32K_WIRE_UNICODE_STRING;
#pragma pack(pop)

C_ASSERT(sizeof(W32K_BATCH_HEADER)          == 24);
C_ASSERT(sizeof(W32K_EVENT_HEADER)          == 72);
C_ASSERT(sizeof(W32K_EVENT_ARG)             == 32);
C_ASSERT(sizeof(W32K_EVENT_NESTED)          == 40);
C_ASSERT(sizeof(W32K_WIRE_UNICODE_STRING)   == 16);
#endif /* !W32K_WIRE_KM_H */


#ifdef __cplusplus
}
#endif

#endif /* W32K_WIRE_HOST_H */
