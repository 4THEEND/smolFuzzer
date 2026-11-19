/*
 * sysmon_wire.h - record layout shared by the driver and the user-mode decoder.
 *
 * Deliberately includes nothing and uses only built-in types whose size is the
 * same in the kernel, in a Win64 service and in a test build on another OS, so
 * both sides can include this exact file.
 */
#ifndef SYSMON_WIRE_H
#define SYSMON_WIRE_H

#define SYSMON_MAX_ARGS        17      /* must be >= W32K_MAX_ARGS            */
#define SYSMON_BLOB_BYTES      512     /* pointed-to data kept per call       */
#define SYSMON_PER_ARG_CAP     128     /* pointed-to data kept per argument   */

#define SYSMON_REC_KERNEL_CALLER  0x01  /* PreviousMode == KernelMode, pointers not followed */
#define SYSMON_REC_BLOB_FULL      0x02  /* ran out of blob space, some captures skipped      */

typedef struct _SYSMON_RECORD {
    unsigned long long Sequence;                 /* left 0 by the gatherer; caller may set  */
    long long          Timestamp;                /* system time (100 ns since 1601, UTC)    */
    unsigned long long ProcessId;
    unsigned long long ThreadId;
    unsigned int       Ssn;                      /* 0x1000 + index                          */
    unsigned char      NumArgs;
    unsigned char      Flags;                    /* SYSMON_REC_*                            */
    unsigned short     BlobUsed;                 /* valid bytes in Blob                     */
    unsigned long long Args[SYSMON_MAX_ARGS];    /* raw values, truncated to declared width */
    unsigned char      Blob[SYSMON_BLOB_BYTES];  /* sequence of SYSMON_CAPTURE entries      */
} SYSMON_RECORD;

#define SYSMON_CAP_OK         0
#define SYSMON_CAP_TRUNCATED  1   /* more data existed than was kept          */
#define SYSMON_CAP_FAULT      2   /* pointer was invalid / unreadable         */
#define SYSMON_CAP_STATUS_MASK 0x7F
#define SYSMON_CAP_ANSI       0x80 /* OR-ed in: PLARGE_STRING data is 1-byte chars, not UTF-16 */

/* One entry in SYSMON_RECORD.Blob. Followed by Length data bytes, then padded
 * to a 4-byte boundary. For string arguments the data is the characters
 * (no terminator); for PUNICODE_STRING / PLARGE_STRING it is the string body,
 * not the header. */
typedef struct _SYSMON_CAPTURE {
    unsigned char  ArgIndex;
    unsigned char  Status;                       /* SYSMON_CAP_* (| SYSMON_CAP_ANSI)        */
    unsigned short Length;
} SYSMON_CAPTURE;

/* Both sides must agree on the layout; fail the build if a compiler disagrees. */
typedef char SYSMON_ASSERT_RECORD_SIZE [(sizeof(SYSMON_RECORD)  == 40 + 8 * SYSMON_MAX_ARGS + SYSMON_BLOB_BYTES) ? 1 : -1];
typedef char SYSMON_ASSERT_CAPTURE_SIZE[(sizeof(SYSMON_CAPTURE) == 4) ? 1 : -1];

#endif /* SYSMON_WIRE_H */
