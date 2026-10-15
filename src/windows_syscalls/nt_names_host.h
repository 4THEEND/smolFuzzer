/*
 * nt_names_host.h  --  HOST ONLY
 *
 * NT SSN -> syscall name lookup. No WDK types.
 * AUTO-GENERATED from nt_devioctl.json -- do not edit by hand.
 *   Build : None
 */

#ifndef NT_NAMES_HOST_H
#define NT_NAMES_HOST_H

#include <stdio.h> /* snprintf */

#define NT_NAMES_BASE 0x0u
#define NT_NAMES_COUNT 8u /* table slots; 1 described, 7 gaps */

static const char *const NtSyscallNames[NT_NAMES_COUNT] = {
    "",                      /* 0x0 gap */
    "",                      /* 0x1 gap */
    "",                      /* 0x2 gap */
    "",                      /* 0x3 gap */
    "",                      /* 0x4 gap */
    "",                      /* 0x5 gap */
    "",                      /* 0x6 gap */
    "NtDeviceIoControlFile", /* 0x7 */
};

static inline const char *NtNameFromSsn(unsigned ssn)
{
    unsigned idx = ssn - NT_NAMES_BASE;
    if (idx < NT_NAMES_COUNT && NtSyscallNames[idx][0] != '\0')
        return NtSyscallNames[idx];
    /* SSN not described in this JSON or out of range */
    static char _buf[20];
    (void)snprintf(_buf, sizeof(_buf), "<nt:0x%04X>", ssn);
    return _buf;
}

#endif /* NT_NAMES_HOST_H */
