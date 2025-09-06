#pragma once
#ifndef _NTIFS_
#include <ntifs.h>
#endif

#ifndef dbg
#define dbg(str) \
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, str))
#endif

#ifndef dbgv
#define dbgv(str, var) \
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, str, var))
#endif

typedef __int64(__fastcall* NtUserCreateWindowStation_t)(
    __int64      a1,
    UINT64 a2,
    __int64      a3,
    UINT64 a4,
    int          a5,
    __int64      a6,
    __int64      a7,
    int          a8
    );

typedef __int64(__stdcall* W32GetSessionState)();

NTSTATUS hook();