#include "hook.h"
#include "core.h"
#include "utils.h"

/*typedef __int64(__fastcall* NtUserCreateWindowStation_t)(
    __int64      a1,
     UINT64 a2,
    __int64      a3,
     UINT64 a4,
    int          a5,
    __int64      a6,
    __int64      a7,
    int          a8
    );

typedef __int64 (__stdcall* W32GetSessionState)();*/

NtUserCreateWindowStation_t original_function = NULL;
PEPROCESS g_pWinlogon = 0;
KAPC_STATE apc = { 0 };
extern HANDLE g_SectionHandle;
extern PVOID g_SectionPointer;

__int64 HookedFunction(__int64 a1, UINT64 a2, __int64 a3, UINT64 a4, int a5, __int64 a6, __int64 a7, int a8)
{
    dbg("[!] hook called ! \n");
    
    KeStackAttachProcess(g_pWinlogon, &apc);
    if (!g_SectionHandle)
    {
        auto status = InitializeSharedMemory();
        if (!NT_SUCCESS(status)) { return original_function(a1, a2, a3, a4, a5, a6, a7, a8); }
    }
    MyFunction();
    KeUnstackDetachProcess(&apc);
    return original_function(a1, a2, a3, a4, a5, a6, a7, a8);
}

NTSTATUS hook()
{
	auto status = STATUS_SUCCESS;

    if (!NT_SUCCESS(PsLookupProcessByProcessId(GetProcID("winlogon.exe"), &g_pWinlogon)))
    {
        dbg("[-] failed to find winlogon.exe\n");
        return STATUS_UNSUCCESSFUL;
    }

	auto GetSessionState = (W32GetSessionState)GetKernelModuleExport(L"win32k.sys", "W32GetSessionState");
    if (GetSessionState == NULL)
    {
        dbg("[-] GetKernelModuleExport failed \n");
        return STATUS_UNSUCCESSFUL;
    }
    auto function_ptr = (__int64*)(*(UINT64*)(*(UINT64*)(GetSessionState() + 136) + 360LL) + 72LL);
    if (!function_ptr || !*function_ptr)
    {
        dbg("[-] failed getting NtUserCreateWindowStation ptr \n");
        return STATUS_UNSUCCESSFUL;
    }

    //dbgv("[!] function ptr value : %p\n", *function_ptr);
    //dbg("[!] swapping ... \n");

    original_function = reinterpret_cast<NtUserCreateWindowStation_t>(*function_ptr);
    InterlockedExchangePointer(reinterpret_cast<PVOID volatile*>(function_ptr), HookedFunction);

    //dbgv("[!] hooked function address : %p\n", HookedFunction);
    //dbgv("[!] function ptr value : %p\n", *function_ptr);
    //dbg("[!] restoring pointers ... \n");

    //InterlockedExchangePointer(reinterpret_cast<PVOID volatile*>(function_ptr), original_function);

    //dbgv("[!] function ptr value : %p\n", *function_ptr);
    dbg("[+] Swapped !\n");

	return status;
}