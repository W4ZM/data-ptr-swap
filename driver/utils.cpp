#include <ntifs.h>
#include "utils.h"

#ifndef dbg
#define dbg(str) \
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, str))
#endif

#ifndef dbgv
#define dbgv(str, var) \
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, str, var))
#endif

extern "C" NTKERNELAPI
PVOID NTAPI RtlFindExportedRoutineByName(
    _In_ PVOID ImageBase,
    _In_ PCCH RoutineName
);

void* GetKernelModuleExport(LPCWSTR module_name, LPCSTR routine_name) {
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"PsLoadedModuleList");
    PLIST_ENTRY module_list = (PLIST_ENTRY)MmGetSystemRoutineAddress(&name);

    if (!module_list)
        return NULL;

    for (PLIST_ENTRY link = module_list; link != module_list->Blink; link = link->Flink) {
        _LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(link, _LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        UNICODE_STRING name;
        RtlInitUnicodeString(&name, module_name);

        if (RtlEqualUnicodeString(&entry->BaseDllName, &name, TRUE)) {
            return (entry->DllBase) ? RtlFindExportedRoutineByName(entry->DllBase, routine_name) : NULL;
        }
    }
    return NULL;
}

HANDLE GetProcID(const char* process_name)
{
    ANSI_STRING AS = { 0 };
    UNICODE_STRING US = { 0 };

    RtlInitAnsiString(&AS, process_name);
    RtlAnsiStringToUnicodeString(&US, &AS, true); // converting to the type used by the process ID in SYSTEM_PROCESS_INFO struct

    ULONG buffer_size = 0;
    ZwQuerySystemInformation(SystemProcessInformation, NULL, NULL, &buffer_size);  // gets the size of the SYSTEM_PROCESS_INFO struct

    PVOID buffer = ExAllocatePoolWithTag(NonPagedPool, buffer_size, 'PYXR'); // allocates pool memory to buffer
    if (!buffer)
    {
        dbg("[-] Failed to allocate pool");
        return 0;
    }

    ZwQuerySystemInformation(SystemProcessInformation, buffer, buffer_size, NULL); // returns pointer to SYSTEM_PROCESS_INFO


    PSYSTEM_PROCESS_INFORMATION process_info = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(buffer);

    if (!process_info)
    {
        dbg("[-] PSYSTEM_PROCESS_INFORMATION is null\n");
        ExFreePoolWithTag(buffer, 'PYXR');
        return 0;
    }

    while (process_info->NextEntryOffset) // loops through all the processes
    {
        if (!RtlCompareUnicodeString(&US, &process_info->ImageName, TRUE))
        {
            ExFreePoolWithTag(buffer, 'PYXR');
            return process_info->UniqueProcessId;
        }

        process_info = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)process_info + process_info->NextEntryOffset); // sets it to the address of the next struct

    }

    RtlFreeUnicodeString(&US);
    RtlFreeAnsiString(&AS);
    ExFreePoolWithTag(buffer, 'PYXR');
    return 0;
}

namespace utils
{
    uint64_t driver_pool_base;
    uint32_t driver_pool_size;

    /*
    * Gets a kernel module's base (ntoskrnl.exe, disk.sys, etc..).
    */
    PVOID get_module_base(const char* module_name, size_t* size_output)
    {
        PVOID address = nullptr;
        ULONG size = 0;

        auto status = ZwQuerySystemInformation(SystemModuleInformation, &size, 0, &size);

        if (status != STATUS_INFO_LENGTH_MISMATCH)
        {
            return nullptr;
        }

#pragma warning( disable : 4996 )
        auto module_list = static_cast<PSYSTEM_MODULE_INFORMATION>(ExAllocatePool(NonPagedPool, size));

        if (!module_list)
        {
            return nullptr;
        }
        status = ZwQuerySystemInformation(SystemModuleInformation, module_list, size, nullptr);

        if (!NT_SUCCESS(status))
        {
            ExFreePool(module_list);

            return address;
        }

        for (auto i = 0; i < module_list->ulModuleCount; i++)
        {
            auto module = module_list->Modules[i];
            if (strstr(module.ImageName, module_name))
            {
                address = module.Base;

                if (size_output != nullptr)
                {
                    *size_output = module.Size;
                }

                break;
            }
        }

        ExFreePool(module_list);

        return address;
    }

    /*
    * Copies data to an allocated buffer.
    */
    void* copy_to_buffer(void* src, uint32_t size)
    {
        auto buffer = reinterpret_cast<char*>(ExAllocatePool(NonPagedPool, size));

        if (buffer)
        {
            MM_COPY_ADDRESS address = { 0 };
            address.VirtualAddress = src;

            size_t read_data;

            if (NT_SUCCESS(MmCopyMemory(buffer, address, size, MM_COPY_MEMORY_VIRTUAL, &read_data)) && read_data == size)
            {
                return buffer;
            }

            ExFreePool(buffer);
        }
        else
        {
#ifdef DEBUG_MODE
            DbgPrintEx(0, 0, "could not allocate pool for buffer of size &d\n", size);
#endif
        }

        return nullptr;
    }

    /*
    * Finds a pattern of bytes in a given address range.
    */
    template <typename t>
    t find_pattern(const char* pattern, const char* mask, void* start, size_t length)
    {
        const auto data = static_cast<const char*>(start);
        const auto pattern_length = strlen(mask);

        for (size_t i = 0; i <= length - pattern_length; i++)
        {
            bool found = true;

            for (size_t j = 0; j < pattern_length; j++)
            {
                if (!MmIsAddressValid(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(start) + i + j)))
                {
                    found = false;
                    break;
                }

                if (data[i + j] != pattern[j] && mask[j] != '?')
                {
                    found = false;
                    break;
                }
            }

            if (found)
            {
                return (t)(reinterpret_cast<uintptr_t>(start) + i);
            }
        }

        return (t)(nullptr);
    }

    /*
    * Walks the PEB and finds a process module's base address and size, and returns it.
    * This function attatches to the remote process (MmCopyVirtualMemory).
    */
    NTSTATUS get_process_module_base(PEPROCESS process, PUNICODE_STRING module_name, PVOID* module_address, ULONG* module_size)
    {
        NTSTATUS status;
        SIZE_T bytesCopied = 0;
        PEPROCESS currentProcess = PsGetCurrentProcess();

        if (process == NULL)
        {
            return STATUS_INVALID_PARAMETER;
        }

        // Get remote PEB.
        PPEB remotePEB = PsGetProcessPeb(process);
        if (remotePEB == NULL)
        {
            return STATUS_UNSUCCESSFUL;
        }

        // Copy the remote PEB into local memory.
        PEB localPEB = { 0 };
        status = MmCopyVirtualMemory(
            process,
            remotePEB,
            currentProcess,
            &localPEB,
            sizeof(PEB),
            KernelMode,
            &bytesCopied);
        if (!NT_SUCCESS(status))
        {
            return status;
        }

        if (localPEB.Ldr == NULL)
        {
            return STATUS_UNSUCCESSFUL;
        }

        // Copy the remote PEB_LDR_DATA into local memory.
        PEB_LDR_DATA localLdr = { 0 };
        status = MmCopyVirtualMemory(
            process,
            localPEB.Ldr,
            currentProcess,
            &localLdr,
            sizeof(PEB_LDR_DATA),
            KernelMode,
            &bytesCopied);
        if (!NT_SUCCESS(status))
        {
            return status;
        }

        // Wait for Ldr to initialize if necessary.
        if (!localLdr.Initialized)
        {
            LARGE_INTEGER delay;
            int retries = 0;
            while (!localLdr.Initialized && retries++ < 4)
            {
                delay.QuadPart = -10000 * 250; // 250ms
                KeDelayExecutionThread(KernelMode, FALSE, &delay);
                status = MmCopyVirtualMemory(
                    process,
                    localPEB.Ldr,
                    currentProcess,
                    &localLdr,
                    sizeof(PEB_LDR_DATA),
                    KernelMode,
                    &bytesCopied);
                if (!NT_SUCCESS(status))
                {
                    return status;
                }
            }
            if (!localLdr.Initialized)
            {
                return STATUS_UNSUCCESSFUL;
            }
        }

        // Compute the remote address of the list head.
        PLIST_ENTRY remoteListHead = (PLIST_ENTRY)((PUCHAR)localPEB.Ldr +
            FIELD_OFFSET(PEB_LDR_DATA, InLoadOrderModuleList));

        // Begin iterating over the module list.
        PLIST_ENTRY currentEntry = localLdr.InLoadOrderModuleList.Flink;

        while (currentEntry != remoteListHead)
        {
            LDR_DATA_TABLE_ENTRY localEntry = { 0 };
            status = MmCopyVirtualMemory(
                process,
                currentEntry,
                currentProcess,
                &localEntry,
                sizeof(LDR_DATA_TABLE_ENTRY),
                KernelMode,
                &bytesCopied);
            if (!NT_SUCCESS(status))
            {
                return status;
            }

            // Now, instead of directly comparing localEntry.BaseDllName,
            // copy the BaseDllName.Buffer (the actual module name) from the remote process.

            if (localEntry.BaseDllName.Length > 0 && localEntry.BaseDllName.Buffer != NULL)
            {
                ULONG nameLength = localEntry.BaseDllName.Length; // in bytes
                // Allocate local buffer (add space for a null terminator)
                PWCH localBaseDllNameBuffer = (PWCH)ExAllocatePoolWithTag(NonPagedPoolNx, nameLength + sizeof(WCHAR), 'nMDL');
                if (!localBaseDllNameBuffer)
                {
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                // Copy the module name string from the remote process.
                status = MmCopyVirtualMemory(
                    process,
                    localEntry.BaseDllName.Buffer,
                    currentProcess,
                    localBaseDllNameBuffer,
                    nameLength,
                    KernelMode,
                    &bytesCopied);
                if (!NT_SUCCESS(status))
                {
                    ExFreePoolWithTag(localBaseDllNameBuffer, 'nMDL');
                    return status;
                }

                // Null-terminate the string.
                localBaseDllNameBuffer[nameLength / sizeof(WCHAR)] = 0;

                UNICODE_STRING localBaseDllName;
                RtlInitUnicodeString(&localBaseDllName, localBaseDllNameBuffer);

                // Compare the module names.
                if (RtlCompareUnicodeString(&localBaseDllName, module_name, TRUE) == 0)
                {
                    if (module_address != NULL)
                    {
                        *module_address = localEntry.DllBase;
                    }
                    if (module_size != NULL)
                    {
                        *module_size = localEntry.SizeOfImage;
                    }
                    ExFreePoolWithTag(localBaseDllNameBuffer, 'nMDL');
                    return STATUS_SUCCESS;
                }

                ExFreePoolWithTag(localBaseDllNameBuffer, 'nMDL');
            }

            // Move to the next entry using the remote pointer from the copied entry.
            currentEntry = localEntry.InLoadOrderLinks.Flink;
        }

        return STATUS_UNSUCCESSFUL;
    }
}