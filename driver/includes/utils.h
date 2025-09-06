#pragma once
#include "imports.h"


void* GetKernelModuleExport(LPCWSTR module_name, LPCSTR routine_name);
HANDLE GetProcID(const char* process_name);

namespace utils
{
    PVOID get_module_base(const char* module_name, size_t* size_output);
    void* copy_to_buffer(void* src, uint32_t size);
    template <typename t>
    t find_pattern(const char* pattern, const char* mask, void* start, size_t length);
    NTSTATUS get_process_module_base(PEPROCESS process, PUNICODE_STRING module_name, PVOID* module_address, ULONG* module_size);

}

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[MAXIMUM_FILENAME_LENGTH];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;