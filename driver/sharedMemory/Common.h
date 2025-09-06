#pragma once
#ifdef _KERNEL_MODE
#include <ntddk.h>  
#else
#include <Windows.h>
#include <cstdint>
#endif

#define MAGIC 1337
#define PROCESS_NAME "" // ProcessName.exe
#define MODULE_NAME L"" // ModuleName.dll

typedef enum _OPERATION_TYPE
{
    OP_BASE = 0,
    OP_READ = 1,
    OP_WRITE = 2,
    OP_MODULE_BASE = 3

} OPERATION_TYPE;

struct UM_Msg
{
    ULONG ProcId;
    PVOID address;
    OPERATION_TYPE opType;
    SIZE_T dataSize;
    int magic = MAGIC;
    BYTE data[256]; 
};
