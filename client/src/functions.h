#pragma once
#include "Common.h"


VOID Clean();
BOOL InitSharedMemory();
UM_Msg* InitMsg(UM_Msg* m, SIZE_T size, PVOID addr, OPERATION_TYPE op, const void* data);

BOOL write_address(PVOID addr, const void* data, SIZE_T dataSize);
template <typename T>
BOOL write(uintptr_t addr, const T& value) { return write_address(reinterpret_cast<PVOID>(addr), &value, sizeof(T)); }

void* read_address(PVOID addr, SIZE_T dataSize);
template <typename T>
T read(const uintptr_t addr)
{
	T* pValue{};
	pValue = reinterpret_cast<T*>(read_address(reinterpret_cast<PVOID>(addr), sizeof(T)));
	if (!pValue)
	{
		printf("[-] %s : 'pValue' is Null: %X\n", __FUNCTION__, GetLastError());
		Clean();
		ExitProcess(1);
	}
	return *pValue;
}

uint32_t GetProcID(const std::string& image_name);
uintptr_t GetBaseAddr(const std::string& ProcName, BOOL isModule);