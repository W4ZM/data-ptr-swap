#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <string> 
#include "functions.h"

struct Globals
{
	HANDLE h_write;
	HANDLE h_read;
	SIZE_T MapSize = 4096; // 4 KB
	LPVOID MapWrite;
	LPVOID MapRead;
	DWORD processId;
};

Globals Global;
UM_Msg msg;

VOID Clean()
{
	if (Global.h_read){CloseHandle(Global.h_read);}
	if (Global.h_write) { CloseHandle(Global.h_write);}
}

BOOL InitSharedMemory()
{
	
	// calling the hook to create shared section
	auto h = CreateWindowStationW(NULL, 0, GENERIC_READ | GENERIC_WRITE, nullptr);
	if (!h)
	{
		printf("[-] %s : CreateWindowStation failed: %u\n", __FUNCTION__, GetLastError());
		Clean();
		return NULL;
	}
	CloseWindowStation(h);
	
	Global.h_write = OpenFileMappingA(FILE_MAP_WRITE, false, "Global\\SharedSection");

	if (Global.h_write == NULL || Global.h_write == INVALID_HANDLE_VALUE)
	{
		printf("[-] %s : OpenFileMapping for Write Failed: %X\n",__FUNCTION__, GetLastError());
		return false;
	}

	Global.h_read = OpenFileMappingA(FILE_MAP_READ, false, "Global\\SharedSection");

	if (Global.h_read == NULL || Global.h_read == INVALID_HANDLE_VALUE)
	{
		printf("[-] %s : OpenFileMapping for Read Failed: %X\n",__FUNCTION__, GetLastError());
		return false;
	}

	// Map the view for writing.
	Global.MapWrite = MapViewOfFile(Global.h_write, FILE_MAP_WRITE, 0, 0, Global.MapSize);

	if (Global.MapWrite == NULL)
	{
		printf("[-] %s : Write Mapping Failed: %X\n", __FUNCTION__, GetLastError());
		Clean();
		return false;
	}

	// Map the view for writing.
	Global.MapRead = MapViewOfFile(Global.h_read, FILE_MAP_READ, 0, 0, Global.MapSize);

	if (Global.MapRead == NULL)
	{
		printf("[-] %s : Read Mapping Failed: %X\n", __FUNCTION__, GetLastError());
		Clean();
		return false;
	}

	return true;
}

UM_Msg* InitMsg(UM_Msg* m, SIZE_T size, PVOID addr, OPERATION_TYPE op, const void* data)
{
	if (op == OPERATION_TYPE::OP_BASE || op == OPERATION_TYPE::OP_MODULE_BASE) 
	{ 
		m->ProcId = Global.processId;
		m->address = addr;
		m->opType = op;
		return m;
	}
	m->address = addr;
	m->dataSize = size;
	m->opType = op;
	memset(m->data, 0, sizeof(m->data));
	if (op == OPERATION_TYPE::OP_WRITE){RtlCopyMemory(m->data, data, size);}
	return m;
}

// write
BOOL write_address(PVOID addr, const void* data, SIZE_T dataSize)
{

	// Prepare message structure.
	UM_Msg* m = InitMsg(&msg, dataSize, addr, OPERATION_TYPE::OP_WRITE, data);

	// write data to our shared memory
	memset(Global.MapWrite, 0, sizeof(Global.MapSize));
	RtlCopyMemory(Global.MapWrite, m, sizeof(UM_Msg));
	MemoryBarrier();
	
	// calling our hooked function
	auto h = CreateWindowStationW(NULL, 0, GENERIC_READ | GENERIC_WRITE, nullptr);
	if (!h) 
	{ 
		printf("[-] %s : CreateWindowStation failed: %u\n", __FUNCTION__, GetLastError());
		Clean();
		return false;
	}
	CloseWindowStation(h);
	return true;
}

// read
void* read_address(PVOID addr, SIZE_T dataSize)
{

	// Prepare message structure.
	UM_Msg* m = InitMsg(&msg, dataSize, addr, OPERATION_TYPE::OP_READ, NULL);

	// write data to our shared memory
	memset(Global.MapWrite, 0, sizeof(Global.MapSize));
	RtlCopyMemory(Global.MapWrite, m, sizeof(UM_Msg));
	MemoryBarrier();

	// calling our hooked function
	auto h = CreateWindowStationW(NULL, 0, GENERIC_READ | GENERIC_WRITE, nullptr);
	if (!h) 
	{ 
		printf("[-] %s : CreateWindowStation failed: %u\n", __FUNCTION__, GetLastError());
		Clean();
		return NULL;
	}
	CloseWindowStation(h);

	if ((UM_Msg*)Global.MapRead == NULL || ((UM_Msg*)Global.MapRead)->magic != MAGIC)
	{
		printf("[-] %s : Shared Data Not Found: %u\n", __FUNCTION__, GetLastError());
		Clean();
		return NULL;
	}
	
	return ((UM_Msg*)Global.MapRead)->data;
}

uint32_t GetProcID(const std::string& image_name)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE)
		return 0;

	PROCESSENTRY32 process;
	process.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(snapshot, &process)) {
		do {
			// Using _stricmp for a case-insensitive comparison
			if (_stricmp(image_name.c_str(), process.szExeFile) == 0) {
				CloseHandle(snapshot);
				return process.th32ProcessID;
			}
		} while (Process32Next(snapshot, &process));
	}

	CloseHandle(snapshot);

	return 0;
}

uintptr_t GetBaseAddr(const std::string& ProcName, BOOL isModule)
{
	Global.processId = GetProcID(ProcName);
	
	if (!Global.processId)
	{
		printf("[-] %s : GetProcID Failed: %X\n", __FUNCTION__, GetLastError());
		Clean();
		return NULL;
	}

	OPERATION_TYPE op = OPERATION_TYPE::OP_BASE;
	if (isModule){op = OPERATION_TYPE::OP_MODULE_BASE;}
	auto m = InitMsg(&msg, 0, NULL,op, NULL);

	// write data to our shared memory
	memset(Global.MapWrite, 0, sizeof(Global.MapSize));
	RtlCopyMemory(Global.MapWrite, m, sizeof(UM_Msg));
	MemoryBarrier();

	// calling our hooked function
	auto h = CreateWindowStationW(NULL, 0, GENERIC_READ | GENERIC_WRITE, nullptr);
	if (!h)
	{
		printf("[-] %s : CreateWindowStation failed: %u\n", __FUNCTION__, GetLastError());
		Clean();
		return NULL;
	}
	CloseWindowStation(h);

	if ((UM_Msg*)Global.MapRead == NULL || ((UM_Msg*)Global.MapRead)->magic != MAGIC)
	{
		printf("[-] %s : Shared Data Not Found: %u\n", __FUNCTION__, GetLastError());
		Clean();
		return NULL;
	}
	return reinterpret_cast<uintptr_t>(((UM_Msg*)Global.MapRead)->address);
}