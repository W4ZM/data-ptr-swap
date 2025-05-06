#include "core.h"
#include "shared.h"
#include "utils.h"
#include "Common.h"
#include "Physmem.h"

extern PVOID g_SharedSection;
BYTE* data;


NTSTATUS InitializeSharedMemory()
{
	auto status = CreateSharedMemory();

	if (!NT_SUCCESS(status))
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
			"[-] InitializeSharedMemory failed!\n"));
		CleanSharedMemory();
		return status;
	}
	return status;
}
NTSTATUS MyFunction()
{
	auto status = STATUS_SUCCESS;
	ReadSharedMemory();
	auto msg = (UM_Msg*)g_SharedSection;
	if (msg && (ExGetPreviousMode() == UserMode))
	{	 
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
			"[!] MyFunction called !\n"));

		// get process base address
		if (msg->magic == MAGIC && msg->opType == OPERATION_TYPE::OP_BASE)
		{
			KeMemoryBarrier();
			auto BaseAddr = GetProcessBaseAddress(msg->ProcId);

			if (BaseAddr == NULL)
			{
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
					"[-] GetProcessBaseAddress failed!\n"));
				return STATUS_UNSUCCESSFUL;
			}

			msg->address = BaseAddr;
		}

		// get a process module base
		if (msg->magic == MAGIC && msg->opType == OPERATION_TYPE::OP_MODULE_BASE)
		{
			KeMemoryBarrier();

			PEPROCESS proc;
			status = PsLookupProcessByProcessId(ULongToHandle( msg->ProcId), &proc);
				
			if (!NT_SUCCESS(status)) 
			{
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
					"[-] PsLookupProcessByProcessId failed!\n"));
				return STATUS_UNSUCCESSFUL;
			}

			UNICODE_STRING name;
			RtlInitUnicodeString(&name, MODULE_NAME);

			PVOID module_address;
			ULONG module_size;

			status = utils::get_process_module_base(proc, &name, &module_address, &module_size);

			if (!NT_SUCCESS(status))
			{
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
					"[-] get_process_module_base failed!\n"));
				return STATUS_UNSUCCESSFUL;
			}

			msg->address = module_address;
		}
		
		// read
		if (msg->magic == MAGIC && msg->opType == OPERATION_TYPE::OP_READ)
		{
				
			KeMemoryBarrier();
			
			data = (BYTE*)ExAllocatePoolWithTag(NonPagedPool, msg->dataSize, 'bufT');
			if (!data)
			{
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] %s Failed to allocate memory\n", __FUNCTION__));
				return STATUS_UNSUCCESSFUL;
			}
				
			RtlZeroMemory(data, sizeof(msg->dataSize));
			SIZE_T read;

			status = ReadProcessMemory(msg->ProcId,
				reinterpret_cast<PVOID>(msg->address),
				data,
				msg->dataSize,
				&read);
	
			if (!NT_SUCCESS(status))
			{
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
					"[-] ReadProcessMemory failed\n"));

				ExFreePool(data);
				return STATUS_UNSUCCESSFUL;
			}

			RtlCopyMemory(msg->data, data, msg->dataSize);
			ExFreePool(data);
		}

		// write
		if (msg->magic == MAGIC && msg->opType == OPERATION_TYPE::OP_WRITE)
		{
			KeMemoryBarrier();
			// is it necessary ?
			if (msg->ProcId == 0 || msg->data == NULL || msg->dataSize == 0)
			{
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
					"[-] Some BS got provided to WriteProcessMemory\n"));
				return STATUS_UNSUCCESSFUL;
			}

			SIZE_T written = 0;
			status = WriteProcessMemory(msg->ProcId,         
				reinterpret_cast<PVOID>(msg->address),
				msg->data,           
				msg->dataSize,       
				&written);

			if (!NT_SUCCESS(status))
			{
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
					"[-] WriteProcessMemory failed\n"));
				return STATUS_UNSUCCESSFUL;
			}
		}
	}

	return status;
}
