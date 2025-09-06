#pragma once
#include <ntifs.h>


NTSTATUS CreateSharedMemory();
void ReadSharedMemory();
void CleanSharedMemory();
