extern "C" {
#include "CreateDriver.h"
}
#include "hook.h"
#include "core.h"

NTSTATUS mainEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING  reg_path)
{
	UNREFERENCED_PARAMETER(driver_object);
	UNREFERENCED_PARAMETER(reg_path);
	return hook();
}

NTSTATUS DriverEntry()
{
	return IoCreateDriver(mainEntry);
}