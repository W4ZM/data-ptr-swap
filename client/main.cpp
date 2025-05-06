#include <Windows.h>
#include <stdio.h>
#include <string> 
#include "functions.h"


int main()
{
	auto status = InitSharedMemory();
	if (!status){return 1;}

	auto client = GetBaseAddr(PROCESS_NAME, 0);
	if (!client) { return 1; }


	//example
 
	//const auto value = read<int>(address to read);
	//status = write<int>(address to write, value);	
	
	Clean();
	return 0;
}