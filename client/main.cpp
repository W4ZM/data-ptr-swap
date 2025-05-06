#include <Windows.h>
#include <stdio.h>
#include <string> 
#include "functions.h"

namespace offsets
{
	constexpr auto iViewMatrix = 0x17DFD0;
	constexpr auto iLocalPlayer = 0x0018AC00;
	constexpr auto iEntityList = 0x00191FCC;

	constexpr auto vHead = 0x4;
	constexpr auto iTeam = 0x30C;
	constexpr auto isDead = 0x0318;
	constexpr auto pYaw = 0x34;
	constexpr auto vFeet = 0x28;
	constexpr auto pHealth = 0xEC;
	constexpr auto pPitch = 0x38;
}

int main()
{
	auto status = InitSharedMemory();
	if (!status){return 1;}

	auto client = GetBaseAddr(PROCESS_NAME, 0);
	if (!client) { return 1; }
	printf("Base : %lu\n", client);

	const auto localPayer = read<uint32_t>(client + offsets::iLocalPlayer);
	printf("localPayer : %lu\n", localPayer);
	const auto health = read<int>(localPayer + offsets::pHealth);
	printf("[+] HP : %d\n", health);
	const int newhealth = 100;
	while (true)
	{
		if (GetAsyncKeyState(VK_LSHIFT))
		{
			status = write<int>((localPayer + offsets::pHealth), newhealth);
			if (!status)
			{
				printf("[-] write failed\n");
				break;
			}
		}
		Sleep(1);
	}
	
	Clean();
	return 0;
}