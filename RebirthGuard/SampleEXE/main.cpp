
#include <Windows.h>
#include <stdio.h>
#include "../RebirthGuard/RebirthGuardSDK.h"
#pragma comment (lib, "RebirthGuard.lib")

int main(void)
{
	//CheckRebirthGuard();

	printf("Hello RebirthGuard SampleEXE!\n");

	LoadLibraryA("SampleDLL.dll");

	getchar();

	return 0;
}