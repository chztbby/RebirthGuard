
#include <Windows.h>
#include <stdio.h>
#include "../RebirthGuard/RebirthGuardSDK.h"
#pragma comment (lib, "RebirthGuard.lib")

int main(void)
{
	printf(RGS("Hello RebirthGuard SampleEXE!\n"));

	LoadLibraryA(RGS("SampleDLL.dll"));

	getchar();

	return 0;
}