
#include <Windows.h>
#include <stdio.h>
#include "../RebirthGuard/RebirthGuardSDK.h"
#pragma comment (lib, "RebirthGuard.lib")

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		printf(RGS("Hello RebirthGuard SampleDLL!\n"));
		break;

	case DLL_THREAD_ATTACH:
		break;

	case DLL_THREAD_DETACH:
		break;

	case DLL_PROCESS_DETACH:
		break;
	}

    return TRUE;
}