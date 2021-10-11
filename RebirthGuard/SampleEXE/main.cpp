
#include <Windows.h>
#include <stdio.h>
#include "../RebirthGuard/RebirthGuardSDK.h"
#pragma comment (lib, "RebirthGuard.lib")

int main(void)
{
	//CheckRebirthGuard();

	printf("Hello RebirthGuard!\n");

	MessageBoxA(0, "Hello RebirthGuard!", 0, 0);

	return 0;
}