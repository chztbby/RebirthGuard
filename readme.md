# RebirthGuard

## Windows Process Protection Library (x64)

__RebirthGuard__ is a User-mode (ring 3) library written on C.

This library is based on *__Section remapping__* and *__Manual mapping__* technique, and designed *__callback-based__*.

Certain functions need to be called when needed : `MemCheck`, `CRCCheck` 

In this project, *__Rebirth__* means *Section remap* and *Force page protection*.

## :heavy_check_mark: Dependencies
* Windows 10 x64
* Visual Studio 2017 Community
* Windows 10 SDK 10.0.15063.0


## :page_facing_up: Capabilities
* __Module remapping__ (Force page protection)
* __Hide module list__
* __Process policy__
* __File integrity check__
* __Thread filtering__
* __Memory check__
* __CRC check__ (Hide from debugger)
* __Anti-DLL Injection__
* __Anti-Debugging__
* __Exception handling__


## :wrench: How to use
1. Set RebirthGuard options in `Settings.h`.
2. Complie RebirthGuard.
3. Include `RebirthGuardSDK.h` and link `RebirthGuard.lib` in your project.
4. Add linker option : `/RELEASE` (If `FILE_CHECK` option is enabled)
5. Compile your project.

## :memo: Example
```CPP
#include <Windows.h>
#include <stdio.h>
#include <RebirthGuardSDK.h>
#pragma comment (lib, "RebirthGuard.lib")

int main(void)
{
	printf("RebirthGuard Test\n\n");

	for (int i = 0;; i++)
	{
		printf("%d\n", i);

		MemCheck(GetCurrentProcess());

		CRCCheck();

		Sleep(3000);
	}

	return 0;
}
```


## :mag: References
* [Self-Remapping-Code](https://github.com/changeofpace/Self-Remapping-Code)
* [Manual-DLL-Injection](http://www.rohitab.com/discuss/topic/40761-manual-dll-injection/)

## :pencil2: Sample Test 2
* [Titan-Voyager-Custom-Game-Engine](https://github.com/TheFearlessHobbit/Titan-Voyager-Custom-Game-Engine)
