# RebirthGuard

### Anti-cheat library for Windows C++

## :page_facing_up: Features
* __Module remapping__
* __Thread filtering__
* __Module hidding__
* __Memory check__
* __Integrity check__
* __Anti-DLL Injection__
* __Anti-Debugging__
* __Process policy__
* __Compatibility with Themida/VMProtect__

## :heavy_check_mark: Dependencies
* Windows 7~11
* Visual Studio C++

## :wrench: How to use
1. Set options in `options.h` and build *RebirthGuard*.
2. Include `RebirthGuardSDK.h` and link `RebirthGuard.lib` in your project.
3. Build your project.

## :memo: Example
```CPP
#include <Windows.h>
#include <stdio.h>
#include "../RebirthGuard/RebirthGuardSDK.h"
#pragma comment (lib, "RebirthGuard.lib")

int main(void)
{
	CheckRebirthGuard();

	printf("Hello RebirthGuard SampleEXE!\n");

	LoadLibraryA("SampleDLL.dll");

	getchar();

	return 0;
}
```

## :mag: References
* [Self-Remapping-Code](https://github.com/changeofpace/Self-Remapping-Code)
* [Manual-DLL-Injection](http://www.rohitab.com/discuss/topic/40761-manual-dll-injection/)