# RebirthGuard

### Windows anti-cheat library

## :page_facing_up: Features
* __Module remapping__ (Force page protection)
* __Thread filtering__
* __Hide module list__
* __Memory check__
* __CRC check__ (Hide from debugger)
* __Anti-DLL Injection__
* __Anti-Debugging__
* __Process policy__

## :heavy_check_mark: Dependencies
* Windows 7~11
* Visual Studio 2019

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
	printf("Hello RebirthGuard!\n");

	getchar();

	return 0;
}
```


## :mag: References
* [Self-Remapping-Code](https://github.com/changeofpace/Self-Remapping-Code)
* [Manual-DLL-Injection](http://www.rohitab.com/discuss/topic/40761-manual-dll-injection/)