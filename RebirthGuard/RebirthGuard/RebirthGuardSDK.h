
/*
	chztbby::RebirthGuard/RebirthGuardSDK.h
*/

#ifndef REBIRTHGUARD_SDK_H
#define REBIRTHGUARD_SDK_H

#include <Windows.h>

#pragma comment(linker, "/ALIGN:0x10000")
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:_TLS_CALLBACK")

VOID WINAPI Tls_Callback(PVOID, DWORD, PVOID);
VOID MemoryCheck(HANDLE);
VOID CRCCheck();

EXTERN_C
#pragma const_seg (".CRT$XLB")
const

PIMAGE_TLS_CALLBACK _TLS_CALLBACK = Tls_Callback;
#pragma data_seg ()
#pragma const_seg ()

#endif