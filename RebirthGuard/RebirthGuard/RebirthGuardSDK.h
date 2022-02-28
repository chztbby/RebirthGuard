
/*
	chztbby::RebirthGuard/RebirthGuardSDK.h
*/

#ifndef REBIRTHGUARD_SDK_H
#define REBIRTHGUARD_SDK_H

#include <Windows.h>
#include "RGString.h"

#pragma comment(linker, "/ALIGN:0x10000")
#pragma check_stack(off)

VOID WINAPI RG_TlsCallback(PVOID, DWORD, PVOID);

#ifdef _WIN64
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback")
#else
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:__tls_callback")
#endif
EXTERN_C
#ifdef _WIN64
#pragma const_seg (".CRT$XLB")
const
#else
#pragma data_seg (".CRT$XLB")
#endif

PIMAGE_TLS_CALLBACK _tls_callback = RG_TlsCallback;
#pragma data_seg ()
#pragma const_seg ()

#endif