
/*
	chztbby::RebirthGuard/RebirthGuard.h
*/

#ifndef REBIRTHGUARD_H
#define REBIRTHGUARD_H

#include <windows.h>
#include <psapi.h>
#include <time.h>
#include <stdio.h>
#include "ntstruct.h"
#include "RGString.h"
#include "options.h"

#define RG_MAGIC_0 0x20170408
#define RG_MAGIC_1 0x12345678
#define RG_MAGIC_2 0x87654321
#define RG_DATA_SIZE 0x10000
#define MODULE_FIRST 0
#define MODULE_EXE 0
#define MODULE_NTDLL 1
#define MODULE_KERNEL32 2
#define MODULE_KERNELBASE 3
#define MODULE_LAST 3
#define PADDING(p, size) ((SIZE_T)((SIZE_T)(p) / (SIZE_T)(size) * (SIZE_T)(size) + ((SIZE_T)(p) % (SIZE_T)(size) ? (SIZE_T)(size) : 0)))
#define GetPtr(base, offset) ((PVOID)((SIZE_T)(base) + (SIZE_T)(offset)))
#define GetOffset(src, dst) ((SIZE_T)((SIZE_T)(dst) - (SIZE_T)(src)))
#define GetNtHeader(base) ((PIMAGE_NT_HEADERS)((SIZE_T)(base) + (SIZE_T)((PIMAGE_DOS_HEADER)(base))->e_lfanew))
#define TO_STRING(param) #param
#define APICALL(api_name) ((decltype(&api_name))RG_GetApi(RGS(TO_STRING(api_name))))
#define APICALL_FROM_MODULE(index, api_name) ((decltype(&api_name))RG_GetApi(RGS(TO_STRING(api_name)), index))
#define IS_ENABLED(OPTION) (OPTION & RG_ENABLE)
#define PAGE_SIZE 0x1000
#define ALLOCATION_GRANULARITY 0x10000
#define CURRENT_PROCESS ((HANDLE)-1)
#define CURRENT_THREAD ((HANDLE)-2)
#ifdef _WIN64
#define MEMORY_END 0x7FFFFFFF0000
#else
#define MEMORY_END 0x7FFF0000
#endif

typedef struct _REBIRTHED_MODULE_INFO
{
	PVOID module_base;
	HANDLE section;
} REBIRTHED_MODULE_INFO, *PREBIRTHED_MODULE_INFO;

typedef struct _RG_DATA
{
	SIZE_T magic[3];
	REBIRTHED_MODULE_INFO rmi[RG_DATA_SIZE - sizeof(SIZE_T)*3];
} RG_DATA, *PRG_DATA;

extern PRG_DATA rgdata;

typedef struct _MAP_INFO
{
	decltype(&NtMapViewOfSection) pNtMapViewOfSection;
	decltype(&NtLockVirtualMemory) pNtLockVirtualMemory;
	decltype(&NtQueryInformationProcess) pNtQueryInformationProcess;
	decltype(&RtlAcquirePrivilege) pRtlAcquirePrivilege;
	decltype(&NtSetInformationProcess) pNtSetInformationProcess;
	decltype(&RtlReleasePrivilege) pRtlReleasePrivilege;

	PVOID base;
	HANDLE hsection;
	PIMAGE_NT_HEADERS nt;

	SIZE_T chunk_offset;
	SIZE_T chunk_size;
	DWORD chunk_Characteristics;
} MAP_INFO, * PMAP_INFO;

enum RG_REPORT_CODE
{
	REPORT_UNKNOWN,
	REPORT_THREAD_START_ADDRESS,
	REPORT_THREAD_PROTECTION,
	REPORT_DLL_INJECTION_KERNEL32_LoadLibraryA,
	REPORT_DLL_INJECTION_KERNEL32_LoadLibraryW,
	REPORT_DLL_INJECTION_KERNEL32_LoadLibraryExA,
	REPORT_DLL_INJECTION_KERNEL32_LoadLibraryExW,
	REPORT_DLL_INJECTION_KERNELBASE_LoadLibraryA,
	REPORT_DLL_INJECTION_KERNELBASE_LoadLibraryW,
	REPORT_DLL_INJECTION_KERNELBASE_LoadLibraryExA,
	REPORT_DLL_INJECTION_KERNELBASE_LoadLibraryExW,
	REPORT_DLL_INJECTION_NTDLL_LdrLoadDll,
	REPORT_MEMORY_SUSPICIOUS,
	REPORT_MEMORY_UNLOCKED,
	REPORT_INTEGRITY_SECTION_CHECK,
	REPORT_INTEGRITY_CRC64_CHECK,
	REPORT_INVALID_APICALL,
	REPORT_DEBUG_HW_BREAKPOINT_0,
	REPORT_DEBUG_HW_BREAKPOINT_1,
	REPORT_DEBUG_HW_BREAKPOINT_2,
	REPORT_DEBUG_HW_BREAKPOINT_3,
	REPORT_DEBUG_SW_BREAKPOINT,
	REPORT_DEBUG_SINGLE_STEP,
	REPORT_DEBUG_PAGE_GUARD,
};

enum PE_TYPE
{
	PE_TYPE_FILE,
	PE_TYPE_IMAGE
};

enum THREAD_CHECK
{
	TC_TlsCallback,
	TC_ThreadCallback,
	TC_DllCallback
};

enum PTR_CHECK
{
	PC_EXECUTABLE,
	PC_IMAGE_SIZE
};

// RebirthGuard.cpp
VOID RG_Initialze(PVOID hmodule);
PRG_DATA RG_GetGlobalData();
VOID Rebirth(PVOID hmodule);
VOID RebirthModules(PVOID hmodule);
BOOL CheckProcessPolicy();
VOID RestartProcess();

// util.cpp
LPWSTR RG_GetModulePath(DWORD module_index);
LPCWSTR RG_GetModulePath(PVOID hmodule);
PVOID RG_GetNextModule(PLDR_MODULE pmodule_info);
VOID RG_HideModule(PVOID hmodule);
PVOID RG_GetApi(LPCSTR api_name, DWORD module_index = 0);
HMODULE RG_GetModuleHandleW(LPCWSTR module_path);
PVOID RG_GetProcAddress(HMODULE hmodule, LPCSTR proc_name);
HANDLE RG_CreateThread(HANDLE process, PVOID entry, PVOID param);
PVOID RG_AllocMemory(PVOID ptr, SIZE_T size, DWORD protect);
VOID RG_FreeMemory(PVOID ptr);
DWORD RG_ProtectMemory(PVOID ptr, SIZE_T size, DWORD protect);
NTSTATUS RG_QueryMemory(PVOID ptr, PVOID buffer, SIZE_T buffer_size, MEMORY_INFORMATION_CLASS type);
LONG WINAPI RG_ExceptionHandler(PEXCEPTION_POINTERS e);
VOID RG_SetCallbacks();
BOOL IsExe(PVOID hmodule);
PVOID GetCurrentThreadStartAddress();
VOID CopyPeData(PVOID dst, PVOID src, PE_TYPE src_type);

// log.cpp
VOID RG_DebugLog(LPCWSTR format, ...);
VOID RG_Report(DWORD flag, RG_REPORT_CODE code, PVOID data1, PVOID data2);

// mapping.cpp
VOID RebirthModule(PVOID hmodule, PVOID module_base);
PVOID LoadFile(PVOID module_base);
PVOID ManualMap(PVOID module_base);
VOID ExtendWorkingSet(PMAP_INFO info);
VOID AddRebirthedModule(PVOID module_base, HANDLE section);
VOID MapAllSections(PMAP_INFO info);
VOID MapChunk(PMAP_INFO info, SIZE_T offset, SIZE_T size, DWORD chr);
DWORD GetProtection(DWORD chr);
DWORD GetNoChange(DWORD chr);

// verifying.cpp
BOOL IsRebirthed(PVOID module_base);
PVOID GetModuleBaseFromPtr(PVOID ptr, PTR_CHECK type);
BOOL IsSameFunction(PVOID f1, PVOID f2);
VOID CheckThread(PVOID start_address, THREAD_CHECK type);
VOID CheckMemory();
VOID CheckCRC();

// callback.cpp
VOID WINAPI RG_TlsCallback(PVOID dllhandle, DWORD reason, PVOID reserved);
VOID WINAPI ThreadCallback(PTHREAD_START_ROUTINE proc, PVOID param);
VOID DebugCallback(PEXCEPTION_POINTERS e);
VOID CALLBACK DllCallback(ULONG notification_reason, PLDR_DLL_NOTIFICATION_DATA notification_data, PVOID context);

// crypto.cpp
DWORD64 CRC64(PVOID module_base);

// string.cpp
INT RG_strcmp(LPCSTR p1, LPCSTR p2);
LPSTR RG_strcat(LPSTR s1, LPCSTR s2);
LPCWSTR RG_wcsistr(LPCWSTR s1, LPCWSTR s2);
LPWSTR RG_wcscpy(LPWSTR s1, LPCWSTR s2);
LPWSTR RG_wcscat(LPWSTR s1, LPCWSTR s2);

#endif