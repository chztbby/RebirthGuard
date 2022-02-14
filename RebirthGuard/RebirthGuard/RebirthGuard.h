
/*
	chztbby::RebirthGuard/RebirthGuard.h
*/

#ifndef REBIRTHGUARD_H
#define REBIRTHGUARD_H

#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <time.h>
#include <stdio.h>
#include "options.h"

#define REBIRTHED_MODULE_LIST_PTR 0x10000
#define REBIRTHED_MODULE_LIST_SIZE 0x1000
#define XOR_KEY 0xAD
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
#define APICALL(api) ((api)GetApi(API_##api))
#define IS_ENABLED(OPTION) (OPTION & RG_ENABLE)

#define SEC_NO_CHANGE 0x00400000
#define STATUS_INVALID_PAGE_PROTECTION 0xC0000045
#define STATUS_WORKING_SET_QUOTA 0xC00000A1
#define PAGE_SIZE 0x1000
#define ALLOCATION_GRANULARITY 0x10000
#define ViewUnmap 2
#define CURRENT_PROCESS ((HANDLE)-1)
#define CURRENT_THREAD ((HANDLE)-2)
#define LDR_DLL_NOTIFICATION_REASON_LOADED 1
#define	MemoryBasicInformation 0
#define	MemoryWorkingSetExList 4
#define ProcessQuotaLimits 1
#define ThreadQuerySetWin32StartAddress 9
#define	ThreadHideFromDebugger 0x11
#define SE_AUDIT_PRIVILEGE 0x21
#define VM_LOCK_1 0x0001

typedef NTSTATUS (NTAPI* NtCreateSection_T) (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS (NTAPI* NtMapViewOfSection_T) (HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
typedef NTSTATUS (NTAPI* NtUnmapViewOfSection_T) (HANDLE, PVOID);
typedef NTSTATUS (NTAPI* NtProtectVirtualMemory_T) (HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI* NtQueryVirtualMemory_T) (HANDLE, PVOID, DWORD, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI* NtLockVirtualMemory_T) (HANDLE, PVOID, PSIZE_T, ULONG);
typedef NTSTATUS (NTAPI* NtReadVirtualMemory_T) (HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI* NtWriteVirtualMemory_T) (HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI* NtAllocateVirtualMemory_T) (HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI* NtFreeVirtualMemory_T) (HANDLE, PVOID*, PSIZE_T, ULONG);
typedef NTSTATUS (NTAPI* NtResumeProcess_T) (HANDLE);
typedef NTSTATUS (NTAPI* NtQueryInformationProcess_T) (HANDLE, DWORD, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI* NtQueryInformationThread_T) (HANDLE, DWORD, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI* NtSetInformationProcess_T) (HANDLE, DWORD, PVOID, ULONG);
typedef NTSTATUS (NTAPI* NtSetInformationThread_T) (HANDLE, DWORD, PVOID, ULONG);
typedef NTSTATUS (NTAPI* RtlAcquirePrivilege_T) (PULONG, ULONG, ULONG, PVOID*);
typedef NTSTATUS (NTAPI* RtlReleasePrivilege_T) (PVOID);
typedef NTSTATUS (NTAPI* RtlUserThreadStart_T) (PTHREAD_START_ROUTINE, PVOID);
typedef NTSTATUS (NTAPI* NtCreateThreadEx_T) (PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS (NTAPI* NtTerminateProcess_T) (HANDLE, NTSTATUS);
typedef NTSTATUS (NTAPI* NtTerminateThread_T) (HANDLE, NTSTATUS);
typedef NTSTATUS (NTAPI* RtlAddVectoredExceptionHandler_T) (ULONG, PVECTORED_EXCEPTION_HANDLER);
typedef NTSTATUS (NTAPI* LdrRegisterDllNotification_T) (ULONG, PVOID, PVOID, PVOID);
typedef HMODULE	 (WINAPI* LoadLibraryW_T) (LPCWSTR);
typedef BOOL (WINAPI* CreateProcessW_T) (LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef HANDLE (WINAPI* CreateFileW_T) (LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL  (WINAPI* ReadFile_T) (HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef UINT (WINAPI* WinExec_T) (LPCSTR, UINT);

typedef struct _REBIRTHED_MODULE_INFO
{
	PVOID module_base;
	HANDLE section;
} REBIRTHED_MODULE_INFO, *PREBIRTHED_MODULE_INFO;

static REBIRTHED_MODULE_INFO* rebirthed_module_list = (REBIRTHED_MODULE_INFO*)REBIRTHED_MODULE_LIST_PTR;

typedef struct _MAP_INFO
{
	NtMapViewOfSection_T pNtMapViewOfSection;
	NtLockVirtualMemory_T pNtLockVirtualMemory;

	PVOID base;
	HANDLE hsection;
	PIMAGE_NT_HEADERS nt;

	SIZE_T chunk_offset;
	SIZE_T chunk_size;
	DWORD chunk_Characteristics;
} MAP_INFO, * PMAP_INFO;

typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA 
{
	ULONG Flags;
	PCUNICODE_STRING FullDllName;
	PCUNICODE_STRING BaseDllName;
	PVOID DllBase;
	ULONG SizeOfImage;
} LDR_DLL_LOADED_NOTIFICATION_DATA, * PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA
{
	ULONG Flags;
	PCUNICODE_STRING FullDllName;
	PCUNICODE_STRING BaseDllName;
	PVOID DllBase;
	ULONG SizeOfImage;
} LDR_DLL_UNLOADED_NOTIFICATION_DATA, * PLDR_DLL_UNLOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA
{
	LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
	LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
} LDR_DLL_NOTIFICATION_DATA, * PLDR_DLL_NOTIFICATION_DATA;

typedef struct _PEB_LDR_DATA_
{
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA_, *PPEB_LDR_DATA_;

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
	REPORT_MEMORY_IMAGE,
	REPORT_MEMORY_PRIVATE_EXECUTE,
	REPORT_MEMORY_NOT_REBIRTHED,
	REPORT_MEMORY_EXECUTE_WRITE,
	REPORT_MEMORY_UNLOCKED,
	REPORT_MEMORY_UNLOCKED2,
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

enum API_INDEX
{
	API_NtCreateSection_T,
	API_NtMapViewOfSection_T,
	API_NtUnmapViewOfSection_T,
	API_NtProtectVirtualMemory_T,
	API_NtQueryVirtualMemory_T,
	API_NtLockVirtualMemory_T,
	API_NtReadVirtualMemory_T,
	API_NtWriteVirtualMemory_T,
	API_NtAllocateVirtualMemory_T,
	API_NtFreeVirtualMemory_T,
	API_NtTerminateProcess_T,
	API_NtResumeProcess_T,
	API_NtQueryInformationProcess_T,
	API_NtSetInformationProcess_T,
	API_RtlUserThreadStart_T,
	API_NtCreateThreadEx_T,
	API_NtTerminateThread_T,
	API_NtQueryInformationThread_T,
	API_NtSetInformationThread_T,
	API_RtlAcquirePrivilege_T,
	API_RtlReleasePrivilege_T,
	API_RtlAddVectoredExceptionHandler_T,
	API_LdrRegisterDllNotification_T,
	API_LoadLibraryA_T,
	API_LoadLibraryW_T,
	API_LoadLibraryExA_T,
	API_LoadLibraryExW_T,
	API_LdrLoadDll_T,
	API_CreateProcessW_T,
	API_CreateFileW_T,
	API_ReadFile_T,
	API_WinExec_T,
};

enum PE_TYPE
{
	PE_FILE,
	PE_MEMORY
};

// main.cpp
VOID RG_Initialze(PVOID hmodule);
DWORD WINAPI RG_InitialzeWorker(LPVOID hmodule);
VOID Rebirth(PVOID hmodule);
VOID RebirthAll(PVOID hmodule);
BOOL CheckProcessPolicy();
VOID SetProcessPolicy();

// function.cpp
BOOL IsExe(PVOID hmodule);
PVOID GetCurrentThreadStartAddress();
LPWSTR GetModulePath(DWORD module_index);
PVOID GetNextModule(PLDR_DATA_TABLE_ENTRY plist);
VOID HideModule(PVOID hmodule);
HMODULE RG_GetModuleHandleW(LPCWSTR module_path);
FARPROC GetApi(API_INDEX api_index);
FARPROC GetApi(DWORD module_index, API_INDEX api_index);
VOID RG_DebugLog(LPCWSTR format, ...);
VOID Report(DWORD flag, RG_REPORT_CODE code, PVOID data1, PVOID data2);
VOID CopyPeData(PVOID dst, PVOID src, PE_TYPE src_type);
PVOID AllocMemory(PVOID ptr, SIZE_T size, DWORD protect);
VOID FreeMemory(PVOID ptr);
DWORD ProtectMemory(PVOID ptr, SIZE_T size, DWORD protect);
VOID QueryMemory(PVOID ptr, PVOID buffer, SIZE_T buffer_size, DWORD type);
HANDLE RG_CreateThread(PVOID entry, PVOID param);
VOID RG_SetCallbacks();

// mapping.cpp
PVOID LoadFile(PVOID module_base);
PVOID ManualMap(PVOID module_base);
VOID ExtendWorkingSet();
VOID AddRebirthedModule(PVOID module_base, HANDLE section);
VOID RebirthModule(PVOID hmodule, PVOID module_base);

// verifying.cpp
BOOL IsRebirthed(PVOID module_base);
PVOID IsInModule(PVOID ptr, DWORD type);
BOOL IsSameFunction(PVOID f1, PVOID f2);
VOID CheckThread(PVOID start_address, DWORD type);
VOID CheckFullMemory();
VOID CheckMemory(PVOID ptr);
VOID CheckCRC();

// callback.cpp
VOID WINAPI RG_TlsCallback(PVOID dllhandle, DWORD reason, PVOID reserved);
VOID WINAPI ThreadCallback(PTHREAD_START_ROUTINE proc, PVOID param);
VOID DebugCallback(PEXCEPTION_POINTERS e);
VOID CALLBACK DllCallback(ULONG notification_reason, PLDR_DLL_NOTIFICATION_DATA notification_data, PVOID context);

// crypto.cpp
VOID DecryptXOR(CHAR* buffer, DWORD api_index);
DWORD64 CRC64(PVOID module_base);

// string.cpp
LPSTR RG_strcat(LPSTR s1, LPCSTR s2);
LPCWSTR RG_wcsistr(LPCWSTR s1, LPCWSTR s2);
LPWSTR RG_wcscpy(LPWSTR s1, LPCWSTR s2);
LPWSTR RG_wcscat(LPWSTR s1, LPCWSTR s2);

#endif