
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

#define SECTION_LIST_PTR 0x010000000000
#define MAX_SECTION_LIST_SIZE 0x10000
#define XOR_KEY 0xAD
#define EXE 0
#define ntdll 1
#define kernel32 2
#define kernelbase 3
#define PADDING(p, size) (p / size * size + (p % size ? size : 0))
#define GetPtr(base, offset) ((PVOID)((SIZE_T)(base) + (SIZE_T)(offset)))
#define GetOffset(src, dst) ((SIZE_T)((SIZE_T)(dst) - (SIZE_T)(src)))
#define GetNtHeader(base) ((PIMAGE_NT_HEADERS)((SIZE_T)base + (SIZE_T)((PIMAGE_DOS_HEADER)base)->e_lfanew))

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
typedef NTSTATUS (NTAPI* NtCreateThreadEx_T) (PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS (NTAPI* NtTerminateProcess_T) (HANDLE, NTSTATUS);
typedef NTSTATUS (NTAPI* NtTerminateThread_T) (HANDLE, NTSTATUS);
typedef NTSTATUS (NTAPI* RtlAddVectoredExceptionHandler_T) (ULONG, PVECTORED_EXCEPTION_HANDLER);
typedef NTSTATUS (NTAPI* LdrRegisterDllNotification_T) (ULONG, PVOID, PVOID, PVOID);
typedef NTSTATUS (NTAPI* NtDuplicateObject_T) (HANDLE, HANDLE, HANDLE, PHANDLE, DWORD, ULONG, ULONG);
typedef HMODULE	 (WINAPI* LoadLibraryW_T) (LPCWSTR);
typedef BOOL (WINAPI* CreateProcessW_T) (LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef HANDLE (WINAPI* CreateFileW_T) (LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL  (WINAPI* ReadFile_T) (HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef UINT (WINAPI* WinExec_T) (LPCSTR, UINT);

typedef struct _RG_SECTION_INFO
{
	HANDLE section;
	PVOID base;
} RG_SECTION_INFO, *PRG_SECTION_INFO;

static RG_SECTION_INFO* section_list = (RG_SECTION_INFO*)SECTION_LIST_PTR;

typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA
{
	ULONG Flags;
	PUNICODE_STRING FullDllName;
	PUNICODE_STRING BaseDllName;
	PVOID DllBase;
	ULONG SizeOfImage;
} LDR_DLL_LOADED_NOTIFICATION_DATA, *PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA
{
	ULONG Flags;
	PUNICODE_STRING FullDllName;
	PUNICODE_STRING BaseDllName;
	PVOID DllBase;
	ULONG SizeOfImage;
} LDR_DLL_UNLOADED_NOTIFICATION_DATA, *PLDR_DLL_UNLOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA
{
	LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
	LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
} LDR_DLL_NOTIFICATION_DATA, *PLDR_DLL_NOTIFICATION_DATA;

typedef struct _PEB_LDR_DATA_
{
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA_, *PPEB_LDR_DATA_;

enum REBIRTHGUARD_REPORT_CODE
{
	REPORT_ALLOC_SECTION_LIST,
	REPORT_THREAD_START_ADDRESS,
	REPORT_THREAD_PROTECTION,
	REPORT_DLL_INJECTION_KERNEL32_LoadLibraryA,
	REPORT_DLL_INJECTION_KERNEL32LoadLibraryW_T,
	REPORT_DLL_INJECTION_KERNEL32_LoadLibraryExA,
	REPORT_DLL_INJECTION_KERNEL32_LoadLibraryExW,
	REPORT_DLL_INJECTION_KERNELBASE_LoadLibraryA,
	REPORT_DLL_INJECTION_KERNELBASELoadLibraryW_T,
	REPORT_DLL_INJECTION_KERNELBASE_LoadLibraryExA,
	REPORT_DLL_INJECTION_KERNELBASE_LoadLibraryExW,
	REPORT_DLL_INJECTION_NTDLL_LdrLoadDll,
	REPORT_MEMORY_IMAGE,
	REPORT_MEMORY_PRIVATE_EXECUTE,
	REPORT_MEMORY_NOT_REBIRTHED,
	REPORT_MEMORY_EXECUTE_WRITE,
	REPORT_MEMORY_UNLOCKED,
	REPORT_MEMORY_UNLOCKED2,
	REPORT_CRC64_SECTION,
	REPORT_CRC64_INTEGRITY,
	REPORT_APICALL_INVALID_MODULE,
	REPORT_APICALL_INVALID_API,
	REPORT_EXCEPTION_HARDWARE_BREAKPOINT,
	REPORT_EXCEPTION_DEBUG,
	REPORT_EXCEPTION_SINGLE_STEP,
	REPORT_EXCEPTION_GUARDED_PAGE,
};

enum API_INDEX
{
	API_NtCreateSection,
	API_NtMapViewOfSection,
	API_NtUnmapViewOfSection,
	API_NtProtectVirtualMemory,
	API_NtQueryVirtualMemory,
	API_NtLockVirtualMemory,
	API_NtReadVirtualMemory,
	API_NtWriteVirtualMemory,
	API_NtAllocateVirtualMemory,
	API_NtFreeVirtualMemory,
	API_NtTerminateProcess,
	API_NtResumeProcess,
	API_NtQueryInformationProcess,
	API_NtSetInformationProcess,
	API_RtlUserThreadStart,
	API_NtCreateThreadEx,
	API_NtTerminateThread,
	API_NtQueryInformationThread,
	API_NtSetInformationThread,
	API_RtlAcquirePrivilege,
	API_RtlReleasePrivilege,
	API_RtlAddVectoredExceptionHandler,
	API_LdrRegisterDllNotification,
	API_NtDuplicateObject,
	API_LoadLibraryA,
	API_LoadLibraryW,
	API_LoadLibraryExA,
	API_LoadLibraryExW,
	API_LdrLoadDll,
	API_CreateProcessW,
	API_CreateFileW,
	API_ReadFile,
	API_WinExec,
};

// main.cpp
VOID RG_RegisterCallbacks();
VOID RG_Initialze();

// function.cpp
PVOID GetPEHeader(HANDLE process, PVOID module_base);
LPWSTR GetModulePath(DWORD module_index);
PVOID GetNextModule(HANDLE process, PLDR_DATA_TABLE_ENTRY plist);
VOID HideModule();
HMODULE RG_GetModuleHandleEx(HANDLE process, LPCWSTR module_path);
FARPROC ApiCall(DWORD module_index, API_INDEX index);
VOID Report(HANDLE process, DWORD flag, REBIRTHGUARD_REPORT_CODE code, PVOID data1, PVOID data2);

// mapping.cpp
PVOID ManualMap(LPCWSTR module_path);
VOID ExtendWorkingSet(HANDLE process);
VOID AddSection(HANDLE process, HANDLE section, PVOID module_base);
VOID RebirthModule(HANDLE process, LPCWSTR module_path);

// verifying.cpp
BOOL IsRebirthed(HANDLE process, PVOID module_base);
PVOID IsInModule(HANDLE process, PVOID ptr, DWORD type);
BOOL IsSameFunction(PVOID f1, PVOID f2);
VOID ThreadCheck(PVOID start_address, DWORD type);
VOID DestoryModule(HANDLE process);
VOID MemoryCheck(HANDLE process);
VOID CRCCheck();

// callback.cpp */
VOID WINAPI Tls_Callback(PVOID DllHandle, DWORD dwReason, PVOID Reserved);
VOID WINAPI Thread_Callback(PTHREAD_START_ROUTINE proc, PVOID param);
LONG WINAPI Exception_Callback(PEXCEPTION_POINTERS e);
VOID CALLBACK DLL_Callback(ULONG notification_reason, CONST PLDR_DLL_NOTIFICATION_DATA notification_data, PVOID context);

// crypto.cpp
VOID DecryptXOR(CHAR* buffer, DWORD api_index);
DWORD64 CRC64(PVOID module_base);

// string.cpp
LPSTR RG_strcat(LPSTR s1, LPCSTR s2);
LPCWSTR RG_wcsistr(LPCWSTR s1, LPCWSTR s2);
LPWSTR RG_wcscpy(LPWSTR s1, LPCWSTR s2);
LPWSTR RG_wcscat(LPWSTR s1, LPCWSTR s2);

#endif