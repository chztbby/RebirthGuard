
/*
	chztbby::RebirthGuard/ntstruct.h
*/

#ifndef NTSTRUCT_H
#define NTSTRUCT_H

#include <windows.h>

#define SEC_NO_CHANGE 0x00400000
#define STATUS_INVALID_PAGE_PROTECTION 0xC0000045
#define STATUS_WORKING_SET_QUOTA 0xC00000A1
#define LDR_DLL_NOTIFICATION_REASON_LOADED 1
#define SE_AUDIT_PRIVILEGE 0x21
#define VM_LOCK_1 0x0001

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef enum _SECTION_INHERIT
{
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;

typedef enum _MEMORY_INFORMATION_CLASS
{
    MemoryBasicInformation,
    MemoryWorkingSetInformation,
    MemoryMappedFilenameInformation,
    MemoryRegionInformation,
    MemoryWorkingSetExInformation,
    //...
} MEMORY_INFORMATION_CLASS;

typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation,
	ProcessQuotaLimits,
	//...
} PROCESSINFOCLASS, *PPROCESSINFOCLASS;

typedef enum _THREADINFOCLASS
{
	ThreadBasicInformation,
	ThreadTimes,
	ThreadPriority,
	ThreadBasePriority,
	ThreadAffinityMask,
	ThreadImpersonationToken,
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup,
	ThreadEventPair,
	ThreadQuerySetWin32StartAddress,
	ThreadZeroTlsCell,
	ThreadPerformanceCount,
	ThreadAmILastThread,
	ThreadIdealProcessor,
	ThreadPriorityBoost,
	ThreadSetTlsArrayAddress,
	ThreadIsIoPending,
	ThreadHideFromDebugger
} THREADINFOCLASS, *PTHREADINFOCLASS;

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA
{
	ULONG Flags;
	PCUNICODE_STRING FullDllName;
	PCUNICODE_STRING BaseDllName;
	PVOID DllBase;
	ULONG SizeOfImage;
} LDR_DLL_LOADED_NOTIFICATION_DATA, *PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA
{
	ULONG Flags;
	PCUNICODE_STRING FullDllName;
	PCUNICODE_STRING BaseDllName;
	PVOID DllBase;
	ULONG SizeOfImage;
} LDR_DLL_UNLOADED_NOTIFICATION_DATA, *PLDR_DLL_UNLOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA
{
	LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
	LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
} LDR_DLL_NOTIFICATION_DATA, *PLDR_DLL_NOTIFICATION_DATA;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_MODULE
{
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	HMODULE BaseAddress;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	// ...
} LDR_MODULE, *PLDR_MODULE;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID;

typedef struct _PEB
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	BOOLEAN Spare;
	HANDLE Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA LoaderData;
	PVOID ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID FastPebLockRoutine;
	PVOID FastPebUnlockRoutine;
	ULONG EnvironmentUpdateCount;
	PVOID KernelCallbackTable;
	PVOID EventLogSection;
	PVOID EventLog;
	PVOID FreeList;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[0x2];
	PVOID ReadOnlySharedMemoryBase;
	PVOID ReadOnlySharedMemoryHeap;
	PVOID* ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;
	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;
	BYTE Spare2[0x4];
	LARGE_INTEGER CriticalSectionTimeout;
	ULONG HeapSegmentReserve;
	ULONG HeapSegmentCommit;
	ULONG HeapDeCommitTotalFreeThreshold;
	ULONG HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID* ProcessHeaps;
	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	PVOID GdiDCAttributeList;
	PVOID LoaderLock;
	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	ULONG OSBuildNumber;
	ULONG OSPlatformId;
	ULONG ImageSubSystem;
	ULONG ImageSubSystemMajorVersion;
	ULONG ImageSubSystemMinorVersion;
	ULONG GdiHandleBuffer[0x22];
	ULONG PostProcessInitRoutine;
	ULONG TlsExpansionBitmap;
	BYTE TlsExpansionBitmapBits[0x80];
	ULONG SessionId;
} PEB, *PPEB;

typedef struct _TEB
{
	NT_TIB Tib;
	PVOID EnvironmentPointer;
	CLIENT_ID Cid;
	PVOID ActiveRpcInfo;
	PVOID ThreadLocalStoragePointer;
	PPEB Peb;
	ULONG LastErrorValue;
	ULONG CountOfOwnedCriticalSections;
	PVOID CsrClientThread;
	PVOID Win32ThreadInfo;
	ULONG Win32ClientInfo[0x1F];
	PVOID WOW32Reserved;
	ULONG CurrentLocale;
	ULONG FpSoftwareStatusRegister;
	PVOID SystemReserved1[0x36];
	PVOID Spare1;
	ULONG ExceptionCode;
	ULONG SpareBytes1[0x28];
	PVOID SystemReserved2[0xA];
	ULONG GdiRgn;
	ULONG GdiPen;
	ULONG GdiBrush;
	CLIENT_ID RealClientId;
	PVOID GdiCachedProcessHandle;
	ULONG GdiClientPID;
	ULONG GdiClientTID;
	PVOID GdiThreadLocaleInfo;
	PVOID UserReserved[5];
	PVOID GlDispatchTable[0x118];
	ULONG GlReserved1[0x1A];
	PVOID GlReserved2;
	PVOID GlSectionInfo;
	PVOID GlSection;
	PVOID GlTable;
	PVOID GlCurrentRC;
	PVOID GlContext;
	NTSTATUS LastStatusValue;
	UNICODE_STRING StaticUnicodeString;
	WCHAR StaticUnicodeBuffer[0x105];
	PVOID DeallocationStack;
	PVOID TlsSlots[0x40];
	LIST_ENTRY TlsLinks;
	PVOID Vdm;
	PVOID ReservedForNtRpc;
	PVOID DbgSsReserved[0x2];
	ULONG HardErrorDisabled;
	PVOID Instrumentation[0x10];
	PVOID WinSockData;
	ULONG GdiBatchCount;
	ULONG Spare2;
	ULONG Spare3;
	ULONG Spare4;
	PVOID ReservedForOle;
	ULONG WaitingOnLoaderLock;
	PVOID StackCommit;
	PVOID StackCommitMax;
	PVOID StackReserved;
} TEB, *PTEB;

NTSTATUS NTAPI NtCreateSection(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
NTSTATUS NTAPI NtMapViewOfSection(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);
NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);
NTSTATUS NTAPI NtProtectVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
NTSTATUS NTAPI NtQueryVirtualMemory(HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T);
NTSTATUS NTAPI NtLockVirtualMemory(HANDLE, PVOID, PSIZE_T, ULONG);
NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
NTSTATUS NTAPI NtAllocateVirtualMemory(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
NTSTATUS NTAPI NtFreeVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG);
NTSTATUS NTAPI NtResumeProcess(HANDLE);
NTSTATUS NTAPI NtQueryInformationProcess(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
NTSTATUS NTAPI NtQueryInformationThread(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
NTSTATUS NTAPI NtSetInformationProcess(HANDLE, PROCESSINFOCLASS, PVOID, ULONG);
NTSTATUS NTAPI NtSetInformationThread(HANDLE, THREADINFOCLASS, PVOID, ULONG);
NTSTATUS NTAPI RtlAcquirePrivilege(PULONG, ULONG, ULONG, PVOID*);
NTSTATUS NTAPI RtlReleasePrivilege(PVOID);
NTSTATUS NTAPI RtlUserThreadStart(PTHREAD_START_ROUTINE, PVOID);
NTSTATUS NTAPI NtCreateThreadEx(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);
NTSTATUS NTAPI NtTerminateThread(HANDLE, NTSTATUS);
NTSTATUS NTAPI NtClose(HANDLE);
NTSTATUS NTAPI RtlAddVectoredExceptionHandler(ULONG, PVECTORED_EXCEPTION_HANDLER);
NTSTATUS NTAPI LdrRegisterDllNotification(ULONG, PVOID, PVOID, PVOID);
NTSTATUS NTAPI LdrLoadDll(PWCHAR, ULONG, PUNICODE_STRING, PHANDLE);

#endif