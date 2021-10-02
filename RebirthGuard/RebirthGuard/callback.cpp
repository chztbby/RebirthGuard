
/********************************************
*											*
*	RebirthGuard/callback.cpp - chztbby		*
*											*
********************************************/

#include "RebirthGuard.h"


//-----------------------------------------------------------------
//	TLS Callback
//-----------------------------------------------------------------
VOID TLS_Callback(PVOID DllHandle, DWORD dwReason, PVOID Reserved)
{
	// Query information of thread
	PVOID StartAddress = NULL;
	((_NtQueryInformationThread)APICall(ntdll, APICall_NtQueryInformationThread))(CURRENT_THREAD, ThreadQuerySetWin32StartAddress, &StartAddress, sizeof(StartAddress), 0);

	// Thread check
	ThreadCheck(StartAddress, 0);

	// Initialize RebirthGuard
	if (dwReason == DLL_PROCESS_ATTACH && StartAddress != RegisterCallbacks)
		Initialze();

	// Hide Module
#if HIDE_MODULELIST & ENABLE
	static BOOL hidemodule = TRUE;
	if (dwReason == DLL_THREAD_ATTACH && hidemodule && IsRebirthed(CURRENT_PROCESS, myGetModuleHandleEx(CURRENT_PROCESS, NULL)))
	{
		hidemodule = FALSE;

		LDR_DATA_TABLE_ENTRY List;
		*(DWORD64*)&List = 0;
		while (NextModule(CURRENT_PROCESS, &List) && ((PLDR_DATA_TABLE_ENTRY)*(DWORD64*)&List)->DllBase)
			HideModule();
	}
#endif

	// Check the module is rebirthed
#if MEM_CHECK & ENABLE
	if (dwReason == DLL_THREAD_ATTACH)
		DestoryModule(CURRENT_PROCESS);
#endif
}


//-----------------------------------------------------------------
//	Hooked RtlUserThreadStart to this function
//-----------------------------------------------------------------
VOID Thread_Callback(PTHREAD_START_ROUTINE StartAddress, PVOID Parameter)
{
	// Thread check
	ThreadCheck(StartAddress, 0x10);

	((_NtTerminateThread)APICall(ntdll, APICall_NtTerminateThread))(CURRENT_THREAD, StartAddress(Parameter));
}


//-----------------------------------------------------------------
//	Exception handler
//-----------------------------------------------------------------
LONG WINAPI Exception_Callback(EXCEPTION_POINTERS *pExceptionInfo)
{
	// Anti-Debugging
#if ANTI_DEBUGGING & ENABLE
	// Hardware Breakpoint
	if (pExceptionInfo->ContextRecord->Dr0)
		Report(CURRENT_PROCESS, ANTI_DEBUGGING, EXCEPTION_HardwareBreakpoint, (PVOID)pExceptionInfo->ContextRecord->Dr0, (PVOID)pExceptionInfo->ContextRecord->Dr7);
	else if (pExceptionInfo->ContextRecord->Dr1)
		Report(CURRENT_PROCESS, ANTI_DEBUGGING, EXCEPTION_HardwareBreakpoint, (PVOID)pExceptionInfo->ContextRecord->Dr1, (PVOID)pExceptionInfo->ContextRecord->Dr7);
	else if (pExceptionInfo->ContextRecord->Dr2)
		Report(CURRENT_PROCESS, ANTI_DEBUGGING, EXCEPTION_HardwareBreakpoint, (PVOID)pExceptionInfo->ContextRecord->Dr2, (PVOID)pExceptionInfo->ContextRecord->Dr7);
	else if (pExceptionInfo->ContextRecord->Dr3)
		Report(CURRENT_PROCESS, ANTI_DEBUGGING, EXCEPTION_HardwareBreakpoint, (PVOID)pExceptionInfo->ContextRecord->Dr3, (PVOID)pExceptionInfo->ContextRecord->Dr7);

	// Debug event
	else if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT)
		Report(CURRENT_PROCESS, ANTI_DEBUGGING, EXCEPTION_Debugging, (PVOID)pExceptionInfo->ExceptionRecord->ExceptionAddress, (PVOID)pExceptionInfo->ExceptionRecord->ExceptionInformation[1]);

	// Trap flag is enabled
	else if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
		Report(CURRENT_PROCESS, ANTI_DEBUGGING, EXCEPTION_Single_Step, (PVOID)pExceptionInfo->ExceptionRecord->ExceptionAddress, (PVOID)pExceptionInfo->ExceptionRecord->ExceptionInformation[1]);

	// This page protection is PAGE_GUARD
	else if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
		Report(CURRENT_PROCESS, ANTI_DEBUGGING, EXCEPTION_Guarded_Page, (PVOID)pExceptionInfo->ExceptionRecord->ExceptionAddress, (PVOID)pExceptionInfo->ExceptionRecord->ExceptionInformation[1]);
#endif

	// Exception handling
#if EXCEPTION_HANDLING & ENABLE
	else
		Report(CURRENT_PROCESS, EXCEPTION_HANDLING, (REBIRTHGUARD_REPORT_CODE)pExceptionInfo->ExceptionRecord->ExceptionCode, (PVOID)pExceptionInfo->ExceptionRecord->ExceptionAddress, (PVOID)pExceptionInfo->ExceptionRecord->ExceptionInformation[1]);
#endif

	return EXCEPTION_CONTINUE_SEARCH;
}


//-----------------------------------------------------------------
//	DLL notification callback.
//-----------------------------------------------------------------
VOID DLL_Callback(ULONG notification_reason, CONST LDR_DLL_NOTIFICATION_DATA* notification_data, PVOID context)
{
	if (notification_reason == LDR_DLL_NOTIFICATION_REASON_LOADED)
	{
		DWORD OldProtect = 0;
		DWORD64 Size = PAGE_SIZE;
		PVOID Address = notification_data->Loaded.DllBase;
		((_NtProtectVirtualMemory)APICall(ntdll, APICall_NtProtectVirtualMemory))(CURRENT_PROCESS, &Address, &Size, PAGE_WRITECOPY, &OldProtect);
		RebirthModule(CURRENT_PROCESS, notification_data->Loaded.FullDllName->Buffer);
	}

	return;
}
