
/*
	chztbby::RebirthGuard/callback.cpp
*/

#include "RebirthGuard.h"


VOID WINAPI Tls_Callback(PVOID DllHandle, DWORD dwReason, PVOID Reserved)
{
	PVOID start_address = NULL;
	((NtQueryInformationThread_T)ApiCall(ntdll, API_NtQueryInformationThread))(CURRENT_THREAD, ThreadQuerySetWin32StartAddress, &start_address, sizeof(start_address), 0);

	ThreadCheck(start_address, 0);

	if (dwReason == DLL_PROCESS_ATTACH && start_address != RG_RegisterCallbacks)
		RG_Initialze();

#if RG_OPT_HIDE_MODULE_LIST & RG_ENABLE
	static BOOL hidemodule = TRUE;
	if (dwReason == DLL_THREAD_ATTACH && hidemodule && IsRebirthed(CURRENT_PROCESS, RG_GetModuleHandleEx(CURRENT_PROCESS, NULL)))
	{
		hidemodule = FALSE;

		LDR_DATA_TABLE_ENTRY list;
		*(PVOID*)&list = 0;
		while (GetNextModule(CURRENT_PROCESS, &list) && list.DllBase)
			HideModule();
	}
#endif

#if RG_OPT_MEMORY_CHECK & RG_ENABLE
	if (dwReason == DLL_THREAD_ATTACH)
		DestoryModule(CURRENT_PROCESS);
#endif
}

VOID WINAPI Thread_Callback(PTHREAD_START_ROUTINE proc, PVOID param)
{
	ThreadCheck(proc, 0x10);

	((NtTerminateThread_T)ApiCall(ntdll, API_NtTerminateThread))(CURRENT_THREAD, proc(param));
}

LONG WINAPI Exception_Callback(PEXCEPTION_POINTERS e)
{
#if RG_OPT_ANTI_DEBUGGING & RG_ENABLE
	if (e->ContextRecord->Dr0)
		Report(CURRENT_PROCESS, RG_OPT_ANTI_DEBUGGING, REPORT_EXCEPTION_HARDWARE_BREAKPOINT, (PVOID)e->ContextRecord->Dr0, (PVOID)e->ContextRecord->Dr7);
	else if (e->ContextRecord->Dr1)
		Report(CURRENT_PROCESS, RG_OPT_ANTI_DEBUGGING, REPORT_EXCEPTION_HARDWARE_BREAKPOINT, (PVOID)e->ContextRecord->Dr1, (PVOID)e->ContextRecord->Dr7);
	else if (e->ContextRecord->Dr2)
		Report(CURRENT_PROCESS, RG_OPT_ANTI_DEBUGGING, REPORT_EXCEPTION_HARDWARE_BREAKPOINT, (PVOID)e->ContextRecord->Dr2, (PVOID)e->ContextRecord->Dr7);
	else if (e->ContextRecord->Dr3)
		Report(CURRENT_PROCESS, RG_OPT_ANTI_DEBUGGING, REPORT_EXCEPTION_HARDWARE_BREAKPOINT, (PVOID)e->ContextRecord->Dr3, (PVOID)e->ContextRecord->Dr7);

	else if (e->ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT)
		Report(CURRENT_PROCESS, RG_OPT_ANTI_DEBUGGING, REPORT_EXCEPTION_DEBUG, (PVOID)e->ExceptionRecord->ExceptionAddress, (PVOID)e->ExceptionRecord->ExceptionInformation[1]);

	else if (e->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
		Report(CURRENT_PROCESS, RG_OPT_ANTI_DEBUGGING, REPORT_EXCEPTION_SINGLE_STEP, (PVOID)e->ExceptionRecord->ExceptionAddress, (PVOID)e->ExceptionRecord->ExceptionInformation[1]);

	else if (e->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
		Report(CURRENT_PROCESS, RG_OPT_ANTI_DEBUGGING, REPORT_EXCEPTION_GUARDED_PAGE, (PVOID)e->ExceptionRecord->ExceptionAddress, (PVOID)e->ExceptionRecord->ExceptionInformation[1]);
#endif

	return EXCEPTION_CONTINUE_SEARCH;
}

VOID CALLBACK DLL_Callback(ULONG notification_reason, CONST PLDR_DLL_NOTIFICATION_DATA notification_data, PVOID context)
{
	if (notification_reason == LDR_DLL_NOTIFICATION_REASON_LOADED)
	{
		DWORD protect = 0;
		SIZE_T size = PAGE_SIZE;
		PVOID ptr = notification_data->Loaded.DllBase;
		((NtProtectVirtualMemory_T)ApiCall(ntdll, API_NtProtectVirtualMemory))(CURRENT_PROCESS, &ptr, &size, PAGE_WRITECOPY, &protect);
		RebirthModule(CURRENT_PROCESS, notification_data->Loaded.FullDllName->Buffer);
	}

	return;
}
