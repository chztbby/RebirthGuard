
/*
	chztbby::RebirthGuard/callback.cpp
*/

#include "RebirthGuard.h"


VOID WINAPI RG_TlsCallback(PVOID hmodule, DWORD reason, PVOID reserved)
{
	if (reason == DLL_PROCESS_ATTACH)
		RG_Initialze(hmodule);

	if (reason == DLL_THREAD_ATTACH)
	{
#if RG_OPT_HIDE_MODULES & RG_ENABLE
		HideModules();
#endif
#if RG_OPT_THREAD_CHECK & RG_ENABLE
		CheckThread(GetCurrentThreadStartAddress(), 0);
#endif
	}
}

VOID WINAPI ThreadCallback(PTHREAD_START_ROUTINE proc, PVOID param)
{
	CheckThread(proc, 0x10);

	APICALL(NtTerminateThread_T)(CURRENT_THREAD, proc(param));
}

LONG WINAPI DebugCallback(PEXCEPTION_POINTERS e)
{
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

	return EXCEPTION_CONTINUE_SEARCH;
}

VOID CALLBACK DllCallback(ULONG notification_reason, PVOID notification_data, PVOID context)
{
#if RG_OPT_HIDE_MODULES & RG_ENABLE
	if (notification_reason == LDR_DLL_NOTIFICATION_REASON_LOADED)
		HideModules();
#endif
	return;
}
