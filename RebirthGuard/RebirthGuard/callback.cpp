
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
#if IS_ENABLED(RG_OPT_THREAD_CHECK)
		CheckThread(GetCurrentThreadStartAddress(), 0);
#endif
	}
}

VOID WINAPI ThreadCallback(PTHREAD_START_ROUTINE proc, PVOID param)
{
	CheckThread(proc, 0x10);

	APICALL(NtTerminateThread_T)(CURRENT_THREAD, proc(param));
}

VOID DebugCallback(PEXCEPTION_POINTERS e)
{
	if (e->ContextRecord->Dr0)
		Report(RG_OPT_ANTI_DEBUGGING, REPORT_DEBUG_HW_BREAKPOINT_0, (PVOID)e->ContextRecord->Dr0, (PVOID)e->ContextRecord->Dr7);
	else if (e->ContextRecord->Dr1)
		Report(RG_OPT_ANTI_DEBUGGING, REPORT_DEBUG_HW_BREAKPOINT_1, (PVOID)e->ContextRecord->Dr1, (PVOID)e->ContextRecord->Dr7);
	else if (e->ContextRecord->Dr2)
		Report(RG_OPT_ANTI_DEBUGGING, REPORT_DEBUG_HW_BREAKPOINT_2, (PVOID)e->ContextRecord->Dr2, (PVOID)e->ContextRecord->Dr7);
	else if (e->ContextRecord->Dr3)
		Report(RG_OPT_ANTI_DEBUGGING, REPORT_DEBUG_HW_BREAKPOINT_3, (PVOID)e->ContextRecord->Dr3, (PVOID)e->ContextRecord->Dr7);

	else if (e->ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT)
		Report(RG_OPT_ANTI_DEBUGGING, REPORT_DEBUG_SW_BREAKPOINT, (PVOID)e->ExceptionRecord->ExceptionAddress, (PVOID)e->ExceptionRecord->ExceptionInformation[1]);

	else if (e->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
		Report(RG_OPT_ANTI_DEBUGGING, REPORT_DEBUG_SINGLE_STEP, (PVOID)e->ExceptionRecord->ExceptionAddress, (PVOID)e->ExceptionRecord->ExceptionInformation[1]);

	else if (e->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
		Report(RG_OPT_ANTI_DEBUGGING, REPORT_DEBUG_PAGE_GUARD, (PVOID)e->ExceptionRecord->ExceptionAddress, (PVOID)e->ExceptionRecord->ExceptionInformation[1]);
}

VOID CALLBACK DllCallback(ULONG reason, PLDR_DLL_NOTIFICATION_DATA data, PVOID context)
{
#if IS_ENABLED(RG_OPT_REBIRTH_ALL_MODULES)
#ifdef _WIN64 // unstable in x86 yet.
	if (reason == LDR_DLL_NOTIFICATION_REASON_LOADED)
		RebirthModule(NULL, data->Loaded.DllBase);
#endif
#endif

	return;
}
