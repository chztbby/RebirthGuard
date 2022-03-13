
/*
	chztbby::RebirthGuard/callback.cpp
*/

#include "RebirthGuard.h"


VOID WINAPI RG_TlsCallback(PVOID hmodule, DWORD reason, PVOID reserved)
{
	PVOID entry = GetCurrentThreadStartAddress();

#if IS_ENABLED(RG_OPT_THREAD_CHECK)
	CheckThread(entry, TC_TlsCallback);
#endif

	if (reason == DLL_PROCESS_ATTACH && entry != APICALL(Sleep))
		RG_Initialze(hmodule);

	if (reason == DLL_THREAD_DETACH && entry == APICALL(Sleep))
		RG_Initialze(hmodule);
}

VOID WINAPI ThreadCallback(PTHREAD_START_ROUTINE proc, PVOID param)
{
	CheckThread(proc, TC_ThreadCallback);

	APICALL(NtTerminateThread)(CURRENT_THREAD, proc(param));
}

VOID DebugCallback(PEXCEPTION_POINTERS e)
{
	if (e->ContextRecord->Dr0)
		RG_Report(RG_OPT_ANTI_DEBUGGING, REPORT_DEBUG_HW_BREAKPOINT_0, (PVOID)e->ContextRecord->Dr0, (PVOID)e->ContextRecord->Dr7);
	else if (e->ContextRecord->Dr1)
		RG_Report(RG_OPT_ANTI_DEBUGGING, REPORT_DEBUG_HW_BREAKPOINT_1, (PVOID)e->ContextRecord->Dr1, (PVOID)e->ContextRecord->Dr7);
	else if (e->ContextRecord->Dr2)
		RG_Report(RG_OPT_ANTI_DEBUGGING, REPORT_DEBUG_HW_BREAKPOINT_2, (PVOID)e->ContextRecord->Dr2, (PVOID)e->ContextRecord->Dr7);
	else if (e->ContextRecord->Dr3)
		RG_Report(RG_OPT_ANTI_DEBUGGING, REPORT_DEBUG_HW_BREAKPOINT_3, (PVOID)e->ContextRecord->Dr3, (PVOID)e->ContextRecord->Dr7);

	else if (e->ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT)
		RG_Report(RG_OPT_ANTI_DEBUGGING, REPORT_DEBUG_SW_BREAKPOINT, (PVOID)e->ExceptionRecord->ExceptionAddress, (PVOID)e->ExceptionRecord->ExceptionInformation[1]);

	else if (e->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
		RG_Report(RG_OPT_ANTI_DEBUGGING, REPORT_DEBUG_SINGLE_STEP, (PVOID)e->ExceptionRecord->ExceptionAddress, (PVOID)e->ExceptionRecord->ExceptionInformation[1]);

	else if (e->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
		RG_Report(RG_OPT_ANTI_DEBUGGING, REPORT_DEBUG_PAGE_GUARD, (PVOID)e->ExceptionRecord->ExceptionAddress, (PVOID)e->ExceptionRecord->ExceptionInformation[1]);
}

VOID CALLBACK DllCallback(ULONG reason, PLDR_DLL_NOTIFICATION_DATA data, PVOID context)
{
	if (reason == LDR_DLL_NOTIFICATION_REASON_LOADED)
	{
		CheckThread(GetCurrentThreadStartAddress(), TC_DllCallback);

#if IS_ENABLED(RG_OPT_REBIRTH_ALL_MODULES)
#ifdef _WIN64 // unstable in x86 yet.
		BOOL packed = FALSE;
		PIMAGE_NT_HEADERS nt = GetNtHeader(data->Loaded.DllBase);
		PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
		for (DWORD i = 0; !packed && i < nt->FileHeader.NumberOfSections; ++i)
			if (strstr((CHAR*)sec[i].Name, RGS("themida")) || strstr((CHAR*)sec[i].Name, RGS("vmp")))
				packed = TRUE;

		if (!packed)
			RebirthModule(NULL, data->Loaded.DllBase);
#endif
#endif
	}
	return;
}
