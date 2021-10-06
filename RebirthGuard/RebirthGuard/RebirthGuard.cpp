
/*
	chztbby::RebirthGuard/RebirthGuard.cpp
*/

#include "RebirthGuard.h"

VOID RG_RegisterCallbacks()
{
	// Register Exception Handler
	((RtlAddVectoredExceptionHandler_T)ApiCall(ntdll, API_RtlAddVectoredExceptionHandler))(1, Exception_Callback);

	// Register DLL notificaton callback
	PVOID cookie = NULL;
	((LdrRegisterDllNotification_T)ApiCall(ntdll, API_LdrRegisterDllNotification))(0, DLL_Callback, NULL, &cookie);
	cookie = NULL;
}

VOID RG_Initialze()
{
	// Allocate memory for section handle list
#if RG_OPT_CRC_HIDE_FROM_DEBUGGER & RG_ENABLE
	DWORD64 AllocSize = MAX_SECTION_LIST_SIZE;
	NTSTATUS result = ((NtAllocateVirtualMemory_T)ApiCall(ntdll, API_NtAllocateVirtualMemory))(CURRENT_PROCESS, (PVOID*)&section_list, NULL, &AllocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (result)
		Report(CURRENT_PROCESS, RG_ENABLE | RG_ENABLE_LOG | RG_ENABLE_POPUP | RG_ENABLE_KILL, REPORT_ALLOC_SECTION_LIST, (PVOID)(DWORD64)result, (PVOID)1);
#endif

	RebirthModule(CURRENT_PROCESS, GetModulePath(ntdll));

	if (IsRebirthed(CURRENT_PROCESS, RG_GetModuleHandleEx(CURRENT_PROCESS, NULL)) == NULL)
	{
		RG_RegisterCallbacks();

		STARTUPINFOEX si = { sizeof(si) };
		PROCESS_INFORMATION pi;

#if RG_OPT_PROCESS_POLICY & RG_ENABLE
		UCHAR buffer[4096];
		LPPROC_THREAD_ATTRIBUTE_LIST attr = (LPPROC_THREAD_ATTRIBUTE_LIST)buffer;
		DWORD64 size = 0;

		InitializeProcThreadAttributeList(NULL, 1, 0, &size);

		attr = (LPPROC_THREAD_ATTRIBUTE_LIST)  new UCHAR[size];
		InitializeProcThreadAttributeList(attr, 1, 0, &size);

		DWORD64 policy = RG_PROCESS_POLICY;

		UpdateProcThreadAttribute(attr, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(policy), NULL, NULL);

		si.StartupInfo.cb = sizeof(si);
		si.lpAttributeList = attr;

		((CreateProcessW_T)ApiCall(kernel32, API_CreateProcessW))(GetModulePath(EXE), GetCommandLine(),  NULL, NULL, NULL, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi);
#endif
#if !(RG_OPT_PROCESS_POLICY & RG_ENABLE)
		((CreateProcessW_T)ApiCall(kernel32, API_CreateProcessW))(GetModulePath(EXE), GetCommandLine(),  NULL, NULL, NULL, CREATE_SUSPENDED, NULL, NULL, (STARTUPINFO*)&si, &pi);
#endif
		HANDLE hThread = NULL;
		((NtCreateThreadEx_T)ApiCall(ntdll, API_NtCreateThreadEx))(&hThread, MAXIMUM_ALLOWED, NULL, pi.hProcess, RG_RegisterCallbacks, NULL, NULL, NULL, NULL, NULL, NULL);
		WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);

		// Remap all module of restarted process
		LDR_DATA_TABLE_ENTRY List;
		*(DWORD64*)&List = 0;
		while (GetNextModule(pi.hProcess, &List))
		{
			WCHAR ModulePath[MAX_PATH];
			((NtReadVirtualMemory_T)ApiCall(ntdll, API_NtReadVirtualMemory))(pi.hProcess, *(PVOID*)((BYTE*)&List + 0x40), ModulePath, MAX_PATH, NULL);
			RebirthModule(pi.hProcess, ModulePath);
		}

#if RG_OPT_MEMORY_CHECK & RG_ENABLE
		MemoryCheck(pi.hProcess);
#endif

#if RG_OPT_CRC_CHECK & RG_ENABLE
		((NtCreateThreadEx_T)ApiCall(ntdll, API_NtCreateThreadEx))(NULL, MAXIMUM_ALLOWED, NULL, pi.hProcess, CRCCheck, NULL, NULL, NULL, NULL, NULL, NULL);
#endif

		((NtResumeProcess_T)ApiCall(ntdll, API_NtResumeProcess))(pi.hProcess);

		((NtTerminateProcess_T)ApiCall(ntdll, API_NtTerminateProcess))(CURRENT_PROCESS, 0);
	}
}
