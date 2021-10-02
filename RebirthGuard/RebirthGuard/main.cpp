
/********************************************
*											*
*	RebirthGuard/main.cpp - chztbby			*
*											*
********************************************/

#include "RebirthGuard.h"


//-------------------------------------------------------
//	Register Callbacks
//-------------------------------------------------------
VOID RegisterCallbacks(VOID)
{
	// Register Exception Handler
	((_RtlAddVectoredExceptionHandler)APICall(ntdll, APICall_RtlAddVectoredExceptionHandler))(1, Exception_Callback);

	// Register DLL notificaton callback
	PVOID cookie = NULL;
	((_LdrRegisterDllNotification)APICall(ntdll, APICall_LdrRegisterDllNotification))(0, DLL_Callback, NULL, &cookie);
	cookie = NULL;
}


//-------------------------------------------------------
//	Initialize RebirthGuard  
//-------------------------------------------------------
VOID Initialze(VOID)
{
	// Allocate memory for section handle list
#if _HIDE_FROM_DEBUGGER & ENABLE
	DWORD64 AllocSize = SECTION_LIST_SIZE;
	NTSTATUS result = ((_NtAllocateVirtualMemory)APICall(ntdll, APICall_NtAllocateVirtualMemory))(CURRENT_PROCESS, (PVOID*)&SectionList, NULL, &AllocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (result)
		Report(CURRENT_PROCESS, ENABLE | _LOG | _POPUP | _KILL, Allocation_SectionList, (PVOID)(DWORD64)result, (PVOID)1);
#endif

	// Remap ntdll.dll
	RebirthModule(CURRENT_PROCESS, GetModulePath(ntdll));

	// Check this program is rebirthed
	if (IsRebirthed(CURRENT_PROCESS, myGetModuleHandleEx(CURRENT_PROCESS, NULL)) == NULL)
	{
		// Register Callbacks
		RegisterCallbacks();

		STARTUPINFOEX si = { sizeof(si) };
		PROCESS_INFORMATION pi;

		// Set process policy
#if PROCESS_POLICY & ENABLE
		UCHAR buffer[4096];
		LPPROC_THREAD_ATTRIBUTE_LIST attr = (LPPROC_THREAD_ATTRIBUTE_LIST)buffer;
		DWORD64 size = 0;

		InitializeProcThreadAttributeList(NULL, 1, 0, &size);

		attr = (LPPROC_THREAD_ATTRIBUTE_LIST)  new UCHAR[size];
		InitializeProcThreadAttributeList(attr, 1, 0, &size);

		DWORD64 policy = POLICY;

#if _MS_SIGNED_ONLY & ENABLE
			policy |= PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
#endif

		UpdateProcThreadAttribute(attr, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(policy), NULL, NULL);

		si.StartupInfo.cb = sizeof(si);
		si.lpAttributeList = attr;

		// Restart process with process policy (CREATE_SUSPEND)
		((_CreateProcessW)APICall(kernel32, APICall_CreateProcessW))(GetModulePath(EXE), GetCommandLine(),  NULL, NULL, NULL, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi);
#endif
#if !(PROCESS_POLICY & ENABLE)
		((_CreateProcessW)APICall(kernel32, APICall_CreateProcessW))(GetModulePath(EXE), GetCommandLine(),  NULL, NULL, NULL, CREATE_SUSPENDED, NULL, NULL, (STARTUPINFO*)&si, &pi);
#endif
		// CreateRemoteThread in restarted process
		HANDLE hThread = NULL;
		((_NtCreateThreadEx)APICall(ntdll, APICall_NtCreateThreadEx))(&hThread, MAXIMUM_ALLOWED, NULL, pi.hProcess, RegisterCallbacks, NULL, NULL, NULL, NULL, NULL, NULL);
		WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);

		// Remap all module of restarted process
		LDR_DATA_TABLE_ENTRY List;
		*(DWORD64*)&List = 0;
		while (NextModule(pi.hProcess, &List))
		{
			WCHAR ModulePath[MAX_PATH];
			((_NtReadVirtualMemory)APICall(ntdll, APICall_NtReadVirtualMemory))(pi.hProcess, *(PVOID*)((BYTE*)&List + 0x40), ModulePath, MAX_PATH, NULL);
			RebirthModule(pi.hProcess, ModulePath);
		}

		// Memory info check
#if MEM_CHECK & ENABLE
		MemCheck(pi.hProcess);
#endif

		// CRC check
#if CRC_CHECK & ENABLE
		((_NtCreateThreadEx)APICall(ntdll, APICall_NtCreateThreadEx))(NULL, MAXIMUM_ALLOWED, NULL, pi.hProcess, CRCCheck, NULL, NULL, NULL, NULL, NULL, NULL);
#endif

		// Resume the restarted process
		((_NtResumeProcess)APICall(ntdll, APICall_NtResumeProcess))(pi.hProcess);

		// Terminate current process
		((_NtTerminateProcess)APICall(ntdll, APICall_NtTerminateProcess))(CURRENT_PROCESS, 0);
	}
}
