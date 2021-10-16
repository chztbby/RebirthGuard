
/*
	chztbby::RebirthGuard/RebirthGuard.cpp
*/

#include "RebirthGuard.h"

VOID Dummy() {}

VOID RG_Initialze(PVOID hmodule)
{
	if (IsExe(hmodule))
	{
		if (GetCurrentThreadStartAddress() != Dummy)
		{
#if RG_OPT_CRC_HIDE_FROM_DEBUGGER & RG_ENABLE
			SIZE_T list_size = REBIRTHED_MODULE_LIST_SIZE;
			APICALL(NtAllocateVirtualMemory_T)(CURRENT_PROCESS, (PVOID*)&rebirthed_module_list, NULL, &list_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#endif
			LPCWSTR exe_path = GetModulePath(MODULE_EXE);

			STARTUPINFOEX si = { sizeof(si) };
			PROCESS_INFORMATION pi;
#if RG_OPT_PROCESS_POLICY & RG_ENABLE
			SIZE_T size = 0;
			InitializeProcThreadAttributeList(NULL, 1, 0, &size);

			LPPROC_THREAD_ATTRIBUTE_LIST attr = (LPPROC_THREAD_ATTRIBUTE_LIST)new BYTE[size];
			InitializeProcThreadAttributeList(attr, 1, 0, &size);

			DWORD64 policy = RG_PROCESS_POLICY;
			UpdateProcThreadAttribute(attr, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(policy), NULL, NULL);

			si.StartupInfo.cb = sizeof(si);
			si.lpAttributeList = attr;
			APICALL(CreateProcessW_T)(exe_path, GetCommandLineW(), NULL, NULL, NULL, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi);
			delete[] attr;
#endif
#if !(RG_OPT_PROCESS_POLICY & RG_ENABLE)
			((CreateProcessW_T)ApiCall(API_CreateProcessW))(exe_path, GetCommandLineW(), NULL, NULL, NULL, CREATE_SUSPENDED, NULL, NULL, (STARTUPINFO*)&si, &pi);
#endif
			HANDLE thread = NULL;
			APICALL(NtCreateThreadEx_T)(&thread, MAXIMUM_ALLOWED, NULL, pi.hProcess, Dummy, NULL, NULL, NULL, NULL, NULL, NULL);
			WaitForSingleObject(thread, INFINITE);
			CloseHandle(thread);

			RebirthModule(pi.hProcess, exe_path);
			//RebirthModule(pi.hProcess, GetModulePath(ntdll));

#if RG_OPT_REBIRTH_SYSTEM_MODULES & RG_ENABLE
			LDR_DATA_TABLE_ENTRY list;
			*(PVOID*)&list = 0;
			//while (GetNextModule(pi.hProcess, &list))
			GetNextModule(pi.hProcess, &list);
			{
				WCHAR module_path[MAX_PATH];
				APICALL(NtReadVirtualMemory_T)(pi.hProcess, *(PVOID*)GetPtr(&list, sizeof(PVOID) * 8), module_path, MAX_PATH, NULL);
				RebirthModule(pi.hProcess, module_path);
				MessageBoxW(0, module_path, 0, 0);
			}
#endif
			APICALL(NtResumeProcess_T)(pi.hProcess);

			APICALL(NtTerminateProcess_T)(CURRENT_PROCESS, 0);
		}
		else
		{
#if RG_OPT_ANTI_DEBUGGING & RG_ENABLE
			APICALL(RtlAddVectoredExceptionHandler_T)(1, DebugCallback);
#endif
			PVOID cookie = NULL;
			APICALL(LdrRegisterDllNotification_T)(0, DllCallback, NULL, &cookie);
			cookie = NULL;

			// load system dll
		}
	}
	else
	{

	}
}