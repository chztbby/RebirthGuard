
/*
	chztbby::RebirthGuard/RebirthGuard.cpp
*/

#include "RebirthGuard.h"

VOID RG_Initialze(PVOID hmodule)
{
	if (IsRebirthed(hmodule))
		return;

	Rebirth(hmodule);
}

VOID Rebirth(PVOID hmodule)
{
	rgdata = (PRG_DATA)RG_AllocMemory((PVOID)RG_DATA_PTR, RG_DATA_SIZE, PAGE_READWRITE);

#if IS_ENABLED(RG_OPT_COMPAT_THEMIDA) || IS_ENABLED(RG_OPT_COMPAT_VMPROTECT)
	PIMAGE_NT_HEADERS nt = GetNtHeader(hmodule);
	PVOID mapped_module = RG_AllocMemory(NULL, nt->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE);
	CopyPeData(mapped_module, hmodule, PE_TYPE_IMAGE);
#else
	PVOID mapped_module = ManualMap(hmodule);
#endif
	auto pRebirthModule = decltype (&RebirthModule)GetPtr(mapped_module, GetOffset(hmodule, RebirthModule));
	pRebirthModule(hmodule, hmodule);
	RG_FreeMemory(mapped_module);

	RebirthModules(hmodule);

	RG_SetCallbacks();

	CheckMemory();

	CheckCRC();

#if IS_ENABLED(RG_OPT_SET_PROCESS_POLICY)
	if (IsExe(hmodule) && !CheckProcessPolicy())
		RestartProcess();
#endif
}

VOID RebirthModules(PVOID hmodule)
{
#ifdef _WIN64 // unstable in x86 yet.
#if IS_ENABLED(RG_OPT_REBIRTH_SYSTEM_MODULES)
	WCHAR system_modules[11][20];
	RG_wcscpy(system_modules[0], RGS(L"ntdll.dll"));
	RG_wcscpy(system_modules[1], RGS(L"kernel32.dll"));
	RG_wcscpy(system_modules[2], RGS(L"kernelbase.dll"));
	RG_wcscpy(system_modules[3], RGS(L"gdi32.dll"));
	RG_wcscpy(system_modules[4], RGS(L"win32u.dll"));
	RG_wcscpy(system_modules[5], RGS(L"gdi32full.dll"));
	RG_wcscpy(system_modules[6], RGS(L"user32.dll"));
	RG_wcscpy(system_modules[7], RGS(L"ws2_32.dll"));
	RG_wcscpy(system_modules[8], RGS(L"d3d9.dll"));
	RG_wcscpy(system_modules[9], RGS(L"d3d11.dll"));
	RG_wcscpy(system_modules[10], RGS(L"dxgi.dll"));

	for (LPCWSTR mod : system_modules)
	{
		if (!RG_GetModuleHandleW(mod))
			APICALL(LoadLibraryW)(mod);

		RebirthModule(hmodule, RG_GetModuleHandleW(mod));
	}
#endif

#if IS_ENABLED(RG_OPT_REBIRTH_ALL_MODULES)
	LDR_MODULE module_info = { 0, };
	while (RG_GetNextModule(&module_info))
	{
		PLDR_MODULE pmodule_info = (PLDR_MODULE)GetPtr(&module_info, GetOffset(&module_info.InMemoryOrderModuleList, &module_info));
		if (!IsRebirthed(pmodule_info->BaseAddress))
			RebirthModule(hmodule, pmodule_info->BaseAddress);
	}
#endif
#endif
}

BOOL CheckProcessPolicy()
{
	if (RG_PROCESS_POLICY & PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS_ALWAYS_ON)
	{
		PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY shcp;
		APICALL(GetProcessMitigationPolicy)(CURRENT_PROCESS, ProcessStrictHandleCheckPolicy, &shcp, sizeof(shcp));

		if (!shcp.Flags)
			return FALSE;
	}

	/*
		...
	*/

	return TRUE;
}

VOID RestartProcess()
{
	SIZE_T size = 0;
	APICALL(InitializeProcThreadAttributeList)(NULL, 1, 0, &size);

	LPPROC_THREAD_ATTRIBUTE_LIST attr = (LPPROC_THREAD_ATTRIBUTE_LIST)RG_AllocMemory(NULL, size, PAGE_READWRITE);
	APICALL(InitializeProcThreadAttributeList)(attr, 1, 0, &size);

	DWORD64 policy = RG_PROCESS_POLICY;
	APICALL(UpdateProcThreadAttribute)(attr, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(policy), NULL, NULL);

	PROCESS_INFORMATION pi;
	STARTUPINFOEX si = { sizeof(si) };
	si.StartupInfo.cb = sizeof(si);
	si.lpAttributeList = attr;
	APICALL(CreateProcessW)(NULL, APICALL(GetCommandLineW)(), NULL, NULL, NULL, EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED, NULL, NULL, &si.StartupInfo, &pi);
	RG_FreeMemory(attr);

	HANDLE thread = RG_CreateThread(pi.hProcess, APICALL(Sleep), 0);
	APICALL(WaitForSingleObject)(thread, INFINITE);
	APICALL(NtResumeProcess)(pi.hProcess);

	APICALL(NtTerminateProcess)(CURRENT_PROCESS, 0);
}