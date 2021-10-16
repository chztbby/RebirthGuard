
/*
	chztbby::RebirthGuard/function.cpp
*/

#include "RebirthGuard.h"

BOOL IsExe(PVOID hmodule)
{
	PIMAGE_NT_HEADERS nt = GetNtHeader(hmodule);
	return !(nt->FileHeader.Characteristics & IMAGE_FILE_DLL);
}

PVOID GetPEHeader(HANDLE process, PVOID module_base)
{
	if (process == CURRENT_PROCESS)
		return module_base;

	PVOID pe_header = NULL;
	SIZE_T pe_header_size = PAGE_SIZE;
	((NtAllocateVirtualMemory_T)ApiCall(API_NtAllocateVirtualMemory))(CURRENT_PROCESS, &pe_header, NULL, &pe_header_size, MEM_COMMIT, PAGE_READWRITE);
	((NtReadVirtualMemory_T)ApiCall(API_NtReadVirtualMemory))(process, module_base, pe_header, pe_header_size, NULL);
	return pe_header;
}

PVOID GetCurrentThreadStartAddress()
{
	PVOID start_address = NULL;
	((NtQueryInformationThread_T)ApiCall(API_NtQueryInformationThread))(CURRENT_THREAD, ThreadQuerySetWin32StartAddress, &start_address, sizeof(start_address), 0);

	return start_address;
}

LPWSTR GetModulePath(DWORD module_index)
{
	static WCHAR module_path[MODULE_LAST + 1][MAX_PATH] = { 0, };

	if (module_path[module_index][0] == 0)
	{
		LDR_DATA_TABLE_ENTRY list;
		*(PVOID*)&list = 0;

		for (DWORD i = MODULE_FIRST; i <= module_index; i++)
			GetNextModule(CURRENT_PROCESS, &list);

		RG_wcscpy(module_path[module_index], (LPCWSTR)*(PVOID*)(GetPtr(&list, sizeof(PVOID) * 8)));
	}

	return module_path[module_index];
}

PVOID GetNextModule(HANDLE process, PLDR_DATA_TABLE_ENTRY plist)
{
	static LDR_DATA_TABLE_ENTRY* first = NULL;

	if (process == CURRENT_PROCESS)
	{
		if (!*(PVOID*)plist)
		{
			if (!first)
			{
#ifdef _WIN64
				first = (LDR_DATA_TABLE_ENTRY*)(*(*((PTEB)__readgsqword(0x30))->ProcessEnvironmentBlock).Ldr).InMemoryOrderModuleList.Flink;
				*plist = *(LDR_DATA_TABLE_ENTRY*)(*(*((PTEB)__readgsqword(0x30))->ProcessEnvironmentBlock).Ldr).InMemoryOrderModuleList.Flink;
#else
				first = (LDR_DATA_TABLE_ENTRY*)(*(*((PTEB)__readfsdword(0x18))->ProcessEnvironmentBlock).Ldr).InMemoryOrderModuleList.Flink;
				*plist = *(LDR_DATA_TABLE_ENTRY*)(*(*((PTEB)__readfsdword(0x18))->ProcessEnvironmentBlock).Ldr).InMemoryOrderModuleList.Flink;
#endif
			}
			else
				*plist = *first;
		}
		else
			*plist = *(LDR_DATA_TABLE_ENTRY*)(*(PVOID*)plist);
	}
	else
	{
		if (!*(PVOID*)plist)
		{
			PROCESS_BASIC_INFORMATION pbi;
			((NtQueryInformationProcess_T)ApiCall(API_NtQueryInformationProcess))(process, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);

			PEB peb;
			PEB_LDR_DATA ldr;
			((NtReadVirtualMemory_T)ApiCall(API_NtReadVirtualMemory))(process, pbi.PebBaseAddress, &peb, sizeof(peb), NULL);
			((NtReadVirtualMemory_T)ApiCall(API_NtReadVirtualMemory))(process, peb.Ldr, &ldr, sizeof(ldr), NULL);
			((NtReadVirtualMemory_T)ApiCall(API_NtReadVirtualMemory))(process, ldr.InMemoryOrderModuleList.Flink, plist, sizeof(LDR_DATA_TABLE_ENTRY), NULL);
		}
		else
			((NtReadVirtualMemory_T)ApiCall(API_NtReadVirtualMemory))(process, *(PVOID*)plist, plist, sizeof(LDR_DATA_TABLE_ENTRY), NULL);
	}

	return plist->DllBase;
}

VOID HideModules()
{
	LDR_DATA_TABLE_ENTRY list;
	*(PVOID*)&list = 0;
	while (GetNextModule(CURRENT_PROCESS, &list))
	{
		PLIST_ENTRY node = NULL;
#ifdef _WIN64
		PPEB_LDR_DATA_ ldr = (PPEB_LDR_DATA_)(*((PTEB)__readgsqword(0x30))->ProcessEnvironmentBlock).Ldr;
#else
		PPEB_LDR_DATA_ ldr = (PPEB_LDR_DATA_)(*((PTEB)__readfsdword(0x18))->ProcessEnvironmentBlock).Ldr;
#endif
		node = ldr->InLoadOrderModuleList.Flink;
		node->Blink->Flink = node->Flink;
		node->Flink->Blink = node->Blink;

		node = ldr->InMemoryOrderModuleList.Flink;
		node->Blink->Flink = node->Flink;
		node->Flink->Blink = node->Blink;

		node = ldr->InInitializationOrderModuleList.Flink;
		node->Blink->Flink = node->Flink;
		node->Flink->Blink = node->Blink;
	}
}

HMODULE RG_GetModuleHandleEx(HANDLE process, LPCWSTR module_path)
{
	LDR_DATA_TABLE_ENTRY list;
	*(PVOID*)&list = 0;

	while (GetNextModule(process, &list))
	{
		if (!module_path)
			return *(HMODULE*)(GetPtr(&list, sizeof(PVOID) * 4));

		WCHAR module_name[MAX_PATH];
		module_name[0] = '\0';

		if (process == CURRENT_PROCESS)
			RG_wcscpy(module_name, list.FullDllName.Buffer);
		else								
			((NtReadVirtualMemory_T)ApiCall(API_NtReadVirtualMemory))(process, list.FullDllName.Buffer, module_name, MAX_PATH, NULL);

		if (RG_wcsistr(module_path, module_name))
			return *(HMODULE*)(GetPtr(&list, sizeof(PVOID) * 4));
	}

	return NULL;
}

FARPROC ApiCall(API_INDEX api_index)
{
	CHAR api_name[50];
	DecryptXOR(api_name, api_index);

	FARPROC api = NULL;
	
	for (DWORD i = MODULE_FIRST; i <= MODULE_LAST && !api; ++i)
		api = GetProcAddress(RG_GetModuleHandleEx(CURRENT_PROCESS, GetModulePath(i)), api_name);

	for (DWORD i = 0; i < sizeof(api_name); i++)
		api_name[i] = 0;

	return api;
}

FARPROC ApiCall(DWORD module_index, API_INDEX api_index)
{
	CHAR api_name[50];
	DecryptXOR(api_name, api_index);

	FARPROC api = GetProcAddress(RG_GetModuleHandleEx(CURRENT_PROCESS, GetModulePath(module_index)), api_name);

	for (DWORD i = 0; i < sizeof(api_name); i++)
		api_name[i] = 0;

	return api;
}

VOID RG_DebugLog(LPCWSTR format, ...)
{
#if RG_OPT_DEBUG_LOG & RG_ENABLE

#endif
}

VOID Report(HANDLE process, DWORD flag, REBIRTHGUARD_REPORT_CODE code, PVOID data1, PVOID data2)
{
	WCHAR buffer1[MAX_PATH];
	WCHAR buffer2[MAX_PATH];
	WCHAR module_name1[MAX_PATH] = L"";
	WCHAR module_name2[MAX_PATH] = L"";
	WCHAR module_path1[MAX_PATH] = L"";
	WCHAR module_path2[MAX_PATH] = L"";

	time_t t = time(NULL);
	tm tm;
	localtime_s(&tm, &t);

	PVOID order = IsInModule(process, data1, 2);
	PVOID order2 = IsInModule(process, data2, 2);

	LDR_DATA_TABLE_ENTRY list;
	*(PVOID*)&list = 0;
	for (DWORD i = 0; GetNextModule(process, &list); ++i)
	{
		((NtReadVirtualMemory_T)ApiCall(API_NtReadVirtualMemory))(process, list.FullDllName.Buffer, buffer1, MAX_PATH, NULL);
		((NtReadVirtualMemory_T)ApiCall(API_NtReadVirtualMemory))(process, *(PVOID*)GetPtr(&list, 0x40), buffer2, MAX_PATH, NULL);

		if (order == (PVOID)i)
		{
			RG_wcscpy(module_name1, buffer1);
			RG_wcscat(module_name1, L" +");
			RG_wcscpy(module_path1, buffer2);
		}
		if (order2 == (PVOID)i)
		{
			RG_wcscpy(module_name2, buffer2);
			RG_wcscat(module_name2, L" +");
			RG_wcscpy(module_path2, buffer2);
		}
	}

	if (flag & RG_ENABLE_LOG)
	{
		FILE* log = NULL;
		fopen_s(&log, "RebirthGuard.log", "a+");
		fprintf(log,
			"[ %04d-%02d-%02d %02d:%02d:%02d ]\n\n"
			"    Pid\t: %d\n"
			"    Code\t: 0x%08X\n\n"
			"    %S 0x%p\n"
			"    %S 0x%p\n\n"
			"-----------------------------------------------------------------------------------\n",
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
			GetCurrentProcessId(),
			code,
			module_name1, GetOffset(RG_GetModuleHandleEx(process, module_path1), data1),
			module_name2, GetOffset(RG_GetModuleHandleEx(process, module_path2), data2));
		fclose(log);
	}

	if (flag & RG_ENABLE_POPUP)
	{
		CHAR scriptpath[MAX_PATH];
		GetCurrentDirectoryA(MAX_PATH, scriptpath);
		RG_strcat(scriptpath, "\\RebirthGuard.vbs");

		FILE* log = NULL;
		fopen_s(&log, "RebirthGuard.vbs", "w+");
		fprintf(log,
			"Dim obj, file\n"
			"Set obj = CreateObject(\"Scripting.FileSystemObject\")\n"
			"Set file = obj.GetFile(\"%s\")\n"
			"file.Delete\n"
			"msgbox \"[ %04d-%02d-%02d %02d:%02d:%02d ]\" & Chr(13) & Chr(13) &"
			"\"Pid\t:  %d\" & Chr(13) & "
			"\"Code\t:  0x%08X\" & Chr(13) & Chr(13) &"
			"\"%S 0x%p\" & Chr(13) &"
			"\"%S 0x%p\", 0 + 48, \"RebirthGuard\""
			, scriptpath,
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
			GetCurrentProcessId(),
			code,
			module_name1, GetOffset(RG_GetModuleHandleEx(process, module_path1), data1),
			module_name2, GetOffset(RG_GetModuleHandleEx(process, module_path2), data2));
		fclose(log);

		CHAR path[MAX_PATH] = "wscript.exe \"";
		RG_strcat(path, scriptpath);
		RG_strcat(path, "\"");

		((WinExec_T)ApiCall(API_WinExec))(path, SW_SHOW);
	}

	if (flag & RG_ENABLE_MEM_FREE)
	{
		SIZE_T Size = NULL;
		PVOID Address = data1;
		((NtFreeVirtualMemory_T)ApiCall(API_NtFreeVirtualMemory))(process, &Address, &Size, MEM_RELEASE);
		((NtFreeVirtualMemory_T)ApiCall(API_NtFreeVirtualMemory))(process, &Address, &Size, MEM_RELEASE | MEM_DECOMMIT);
	}

	if (flag & RG_ENABLE_KILL)
	{
		((NtTerminateProcess_T)ApiCall(API_NtTerminateProcess))(process, 0);
		((NtTerminateProcess_T)ApiCall(API_NtTerminateProcess))(CURRENT_PROCESS, 0);
	}
}