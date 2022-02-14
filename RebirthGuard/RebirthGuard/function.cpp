
/*
	chztbby::RebirthGuard/function.cpp
*/

#include "RebirthGuard.h"

BOOL IsExe(PVOID hmodule)
{
	return !(GetNtHeader(hmodule)->FileHeader.Characteristics & IMAGE_FILE_DLL);
}

PVOID GetCurrentThreadStartAddress()
{
	PVOID start_address = NULL;
	APICALL(NtQueryInformationThread_T)(CURRENT_THREAD, ThreadQuerySetWin32StartAddress, &start_address, sizeof(start_address), 0);

	return start_address;
}

LPWSTR GetModulePath(DWORD module_index)
{
	static WCHAR module_path[MODULE_LAST + 1][MAX_PATH] = { 0, };

	if (!module_path[module_index][0])
	{
		LDR_DATA_TABLE_ENTRY list = { 0, };
		for (DWORD i = MODULE_FIRST; i <= module_index; i++)
			GetNextModule(&list);

		RG_wcscpy(module_path[module_index], (LPCWSTR)*(PVOID*)(GetPtr(&list, sizeof(PVOID) * 8)));
	}

	return module_path[module_index];
}

PVOID GetNextModule(PLDR_DATA_TABLE_ENTRY plist)
{
	static LDR_DATA_TABLE_ENTRY* first = NULL;

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

	return plist->DllBase;
}

VOID HideModule(PVOID hmodule)
{
#if IS_ENABLED(RG_OPT_HIDE_MODULE)
#ifdef _WIN64
	PPEB_LDR_DATA_ ldr = (PPEB_LDR_DATA_)(*((PTEB)__readgsqword(0x30))->ProcessEnvironmentBlock).Ldr;
#else
	PPEB_LDR_DATA_ ldr = (PPEB_LDR_DATA_)(*((PTEB)__readfsdword(0x18))->ProcessEnvironmentBlock).Ldr;
#endif
	for (PLIST_ENTRY node = ldr->InLoadOrderModuleList.Flink; node; node = node->Flink)
	{
		PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)node;
		if (entry->DllBase == hmodule)
		{
			node->Blink->Flink = node->Flink;
			node->Flink->Blink = node->Blink;
			break;
		}
	}
#endif
}

HMODULE RG_GetModuleHandleW(LPCWSTR module_path)
{
	LDR_DATA_TABLE_ENTRY list = { 0, };

	while (GetNextModule(&list))
	{
		if (!module_path)
			return *(HMODULE*)(GetPtr(&list, sizeof(PVOID) * 4));

		WCHAR module_name[MAX_PATH];
		module_name[0] = '\0';

		RG_wcscpy(module_name, list.FullDllName.Buffer);

		if (RG_wcsistr(module_path, module_name))
			return *(HMODULE*)(GetPtr(&list, sizeof(PVOID) * 4));
	}

	return NULL;
}

HANDLE RG_CreateThread(PVOID entry, PVOID param)
{
	HANDLE thread = NULL;
	APICALL(NtCreateThreadEx_T)(&thread, MAXIMUM_ALLOWED, NULL, CURRENT_PROCESS, entry, param, NULL, NULL, NULL, NULL, NULL);
	return thread;
}

FARPROC GetApi(API_INDEX api_index)
{
	CHAR api_name[50];
	DecryptXOR(api_name, api_index);

	FARPROC api = NULL;
	
	for (DWORD i = MODULE_FIRST; i <= MODULE_LAST && !api; ++i)
		api = GetProcAddress(RG_GetModuleHandleW(GetModulePath(i)), api_name);

	for (DWORD i = 0; i < sizeof(api_name); i++)
		api_name[i] = 0;

	return api;
}

FARPROC GetApi(DWORD module_index, API_INDEX api_index)
{
	CHAR api_name[50];
	DecryptXOR(api_name, api_index);

	FARPROC api = GetProcAddress(RG_GetModuleHandleW(GetModulePath(module_index)), api_name);

	for (DWORD i = 0; i < sizeof(api_name); i++)
		api_name[i] = 0;

	return api;
}

VOID CopyPeData(PVOID dst, PVOID src, PE_TYPE src_type)
{
	PIMAGE_NT_HEADERS nt = GetNtHeader(src);
	PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

	memcpy(dst, src, nt->OptionalHeader.SizeOfHeaders);

	for (DWORD i = 0; i < nt->FileHeader.NumberOfSections; i++)
	{
		if (src_type == PE_MEMORY)
			memcpy(GetPtr(dst, sec[i].VirtualAddress), GetPtr(src, sec[i].VirtualAddress), sec[i].Misc.VirtualSize);

		if (src_type == PE_FILE)
			memcpy(GetPtr(dst, sec[i].VirtualAddress), GetPtr(src, sec[i].PointerToRawData), sec[i].SizeOfRawData);
	}
}

PVOID AllocMemory(PVOID ptr, SIZE_T size, DWORD protect)
{
	APICALL(NtAllocateVirtualMemory_T)(CURRENT_PROCESS, &ptr, NULL, &size, MEM_COMMIT | MEM_RESERVE, protect);
	return ptr;
}

VOID FreeMemory(PVOID ptr)
{
	SIZE_T size = NULL;
	APICALL(NtFreeVirtualMemory_T)(CURRENT_PROCESS, &ptr, &size, MEM_RELEASE);
}

DWORD ProtectMemory(PVOID ptr, SIZE_T size, DWORD protect)
{
	DWORD old = NULL;
	APICALL(NtProtectVirtualMemory_T)(CURRENT_PROCESS, &ptr, &size, protect, &old);
	return old;
}

VOID QueryMemory(PVOID ptr, PVOID buffer, SIZE_T buffer_size, DWORD type)
{
	APICALL(NtQueryVirtualMemory_T)(CURRENT_PROCESS, ptr, type, buffer, buffer_size, NULL);
}

VOID RG_DebugLog(LPCWSTR format, ...)
{
#if RG_OPT_DEBUG_LOG & RG_ENABLE

#endif
}

LONG WINAPI RG_ExceptionHandler(PEXCEPTION_POINTERS e)
{
#if IS_ENABLED(RG_OPT_ANTI_DEBUGGING)
	DebugCallback(e);
#endif
	return EXCEPTION_CONTINUE_SEARCH;
}

VOID RG_SetCallbacks()
{
	APICALL(RtlAddVectoredExceptionHandler_T)(1, RG_ExceptionHandler);

	PVOID cookie = NULL;
	APICALL(LdrRegisterDllNotification_T)(NULL, DllCallback, NULL, &cookie);
	cookie = NULL;
}

VOID Report(DWORD flag, RG_REPORT_CODE code, PVOID data1, PVOID data2)
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

	PVOID order = IsInModule(data1, 2);
	PVOID order2 = IsInModule(data2, 2);

	LDR_DATA_TABLE_ENTRY list = { 0, };
	for (DWORD i = 0; GetNextModule(&list); ++i)
	{
		APICALL(NtReadVirtualMemory_T)(CURRENT_PROCESS, list.FullDllName.Buffer, buffer1, MAX_PATH, NULL);
		APICALL(NtReadVirtualMemory_T)(CURRENT_PROCESS, *(PVOID*)GetPtr(&list, sizeof(PVOID) * 8), buffer2, MAX_PATH, NULL);

		if (order == (PVOID)(SIZE_T)i)
		{
			RG_wcscpy(module_name1, buffer1);
			RG_wcscat(module_name1, L" +");
			RG_wcscpy(module_path1, buffer2);
		}
		if (order2 == (PVOID)(SIZE_T)i)
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
			"[%04d-%02d-%02d %02d:%02d:%02d] Pid : %d / Code : 0x%08X / %S 0x%p / %S 0x%p\n",
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
			GetCurrentProcessId(),
			code,
			module_name1, (PVOID)GetOffset(RG_GetModuleHandleW(module_path1), data1),
			module_name2, (PVOID)GetOffset(RG_GetModuleHandleW(module_path2), data2));
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
			module_name1, (PVOID)GetOffset(RG_GetModuleHandleW(module_path1), data1),
			module_name2, (PVOID)GetOffset(RG_GetModuleHandleW(module_path2), data2));
		fclose(log);

		CHAR path[MAX_PATH] = "wscript.exe \"";
		RG_strcat(path, scriptpath);
		RG_strcat(path, "\"");

		APICALL(WinExec_T)(path, SW_SHOW);
	}

	if (flag & RG_ENABLE_MEM_FREE)
	{
		SIZE_T Size = NULL;
		PVOID Address = data1;
		APICALL(NtFreeVirtualMemory_T)(CURRENT_PROCESS, &Address, &Size, MEM_RELEASE);
		APICALL(NtFreeVirtualMemory_T)(CURRENT_PROCESS, &Address, &Size, MEM_RELEASE | MEM_DECOMMIT);
	}

	if (flag & RG_ENABLE_KILL)
	{
		APICALL(NtTerminateProcess_T)(CURRENT_PROCESS, 0);
	}
}