
/*
	chztbby::RebirthGuard/util.cpp
*/

#include "RebirthGuard.h"

LPWSTR RG_GetModulePath(DWORD module_index)
{
	static WCHAR module_path[MODULE_LAST + 1][MAX_PATH] = { 0, };

	if (!module_path[module_index][0])
	{
		LDR_DATA_TABLE_ENTRY list = { 0, };
		for (DWORD i = MODULE_FIRST; i <= module_index; i++)
			RG_GetNextModule(&list);

		RG_wcscpy(module_path[module_index], (LPCWSTR)*(PVOID*)(GetPtr(&list, sizeof(PVOID) * 8)));
	}

	return module_path[module_index];
}

PVOID RG_GetNextModule(PLDR_DATA_TABLE_ENTRY plist)
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

VOID RG_HideModule(PVOID hmodule)
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

FARPROC RG_GetApi(API_INDEX api_index)
{
	CHAR api_name[50];
	DecryptXOR(api_name, api_index);

	FARPROC api = NULL;

	for (DWORD i = MODULE_FIRST; i <= MODULE_LAST && !api; ++i)
		api = GetProcAddress(RG_GetModuleHandleW(RG_GetModulePath(i)), api_name);

	for (DWORD i = 0; i < sizeof(api_name); i++)
		api_name[i] = 0;

	return api;
}

FARPROC RG_GetApi(DWORD module_index, API_INDEX api_index)
{
	CHAR api_name[50];
	DecryptXOR(api_name, api_index);

	FARPROC api = GetProcAddress(RG_GetModuleHandleW(RG_GetModulePath(module_index)), api_name);

	for (DWORD i = 0; i < sizeof(api_name); i++)
		api_name[i] = 0;

	return api;
}

HMODULE RG_GetModuleHandleW(LPCWSTR module_path)
{
	LDR_DATA_TABLE_ENTRY list = { 0, };

	while (RG_GetNextModule(&list))
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

PVOID RG_AllocMemory(PVOID ptr, SIZE_T size, DWORD protect)
{
	APICALL(NtAllocateVirtualMemory_T)(CURRENT_PROCESS, &ptr, NULL, &size, MEM_COMMIT | MEM_RESERVE, protect);
	return ptr;
}

VOID RG_FreeMemory(PVOID ptr)
{
	SIZE_T size = NULL;
	APICALL(NtFreeVirtualMemory_T)(CURRENT_PROCESS, &ptr, &size, MEM_RELEASE);
}

DWORD RG_ProtectMemory(PVOID ptr, SIZE_T size, DWORD protect)
{
	DWORD old = NULL;
	APICALL(NtProtectVirtualMemory_T)(CURRENT_PROCESS, &ptr, &size, protect, &old);
	return old;
}

VOID RG_QueryMemory(PVOID ptr, PVOID buffer, SIZE_T buffer_size, DWORD type)
{
	APICALL(NtQueryVirtualMemory_T)(CURRENT_PROCESS, ptr, type, buffer, buffer_size, NULL);
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