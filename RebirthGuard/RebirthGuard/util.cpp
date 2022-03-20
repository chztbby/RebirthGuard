
/*
	chztbby::RebirthGuard/util.cpp
*/

#include "RebirthGuard.h"

LPWSTR RG_GetModulePath(DWORD module_index)
{
	static WCHAR module_path[MODULE_LAST + 1][MAX_PATH] = { 0, };

	if (!module_path[module_index][0])
	{
		LDR_MODULE module_info = { 0, };
		for (DWORD i = MODULE_FIRST; i <= module_index; i++)
			RG_GetNextModule(&module_info);

		RG_wcscpy(module_path[module_index], module_info.FullDllName.Buffer);
	}

	return module_path[module_index];
}

LPCWSTR RG_GetModulePath(PVOID hmodule)
{
	LDR_MODULE module_info = { 0, };
	while (RG_GetNextModule(&module_info))
	{
		if (hmodule == module_info.BaseAddress)
			return module_info.FullDllName.Buffer;
	}

	return NULL;
}

PVOID RG_GetNextModule(PLDR_MODULE pmodule_info)
{
	PLDR_MODULE flink;
	if (!pmodule_info->BaseAddress)
	{
#ifdef _WIN64
		PTEB teb = (PTEB)__readgsqword(0x30);		
#else
		PTEB teb = (PTEB)__readfsdword(0x18);
#endif
		flink = (PLDR_MODULE)teb->Peb->LoaderData->InMemoryOrderModuleList.Flink;
		
	}
	else
	{
		flink = (PLDR_MODULE)pmodule_info->InMemoryOrderModuleList.Flink;
	}

	PLDR_MODULE base = (PLDR_MODULE)GetPtr(flink, GetOffset(&flink->InMemoryOrderModuleList, flink));
	*pmodule_info = *base;

	return pmodule_info->BaseAddress;
}

VOID RG_HideModule(PVOID hmodule)
{
#if IS_ENABLED(RG_OPT_HIDE_MODULE)
#ifdef _WIN64
	PTEB teb = (PTEB)__readgsqword(0x30);
#else
	PTEB teb = (PTEB)__readfsdword(0x18);
#endif
	for (PLIST_ENTRY node = teb->Peb->LoaderData->InLoadOrderModuleList.Flink; node; node = node->Flink)
	{
		if (((PLDR_MODULE)node)->BaseAddress == hmodule)
		{
			node->Blink->Flink = node->Flink;
			node->Flink->Blink = node->Blink;
			break;
		}
	}
#endif
}

PVOID RG_GetApi(LPCSTR api_name, DWORD module_index)
{
    if (module_index)
        return RG_GetProcAddress(RG_GetModuleHandleW(RG_GetModulePath(module_index)), api_name);

    PVOID api = RG_GetProcAddress(RG_GetModuleHandleW(RG_GetModulePath(MODULE_NTDLL)), api_name);
    if (!api)
        api = RG_GetProcAddress(RG_GetModuleHandleW(RG_GetModulePath(MODULE_KERNELBASE)), api_name);
    if (!api)
        api = RG_GetProcAddress(RG_GetModuleHandleW(RG_GetModulePath(MODULE_KERNEL32)), api_name);

    return api;
}

HMODULE RG_GetModuleHandleW(LPCWSTR module_path)
{
	LDR_MODULE module_info = { 0, };
	while (RG_GetNextModule(&module_info))
	{
		if (!module_path)
			return module_info.BaseAddress;

		if (RG_wcsistr(module_path, module_info.BaseDllName.Buffer))
			return module_info.BaseAddress;
	}

	return NULL;
}

PVOID RG_GetProcAddress(HMODULE hmodule, LPCSTR proc_name)
{
	PIMAGE_NT_HEADERS pnh = GetNtHeader(hmodule);
	PIMAGE_DATA_DIRECTORY pdd = &pnh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	PIMAGE_EXPORT_DIRECTORY ped = (PIMAGE_EXPORT_DIRECTORY)GetPtr(hmodule, pdd->VirtualAddress);

	PDWORD func_table = (PDWORD)GetPtr(hmodule, ped->AddressOfFunctions);
	PWORD ordinal_table = (PWORD)GetPtr(hmodule, ped->AddressOfNameOrdinals);

	if ((DWORD_PTR)proc_name <= 0xFFFF)
	{
		WORD ordinal = (WORD)IMAGE_ORDINAL((DWORD_PTR)proc_name);
		ordinal -= (WORD)ped->Base;
		if (ordinal < ped->NumberOfFunctions)
			return GetPtr(hmodule, func_table[ordinal]);
	}
	else
	{
		PDWORD func_name_table = (PDWORD)GetPtr(hmodule, ped->AddressOfNames);
		for (DWORD i = 0; i < ped->NumberOfNames; ++i)
			if (!RG_strcmp(proc_name, (LPCSTR)GetPtr(hmodule, func_name_table[i])))
				return GetPtr(hmodule, func_table[ordinal_table[i]]);
	}
	return NULL;
}

HANDLE RG_CreateThread(HANDLE process, PVOID entry, PVOID param)
{
	HANDLE thread = NULL;
	APICALL(NtCreateThreadEx)(&thread, MAXIMUM_ALLOWED, NULL, process, entry, param, NULL, NULL, NULL, NULL, NULL);
	return thread;
}

PVOID RG_AllocMemory(PVOID ptr, SIZE_T size, DWORD protect)
{
	APICALL(NtAllocateVirtualMemory)(CURRENT_PROCESS, &ptr, NULL, &size, MEM_COMMIT | MEM_RESERVE, protect);
	return ptr;
}

VOID RG_FreeMemory(PVOID ptr)
{
	MEMORY_BASIC_INFORMATION mbi;
	RG_QueryMemory(ptr, &mbi, sizeof(mbi), MemoryBasicInformation);

	if (mbi.Type == MEM_PRIVATE)
		APICALL(NtFreeVirtualMemory)(CURRENT_PROCESS, &mbi.AllocationBase, &mbi.RegionSize, MEM_RELEASE);
	else
		APICALL(NtUnmapViewOfSection)(CURRENT_PROCESS, mbi.AllocationBase);
}

DWORD RG_ProtectMemory(PVOID ptr, SIZE_T size, DWORD protect)
{
	DWORD old = NULL;
	APICALL(NtProtectVirtualMemory)(CURRENT_PROCESS, &ptr, &size, protect, &old);
	return old;
}

NTSTATUS RG_QueryMemory(PVOID ptr, PVOID buffer, SIZE_T buffer_size, MEMORY_INFORMATION_CLASS type)
{
	return APICALL(NtQueryVirtualMemory)(CURRENT_PROCESS, ptr, type, buffer, buffer_size, NULL);
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
	APICALL(RtlAddVectoredExceptionHandler)(1, RG_ExceptionHandler);

	PVOID cookie = NULL;
	APICALL(LdrRegisterDllNotification)(NULL, DllCallback, NULL, &cookie);
	cookie = NULL;
}

BOOL IsExe(PVOID hmodule)
{
	return !(GetNtHeader(hmodule)->FileHeader.Characteristics & IMAGE_FILE_DLL);
}

PVOID GetCurrentThreadStartAddress()
{
	PVOID start_address = NULL;
	APICALL(NtQueryInformationThread)(CURRENT_THREAD, (THREADINFOCLASS)ThreadQuerySetWin32StartAddress, &start_address, sizeof(start_address), 0);

	return start_address;
}

VOID CopyPeData(PVOID dst, PVOID src, PE_TYPE src_type)
{
	PIMAGE_NT_HEADERS nt = GetNtHeader(src);
	PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

	memcpy(dst, src, nt->OptionalHeader.SizeOfHeaders);

	for (DWORD i = 0; i < nt->FileHeader.NumberOfSections; i++)
	{
		if (src_type == PE_TYPE_IMAGE)
			memcpy(GetPtr(dst, sec[i].VirtualAddress), GetPtr(src, sec[i].VirtualAddress), sec[i].Misc.VirtualSize);

		if (src_type == PE_TYPE_FILE)
			memcpy(GetPtr(dst, sec[i].VirtualAddress), GetPtr(src, sec[i].PointerToRawData), sec[i].SizeOfRawData);
	}
}