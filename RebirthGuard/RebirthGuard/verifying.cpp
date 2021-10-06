
/*
	chztbby::RebirthGuard/verifying.cpp
*/

#include "RebirthGuard.h"


BOOL IsRebirthed(HANDLE process, PVOID module_base)
{
	PSAPI_WORKING_SET_EX_INFORMATION wsi;
	wsi.VirtualAddress = module_base;
	((NtQueryVirtualMemory_T)ApiCall(ntdll, API_NtQueryVirtualMemory))(process, module_base, MemoryWorkingSetExList, &wsi, sizeof(wsi), 0);

	if (wsi.VirtualAttributes.Locked == 0)
		return FALSE;

	return TRUE;
}

PVOID IsInModule(HANDLE process, PVOID ptr, DWORD type)
{
	LDR_DATA_TABLE_ENTRY list;
	*(PVOID*)&list = 0;

	for (DWORD i = 0; GetNextModule(process, &list); ++i)
	{
		PVOID module_base = *(PVOID*)GetPtr(&list, 0x20);

		PVOID pe_header = GetPEHeader(process, module_base);
		SIZE_T pe_header_size = PAGE_SIZE;
		PIMAGE_NT_HEADERS nt = GetNtHeader(pe_header);
		PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

		SIZE_T execute_size = 0;
		for (DWORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
		{
			if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
				execute_size += PADDING(sec[i].Misc.VirtualSize, nt->OptionalHeader.SectionAlignment);
			else
				break;
		}

		PVOID result = (PVOID)-1;

		if (type == 0 && (DWORD64)module_base + (DWORD64)nt->OptionalHeader.SectionAlignment <= (DWORD64)ptr && (DWORD64)ptr < (DWORD64)module_base + (DWORD64)nt->OptionalHeader.SectionAlignment + execute_size)
			result = module_base;

		if (type == 1 && (DWORD64)module_base <= (DWORD64)ptr && (DWORD64)ptr < (DWORD64)module_base + (DWORD64)nt->OptionalHeader.SizeOfImage)
			result = module_base;

		if (type == 2 && (DWORD64)module_base <= (DWORD64)ptr && (DWORD64)ptr < (DWORD64)module_base + (DWORD64)nt->OptionalHeader.SizeOfImage)
			result = (PVOID)i;

		if (process != CURRENT_PROCESS)
			((NtFreeVirtualMemory_T)ApiCall(ntdll, API_NtFreeVirtualMemory))(CURRENT_PROCESS, &pe_header, &pe_header_size, MEM_RELEASE);

		if (result != (PVOID)-1)
			return result;

	}

	return (PVOID)-1;
}

BOOL IsSameFunction(PVOID f1, PVOID f2)
{
	DWORD count = 0, i = 0;

	for (; *((BYTE*)f1 + i) != 0xCC; i++)
		if (*((BYTE*)f1 + i) == *((BYTE*)f2 + i))
			count++;

	return count == i;
}

VOID ThreadCheck(PVOID start_address, DWORD type)
{
#if RG_OPT_ANTI_DEBUGGING & RG_ENABLE
	((NtSetInformationThread_T)ApiCall(ntdll, API_NtSetInformationThread))(CURRENT_THREAD, ThreadHideFromDebugger, NULL, NULL);
#endif

	MEMORY_BASIC_INFORMATION mbi;
	((NtQueryVirtualMemory_T)ApiCall(ntdll, API_NtQueryVirtualMemory))(CURRENT_PROCESS, start_address, MemoryBasicInformation, &mbi, sizeof(mbi), 0);

#if RG_OPT_THREAD_CHECK & RG_ENABLE
	if (IsInModule(CURRENT_PROCESS, start_address, 0) == (PVOID)-1)
		Report(CURRENT_PROCESS, RG_OPT_THREAD_CHECK, REPORT_THREAD_START_ADDRESS, start_address, (PVOID)type);

	if (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY)
		Report(CURRENT_PROCESS, RG_OPT_THREAD_CHECK, REPORT_THREAD_PROTECTION, start_address, (PVOID)type);
#endif

#if RG_OPT_ANTI_DLL_INJECTION & RG_ENABLE
	if (IsSameFunction(ApiCall(kernel32, API_LoadLibraryA), start_address))
		Report(CURRENT_PROCESS, RG_OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_KERNEL32_LoadLibraryA, start_address, (PVOID)type);

	if (IsSameFunction(ApiCall(kernel32, API_LoadLibraryW), start_address))
		Report(CURRENT_PROCESS, RG_OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_KERNEL32LoadLibraryW_T, start_address, (PVOID)type);

	if (IsSameFunction(ApiCall(kernel32, API_LoadLibraryExA), start_address))
		Report(CURRENT_PROCESS, RG_OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_KERNEL32_LoadLibraryExA, start_address, (PVOID)type);

	if (IsSameFunction(ApiCall(kernel32, API_LoadLibraryExW), start_address))
		Report(CURRENT_PROCESS, RG_OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_KERNEL32_LoadLibraryExW, start_address, (PVOID)type);

	if (IsSameFunction(ApiCall(kernelbase, API_LoadLibraryA), start_address))
		Report(CURRENT_PROCESS, RG_OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_KERNELBASE_LoadLibraryA, start_address, (PVOID)type);

	if (IsSameFunction(ApiCall(kernelbase, API_LoadLibraryW), start_address))
		Report(CURRENT_PROCESS, RG_OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_KERNELBASELoadLibraryW_T, start_address, (PVOID)type);

	if (IsSameFunction(ApiCall(kernelbase, API_LoadLibraryExA), start_address))
		Report(CURRENT_PROCESS, RG_OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_KERNELBASE_LoadLibraryExA, start_address, (PVOID)type);

	if (IsSameFunction(ApiCall(kernelbase, API_LoadLibraryExW), start_address))
		Report(CURRENT_PROCESS, RG_OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_KERNELBASE_LoadLibraryExW, start_address, (PVOID)type);

	if (IsSameFunction(ApiCall(ntdll, API_LdrLoadDll), start_address))
		Report(CURRENT_PROCESS, RG_OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_NTDLL_LdrLoadDll, start_address, (PVOID)type);
#endif
}

VOID DestoryModule(HANDLE process)
{
	LDR_DATA_TABLE_ENTRY list;
	*(PVOID*)&list = 0;

	while (GetNextModule(process, &list))
	{
		WCHAR module_path[MAX_PATH];
		((NtReadVirtualMemory_T)ApiCall(ntdll, API_NtReadVirtualMemory))(process, *(PVOID*)GetPtr(&list, 0x40), module_path, MAX_PATH, NULL);

		PVOID module_base = *(PVOID*)GetPtr(&list, 0x20);
		DWORD protect = NULL;
		PVOID mem = NULL;

		PVOID pe_header = GetPEHeader(process, module_base);
		SIZE_T pe_header_size = PAGE_SIZE;
		PIMAGE_NT_HEADERS nt = GetNtHeader(pe_header);
		PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

		PVOID address = GetPtr(module_base, nt->OptionalHeader.SectionAlignment);
		SIZE_T write_size = NULL;

		for (DWORD i = 0; i < nt->FileHeader.NumberOfSections; i++)
		{
			if (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE)
			{
				write_size = sec[i].VirtualAddress;
				break;
			}
		}

		((NtAllocateVirtualMemory_T)ApiCall(ntdll, API_NtAllocateVirtualMemory))	(CURRENT_PROCESS, &mem, NULL, &write_size, MEM_COMMIT, PAGE_READWRITE);
		((NtProtectVirtualMemory_T)ApiCall(ntdll, API_NtProtectVirtualMemory))	(process, &address, &write_size, PAGE_EXECUTE_READWRITE, &protect);
		((NtWriteVirtualMemory_T)ApiCall(ntdll, API_NtWriteVirtualMemory))	(process, address, mem, write_size, NULL);
		write_size = NULL;
		((NtFreeVirtualMemory_T)ApiCall(ntdll, API_NtFreeVirtualMemory))	(CURRENT_PROCESS, &mem, &write_size, MEM_RELEASE);

		if (process != CURRENT_PROCESS)
			((NtFreeVirtualMemory_T)ApiCall(ntdll, API_NtFreeVirtualMemory))(CURRENT_PROCESS, &pe_header, &pe_header_size, MEM_RELEASE);
	}
}

VOID MemoryCheck(HANDLE process)
{
#if RG_OPT_MEMORY_CHECK & RG_ENABLE
	DestoryModule(process);

	for (PVOID ptr = 0; ptr < (PVOID)0x7FFFFFFF0000;)
	{
		MEMORY_BASIC_INFORMATION mbi;
		((NtQueryVirtualMemory_T)ApiCall(ntdll, API_NtQueryVirtualMemory))(process, ptr, MemoryBasicInformation, &mbi, sizeof(mbi), 0);

		if (mbi.Type == MEM_IMAGE && !(mbi.Protect & PAGE_WRITECOPY))
			Report(process, RG_OPT_MEMORY_CHECK, REPORT_MEMORY_IMAGE, ptr, (PVOID)0);

		else if (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) && IsInModule(process, ptr, 2) == (PVOID)-1)
			Report(process, RG_OPT_MEMORY_CHECK, REPORT_MEMORY_PRIVATE_EXECUTE, ptr, (PVOID)0);

		else if (mbi.Protect == PAGE_EXECUTE_WRITECOPY && IsRebirthed(process, ptr) == FALSE)
			Report(process, RG_OPT_MEMORY_CHECK, REPORT_MEMORY_NOT_REBIRTHED, ptr, (PVOID)0);

		else if (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY)
			Report(process, RG_OPT_MEMORY_CHECK, REPORT_MEMORY_EXECUTE_WRITE, ptr, (PVOID)0);

		else if (mbi.Protect == PAGE_EXECUTE_READ || (IsInModule(process, ptr, 1) == RG_GetModuleHandleEx(CURRENT_PROCESS, NULL)))
		{
			PSAPI_WORKING_SET_EX_INFORMATION wsi;
			wsi.VirtualAddress = ptr;
			((NtQueryVirtualMemory_T)ApiCall(ntdll, API_NtQueryVirtualMemory))(process, ptr, MemoryWorkingSetExList, &wsi, sizeof(wsi), 0);

			if (wsi.VirtualAttributes.Locked == 0)
				Report(process, RG_OPT_MEMORY_CHECK, REPORT_MEMORY_UNLOCKED, ptr, (PVOID)0);

			else if (*((BYTE*)&wsi.VirtualAttributes.Flags + 2) != 0x40)
				Report(process, RG_OPT_MEMORY_CHECK, REPORT_MEMORY_UNLOCKED2, ptr, (PVOID)0);
		}

		ptr = GetPtr(ptr, mbi.RegionSize);
	}
#endif
}

VOID CRCCheck()
{
#if RG_OPT_CRC_CHECK & RG_ENABLE
	LDR_DATA_TABLE_ENTRY list;
	*(PVOID*)&list = 0;

	for (DWORD i = 0; GetNextModule(CURRENT_PROCESS, &list); i++)
	{
		PVOID module_base = RG_GetModuleHandleEx(CURRENT_PROCESS, list.FullDllName.Buffer);
		LPWSTR module_path = (LPWSTR)*(PVOID*)GetPtr(&list, 0x40);

		MEMORY_BASIC_INFORMATION mbi;
		((NtQueryVirtualMemory_T)ApiCall(ntdll, API_NtQueryVirtualMemory))(CURRENT_PROCESS, module_base, MemoryBasicInformation, &mbi, sizeof(mbi), 0);

		if (!(mbi.Protect & PAGE_WRITECOPY))
		{
#if RG_OPT_CRC_HIDE_FROM_DEBUGGER & RG_ENABLE
			for (int i = 0;; i++)
			{
				if (section_list[i].base == NULL)
					Report(CURRENT_PROCESS, RG_OPT_CRC_CHECK, REPORT_CRC64_SECTION, module_base, 0);

				if (section_list[i].base == module_base)
				{
					LARGE_INTEGER section_offset;
					section_offset.QuadPart = NULL;
					PIMAGE_NT_HEADERS nt = GetNtHeader(module_base);
					SIZE_T view_size = nt->OptionalHeader.SizeOfImage;

					module_base = NULL;
					while (!module_base)
					{
						module_base = NULL;
						((NtMapViewOfSection_T)ApiCall(ntdll, API_NtMapViewOfSection))(section_list[i].section, CURRENT_PROCESS, &module_base, NULL, NULL, &section_offset, &view_size, ViewUnmap, SEC_NO_CHANGE, PAGE_READONLY);
					}

					break;
				}
			}
#endif
			PVOID mapped_module = ManualMap(module_path);
			if (i == ntdll)
			{
				SIZE_T RtlUserThreadStart_offset = GetOffset(RG_GetModuleHandleEx(CURRENT_PROCESS, GetModulePath(ntdll)), ApiCall(ntdll, API_RtlUserThreadStart));
				BYTE jmp_myRtlUserThreadStart[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, };
				*(PVOID*)(jmp_myRtlUserThreadStart + 6) = Thread_Callback;
				for (DWORD i = 0; i < 14; i++)
					*(BYTE*)GetPtr(mapped_module, RtlUserThreadStart_offset + i) = jmp_myRtlUserThreadStart[i];
			}

			(GetNtHeader(mapped_module))->OptionalHeader.ImageBase = (SIZE_T)RG_GetModuleHandleEx(CURRENT_PROCESS, module_path);

			if (CRC64(module_base) != CRC64(mapped_module))
				Report(CURRENT_PROCESS, RG_OPT_CRC_CHECK, REPORT_CRC64_INTEGRITY, RG_GetModuleHandleEx(CURRENT_PROCESS, list.FullDllName.Buffer), 0);

#if RG_OPT_CRC_HIDE_FROM_DEBUGGER & RG_ENABLE
			((NtUnmapViewOfSection_T)ApiCall(ntdll, API_NtUnmapViewOfSection))(CURRENT_PROCESS, module_base);
#endif

			SIZE_T image_size = NULL;
			((NtFreeVirtualMemory_T)ApiCall(ntdll, API_NtFreeVirtualMemory))(CURRENT_PROCESS, &mapped_module, &image_size, MEM_RELEASE);
		}
	}
#endif
}