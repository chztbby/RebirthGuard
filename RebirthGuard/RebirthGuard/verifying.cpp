
/*
	chztbby::RebirthGuard/verifying.cpp
*/

#include "RebirthGuard.h"


BOOL IsRebirthed(HANDLE process, PVOID module_base)
{
	PIMAGE_NT_HEADERS nt = GetNtHeader(module_base);
	PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

	for (DWORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
	{
		if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			PSAPI_WORKING_SET_EX_INFORMATION wsi;
			wsi.VirtualAddress = GetPtr(module_base, sec[i].VirtualAddress);
			((NtQueryVirtualMemory_T)ApiCall(API_NtQueryVirtualMemory))(process, module_base, MemoryWorkingSetExList, &wsi, sizeof(wsi), 0);

			if (wsi.VirtualAttributes.Locked == 0)
				return FALSE;

			if (*((BYTE*)&wsi.VirtualAttributes.Flags + 2) != 0x40)
				return FALSE;

			break;
		}
	}

	return TRUE;
}

PVOID IsInModule(HANDLE process, PVOID ptr, DWORD type)
{
	LDR_DATA_TABLE_ENTRY list;
	*(PVOID*)&list = 0;

	for (DWORD i = 0; GetNextModule(process, &list); ++i)
	{
		PVOID module_base = *(PVOID*)GetPtr(&list, sizeof(PVOID) * 4);

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

		if (type == 0 && (SIZE_T)module_base + (SIZE_T)nt->OptionalHeader.SectionAlignment <= (SIZE_T)ptr && (SIZE_T)ptr < (SIZE_T)module_base + (SIZE_T)nt->OptionalHeader.SectionAlignment + execute_size)
			result = module_base;

		if (type == 1 && (SIZE_T)module_base <= (SIZE_T)ptr && (SIZE_T)ptr < (SIZE_T)module_base + (SIZE_T)nt->OptionalHeader.SizeOfImage)
			result = module_base;

		if (type == 2 && (SIZE_T)module_base <= (SIZE_T)ptr && (SIZE_T)ptr < (SIZE_T)module_base + (SIZE_T)nt->OptionalHeader.SizeOfImage)
			result = (PVOID)i;

		if (process != CURRENT_PROCESS)
			((NtFreeVirtualMemory_T)ApiCall(API_NtFreeVirtualMemory))(CURRENT_PROCESS, &pe_header, &pe_header_size, MEM_RELEASE);

		if (result != (PVOID)-1)
			return result;

		/*
			Release pe_header
		*/
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

VOID CheckThread(PVOID start_address, DWORD type)
{
#if RG_OPT_ANTI_DEBUGGING & RG_ENABLE
	((NtSetInformationThread_T)ApiCall(API_NtSetInformationThread))(CURRENT_THREAD, ThreadHideFromDebugger, NULL, NULL);
#endif

	MEMORY_BASIC_INFORMATION mbi;
	((NtQueryVirtualMemory_T)ApiCall(API_NtQueryVirtualMemory))(CURRENT_PROCESS, start_address, MemoryBasicInformation, &mbi, sizeof(mbi), 0);

	if (IsInModule(CURRENT_PROCESS, start_address, 0) == (PVOID)-1)
		Report(CURRENT_PROCESS, RG_OPT_THREAD_CHECK, REPORT_THREAD_START_ADDRESS, start_address, (PVOID)type);

	if (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY)
		Report(CURRENT_PROCESS, RG_OPT_THREAD_CHECK, REPORT_THREAD_PROTECTION, start_address, (PVOID)type);

#if RG_OPT_ANTI_DLL_INJECTION & RG_ENABLE
	if (IsSameFunction(ApiCall(MODULE_KERNEL32, API_LoadLibraryA), start_address))
		Report(CURRENT_PROCESS, RG_OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_KERNEL32_LoadLibraryA, start_address, (PVOID)type);

	if (IsSameFunction(ApiCall(MODULE_KERNEL32, API_LoadLibraryW), start_address))
		Report(CURRENT_PROCESS, RG_OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_KERNEL32_LoadLibraryW, start_address, (PVOID)type);

	if (IsSameFunction(ApiCall(MODULE_KERNEL32, API_LoadLibraryExA), start_address))
		Report(CURRENT_PROCESS, RG_OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_KERNEL32_LoadLibraryExA, start_address, (PVOID)type);

	if (IsSameFunction(ApiCall(MODULE_KERNEL32, API_LoadLibraryExW), start_address))
		Report(CURRENT_PROCESS, RG_OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_KERNEL32_LoadLibraryExW, start_address, (PVOID)type);

	if (IsSameFunction(ApiCall(MODULE_KERNELBASE, API_LoadLibraryA), start_address))
		Report(CURRENT_PROCESS, RG_OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_KERNELBASE_LoadLibraryA, start_address, (PVOID)type);

	if (IsSameFunction(ApiCall(MODULE_KERNELBASE, API_LoadLibraryW), start_address))
		Report(CURRENT_PROCESS, RG_OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_KERNELBASE_LoadLibraryW, start_address, (PVOID)type);

	if (IsSameFunction(ApiCall(MODULE_KERNELBASE, API_LoadLibraryExA), start_address))
		Report(CURRENT_PROCESS, RG_OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_KERNELBASE_LoadLibraryExA, start_address, (PVOID)type);

	if (IsSameFunction(ApiCall(MODULE_KERNELBASE, API_LoadLibraryExW), start_address))
		Report(CURRENT_PROCESS, RG_OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_KERNELBASE_LoadLibraryExW, start_address, (PVOID)type);

	if (IsSameFunction(ApiCall(MODULE_NTDLL, API_LdrLoadDll), start_address))
		Report(CURRENT_PROCESS, RG_OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_NTDLL_LdrLoadDll, start_address, (PVOID)type);
#endif
}

VOID CheckFullMemory()
{
#if RG_OPT_MEMORY_CHECK & RG_ENABLE
#ifdef _WIN64
	for (PVOID ptr = 0; ptr < (PVOID)0x7FFFFFFFFFFF;)
#else
	for (PVOID ptr = 0; ptr < (PVOID)0x7FFFFFFF;)
#endif
	{
		MEMORY_BASIC_INFORMATION mbi;
		((NtQueryVirtualMemory_T)ApiCall(API_NtQueryVirtualMemory))(CURRENT_PROCESS, ptr, MemoryBasicInformation, &mbi, sizeof(mbi), 0);

		CheckMemory(ptr);

		ptr = GetPtr(ptr, mbi.RegionSize);
	}

#if RG_OPT_CRC_CHECK & RG_ENABLE
	CheckCRC();
#endif
#endif
}

VOID CheckMemory(PVOID ptr)
{
	MEMORY_BASIC_INFORMATION mbi;
	((NtQueryVirtualMemory_T)ApiCall(API_NtQueryVirtualMemory))(CURRENT_PROCESS, ptr, MemoryBasicInformation, &mbi, sizeof(mbi), 0);

	if (mbi.Type == MEM_IMAGE && !(mbi.Protect & PAGE_WRITECOPY))
		Report(CURRENT_PROCESS, RG_OPT_MEMORY_CHECK, REPORT_MEMORY_IMAGE, ptr, (PVOID)0);

	else if (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) && IsInModule(CURRENT_PROCESS, ptr, 2) == (PVOID)-1)
		Report(CURRENT_PROCESS, RG_OPT_MEMORY_CHECK, REPORT_MEMORY_PRIVATE_EXECUTE, ptr, (PVOID)0);

	else if (mbi.Protect == PAGE_EXECUTE_WRITECOPY && IsRebirthed(CURRENT_PROCESS, ptr) == FALSE)
		Report(CURRENT_PROCESS, RG_OPT_MEMORY_CHECK, REPORT_MEMORY_NOT_REBIRTHED, ptr, (PVOID)0);

	else if (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY)
		Report(CURRENT_PROCESS, RG_OPT_MEMORY_CHECK, REPORT_MEMORY_EXECUTE_WRITE, ptr, (PVOID)0);

	else if (mbi.Protect == PAGE_EXECUTE_READ || (IsInModule(CURRENT_PROCESS, ptr, 1) == RG_GetModuleHandleEx(CURRENT_PROCESS, NULL)))
	{
		PSAPI_WORKING_SET_EX_INFORMATION wsi;
		wsi.VirtualAddress = ptr;
		((NtQueryVirtualMemory_T)ApiCall(API_NtQueryVirtualMemory))(CURRENT_PROCESS, ptr, MemoryWorkingSetExList, &wsi, sizeof(wsi), 0);

		if (wsi.VirtualAttributes.Locked == 0)
			Report(CURRENT_PROCESS, RG_OPT_MEMORY_CHECK, REPORT_MEMORY_UNLOCKED, ptr, (PVOID)0);

		else if (*((BYTE*)&wsi.VirtualAttributes.Flags + 2) != 0x40)
			Report(CURRENT_PROCESS, RG_OPT_MEMORY_CHECK, REPORT_MEMORY_UNLOCKED2, ptr, (PVOID)0);
	}
}

VOID CheckCRC()
{
#if RG_OPT_CRC_CHECK & RG_ENABLE
	LDR_DATA_TABLE_ENTRY list;
	*(PVOID*)&list = 0;

	for (DWORD i = 0; GetNextModule(CURRENT_PROCESS, &list); i++)
	{
		PVOID module_base = RG_GetModuleHandleEx(CURRENT_PROCESS, list.FullDllName.Buffer);
		LPWSTR module_path = (LPWSTR)*(PVOID*)GetPtr(&list, 0x40);

		MEMORY_BASIC_INFORMATION mbi;
		((NtQueryVirtualMemory_T)ApiCall(API_NtQueryVirtualMemory))(CURRENT_PROCESS, module_base, MemoryBasicInformation, &mbi, sizeof(mbi), 0);

		if (!(mbi.Protect & PAGE_WRITECOPY))
		{
#if RG_OPT_CRC_HIDE_FROM_DEBUGGER & RG_ENABLE
			for (int i = 0;; i++)
			{
				if (rebirthed_module_list[i].module_base == NULL)
					Report(CURRENT_PROCESS, RG_OPT_CRC_CHECK, REPORT_CRC64_SECTION, module_base, 0);

				if (rebirthed_module_list[i].module_base == module_base)
				{
					LARGE_INTEGER section_offset;
					section_offset.QuadPart = NULL;
					PIMAGE_NT_HEADERS nt = GetNtHeader(module_base);
					SIZE_T view_size = nt->OptionalHeader.SizeOfImage;

					module_base = NULL;
					while (!module_base)
					{
						module_base = NULL;
						((NtMapViewOfSection_T)ApiCall(API_NtMapViewOfSection))(rebirthed_module_list[i].section, CURRENT_PROCESS, &module_base, NULL, NULL, &section_offset, &view_size, ViewUnmap, SEC_NO_CHANGE, PAGE_READONLY);
					}

					break;
				}
			}
#endif
			PVOID mapped_module = ManualMap(module_path);
#if RG_OPT_THREAD_CHECK & RG_ENABLE
			if (i == MODULE_NTDLL)
			{
				SIZE_T RtlUserThreadStart_offset = GetOffset(RG_GetModuleHandleEx(CURRENT_PROCESS, GetModulePath(MODULE_NTDLL)), ApiCall(API_RtlUserThreadStart));
				BYTE jmp_myRtlUserThreadStart[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, };
				*(PVOID*)(jmp_myRtlUserThreadStart + 6) = ThreadCallback;
				for (DWORD i = 0; i < 14; i++)
					*(BYTE*)GetPtr(mapped_module, RtlUserThreadStart_offset + i) = jmp_myRtlUserThreadStart[i];
			}
#endif
			(GetNtHeader(mapped_module))->OptionalHeader.ImageBase = (SIZE_T)RG_GetModuleHandleEx(CURRENT_PROCESS, module_path);

			if (CRC64(module_base) != CRC64(mapped_module))
				Report(CURRENT_PROCESS, RG_OPT_CRC_CHECK, REPORT_CRC64_INTEGRITY, RG_GetModuleHandleEx(CURRENT_PROCESS, list.FullDllName.Buffer), 0);

#if RG_OPT_CRC_HIDE_FROM_DEBUGGER & RG_ENABLE
			((NtUnmapViewOfSection_T)ApiCall(API_NtUnmapViewOfSection))(CURRENT_PROCESS, module_base);
#endif

			SIZE_T image_size = NULL;
			((NtFreeVirtualMemory_T)ApiCall(API_NtFreeVirtualMemory))(CURRENT_PROCESS, &mapped_module, &image_size, MEM_RELEASE);
		}
	}
#endif
}