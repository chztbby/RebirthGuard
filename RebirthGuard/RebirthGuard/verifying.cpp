
/*
	chztbby::RebirthGuard/verifying.cpp
*/

#include "RebirthGuard.h"


BOOL IsRebirthed(PVOID module_base)
{
	/*PIMAGE_NT_HEADERS nt = GetNtHeader(module_base);
	PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

	for (DWORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
	{
		if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			PSAPI_WORKING_SET_EX_INFORMATION wsi;
			wsi.VirtualAddress = GetPtr(module_base, sec[i].VirtualAddress);
			RG_QueryMemory(module_base, &wsi, sizeof(wsi), MemoryWorkingSetExList);

			if (!wsi.VirtualAttributes.Locked)
				return FALSE;

			if (*((BYTE*)&wsi.VirtualAttributes.Flags + 2) != 0x40)
				return FALSE;

			break;
		}
	}*/

	MEMORY_BASIC_INFORMATION mbi;
	RG_QueryMemory(module_base, &mbi, sizeof(mbi), MemoryBasicInformation);
	if (mbi.Type == MEM_MAPPED)
		return TRUE;

	return FALSE;
}

PVOID IsInModule(PVOID ptr, DWORD type)
{
	LDR_DATA_TABLE_ENTRY list = { 0, };

	for (DWORD i = 0; RG_GetNextModule(&list); ++i)
	{
		PVOID module_base = *(PVOID*)GetPtr(&list, sizeof(PVOID) * 4);

		PIMAGE_NT_HEADERS nt = GetNtHeader(module_base);
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
			result = (PVOID)(SIZE_T)i;

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

VOID CheckThread(PVOID start_address, THREAD_CHECK type)
{
#if IS_ENABLED(RG_OPT_ANTI_DEBUGGING)
	APICALL(NtSetInformationThread)(CURRENT_THREAD, ThreadHideFromDebugger, NULL, NULL);
#endif

	if (IS_ENABLED(RG_OPT_THREAD_CHECK) || (type == TC_DllCallback && IS_ENABLED(RG_OPT_ANTI_DLL_INJECTION)))
	{
		if (IsInModule(start_address, 0) == (PVOID)-1)
			RG_Report(RG_OPT_THREAD_CHECK, REPORT_THREAD_START_ADDRESS, start_address, (PVOID)(SIZE_T)type);

		MEMORY_BASIC_INFORMATION mbi;
		RG_QueryMemory(start_address, &mbi, sizeof(mbi), MemoryBasicInformation);

		if (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY)
			RG_Report(RG_OPT_THREAD_CHECK, REPORT_THREAD_PROTECTION, start_address, (PVOID)(SIZE_T)type);
	}

#if IS_ENABLED(RG_OPT_ANTI_DLL_INJECTION)
	if (IsSameFunction(APICALL_FROM_MODULE(KERNEL32, LoadLibraryA), start_address))
		RG_Report(RG_OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_KERNEL32_LoadLibraryA, start_address, (PVOID)(SIZE_T)type);

	if (IsSameFunction(APICALL_FROM_MODULE(KERNEL32, LoadLibraryW), start_address))
		RG_Report(RG_OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_KERNEL32_LoadLibraryW, start_address, (PVOID)(SIZE_T)type);

	if (IsSameFunction(APICALL_FROM_MODULE(KERNEL32, LoadLibraryExA), start_address))
		RG_Report(RG_OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_KERNEL32_LoadLibraryExA, start_address, (PVOID)(SIZE_T)type);

	if (IsSameFunction(APICALL_FROM_MODULE(KERNEL32, LoadLibraryExW), start_address))
		RG_Report(RG_OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_KERNEL32_LoadLibraryExW, start_address, (PVOID)(SIZE_T)type);

	if (IsSameFunction(APICALL_FROM_MODULE(KERNELBASE, LoadLibraryA), start_address))
		RG_Report(RG_OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_KERNELBASE_LoadLibraryA, start_address, (PVOID)(SIZE_T)type);

	if (IsSameFunction(APICALL_FROM_MODULE(KERNELBASE, LoadLibraryW), start_address))
		RG_Report(RG_OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_KERNELBASE_LoadLibraryW, start_address, (PVOID)(SIZE_T)type);

	if (IsSameFunction(APICALL_FROM_MODULE(KERNELBASE, LoadLibraryExA), start_address))
		RG_Report(RG_OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_KERNELBASE_LoadLibraryExA, start_address, (PVOID)(SIZE_T)type);

	if (IsSameFunction(APICALL_FROM_MODULE(KERNELBASE, LoadLibraryExW), start_address))
		RG_Report(RG_OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_KERNELBASE_LoadLibraryExW, start_address, (PVOID)(SIZE_T)type);

	if (IsSameFunction(APICALL_FROM_MODULE(NTDLL, LdrLoadDll), start_address))
		RG_Report(RG_OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_NTDLL_LdrLoadDll, start_address, (PVOID)(SIZE_T)type);
#endif
}

VOID CheckFullMemory()
{
#if IS_ENABLED(RG_OPT_MEMORY_CHECK)
#ifdef _WIN64
	for (PVOID ptr = 0; ptr < (PVOID)0x7FFFFFFFFFFF;)
#else
	for (PVOID ptr = 0; ptr < (PVOID)0x7FFFFFFF;)
#endif
	{
		MEMORY_BASIC_INFORMATION mbi;
		RG_QueryMemory(ptr, &mbi, sizeof(mbi), MemoryBasicInformation);
		CheckMemory(ptr);

		ptr = GetPtr(ptr, mbi.RegionSize);
	}

#if IS_ENABLED(RG_OPT_INTEGRITY_CHECK)
	CheckCRC();
#endif
#endif
}

VOID CheckMemory(PVOID ptr)
{
	MEMORY_BASIC_INFORMATION mbi;
	RG_QueryMemory(ptr, &mbi, sizeof(mbi), MemoryBasicInformation);

	if (mbi.Type == MEM_IMAGE && !(mbi.Protect & PAGE_WRITECOPY))
		RG_Report(RG_OPT_MEMORY_CHECK, REPORT_MEMORY_IMAGE, ptr, (PVOID)0);

	else if (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) && IsInModule(ptr, 2) == (PVOID)-1)
		RG_Report(RG_OPT_MEMORY_CHECK, REPORT_MEMORY_PRIVATE_EXECUTE, ptr, (PVOID)0);

	else if (mbi.Protect == PAGE_EXECUTE_WRITECOPY && !IsRebirthed(ptr))
		RG_Report(RG_OPT_MEMORY_CHECK, REPORT_MEMORY_NOT_REBIRTHED, ptr, (PVOID)0);

	else if (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY)
		RG_Report(RG_OPT_MEMORY_CHECK, REPORT_MEMORY_EXECUTE_WRITE, ptr, (PVOID)0);

	else if (mbi.Protect == PAGE_EXECUTE_READ || (IsInModule(ptr, 1) == RG_GetModuleHandleW(RG_GetModulePath((DWORD)EXE))))
	{
		PSAPI_WORKING_SET_EX_INFORMATION wsi;
		wsi.VirtualAddress = ptr;
		RG_QueryMemory(ptr, &wsi, sizeof(wsi), MemoryWorkingSetExList);

		if (!wsi.VirtualAttributes.Locked)
			RG_Report(RG_OPT_MEMORY_CHECK, REPORT_MEMORY_UNLOCKED, ptr, (PVOID)0);

		else if (*((BYTE*)&wsi.VirtualAttributes.Flags + 2) != 0x40)
			RG_Report(RG_OPT_MEMORY_CHECK, REPORT_MEMORY_UNLOCKED2, ptr, (PVOID)0);
	}
}

VOID CheckCRC()
{
	LDR_DATA_TABLE_ENTRY list = { 0, };

	for (DWORD i = 0; RG_GetNextModule(&list); i++)
	{
		PVOID module_base = RG_GetModuleHandleW(list.FullDllName.Buffer);
		LPWSTR module_path = (LPWSTR)*(PVOID*)GetPtr(&list, 0x40);

		MEMORY_BASIC_INFORMATION mbi;
		RG_QueryMemory(module_base, &mbi, sizeof(mbi), MemoryBasicInformation);

		if (!(mbi.Protect & PAGE_WRITECOPY))
		{
#if IS_ENABLED(RG_OPT_INTEGRITY_CHECK_HIDE_FROM_DEBUGGER)
			for (int i = 0;; i++)
			{
				if (!rebirthed_module_list[i].module_base)
					RG_Report(RG_OPT_INTEGRITY_CHECK, REPORT_INTEGRITY_SECTION_CHECK, module_base, 0);

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
						APICALL(NtMapViewOfSection_T)(rebirthed_module_list[i].section, CURRENT_PROCESS, &module_base, NULL, NULL, &section_offset, &view_size, ViewUnmap, SEC_NO_CHANGE, PAGE_READONLY);
					}

					break;
				}
			}
#endif
			PVOID mapped_module = ManualMap(module_path);
#ifdef _WIN64
#if IS_ENABLED(RG_OPT_THREAD_CHECK)
			if (i == NTDLL)
			{
				SIZE_T RtlUserThreadStart_offset = GetOffset(RG_GetModuleHandleW(RG_GetModulePath(NTDLL)), APICALL(RtlUserThreadStart));
				BYTE jmp_myRtlUserThreadStart[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, };
				*(PVOID*)(jmp_myRtlUserThreadStart + 6) = ThreadCallback;
				for (DWORD i = 0; i < 14; i++)
					*(BYTE*)GetPtr(mapped_module, RtlUserThreadStart_offset + i) = jmp_myRtlUserThreadStart[i];
			}
#endif
#else
#if IS_ENABLED(RG_OPT_THREAD_CHECK)

#endif
#endif
			(GetNtHeader(mapped_module))->OptionalHeader.ImageBase = (SIZE_T)RG_GetModuleHandleW(module_path);

			if (CRC64(module_base) != CRC64(mapped_module))
				RG_Report(RG_OPT_INTEGRITY_CHECK, REPORT_INTEGRITY_CRC64_CHECK, RG_GetModuleHandleW(list.FullDllName.Buffer), 0);

#if IS_ENABLED(RG_OPT_INTEGRITY_CHECK_HIDE_FROM_DEBUGGER)
			APICALL(NtUnmapViewOfSection_T)(CURRENT_PROCESS, module_base);
#endif

			RG_FreeMemory(mapped_module);
		}
	}
}