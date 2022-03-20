
/*
	chztbby::RebirthGuard/verifying.cpp
*/

#include "RebirthGuard.h"


BOOL IsRebirthed(PVOID module_base)
{
	PIMAGE_NT_HEADERS nt = GetNtHeader(module_base);
	PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (DWORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
    {
        MEMORY_BASIC_INFORMATION mbi;
        RG_QueryMemory(GetPtr(module_base, sec[i].VirtualAddress), &mbi, sizeof(mbi), MemoryBasicInformation);

        PSAPI_WORKING_SET_EX_INFORMATION wsi;
        wsi.VirtualAddress = mbi.AllocationBase;
        RG_QueryMemory(nullptr, &wsi, sizeof(wsi), MemoryWorkingSetExInformation);

        if (!wsi.VirtualAttributes.Locked)
            return FALSE;
    }

	return TRUE;
}

PVOID GetModuleBaseFromPtr(PVOID ptr, PTR_CHECK type)
{
	LDR_MODULE module_info = { 0, };
	for (DWORD i = 0; RG_GetNextModule(&module_info); ++i)
	{
		PVOID module_base = module_info.BaseAddress;
		PIMAGE_NT_HEADERS nt = GetNtHeader(module_base);
		PVOID sptr;
		PVOID eptr;

		if (type == PC_EXECUTABLE)
		{
			PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
			for (DWORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
			{
                if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
                {
					sptr = GetPtr(module_base, sec[i].VirtualAddress);
					eptr = GetPtr(sptr, sec[i].Misc.VirtualSize);
                    if (sptr <= ptr && ptr < eptr)
                        return module_base;
				}
			}
		}

		if (type == PC_IMAGE_SIZE)
		{
			sptr = module_base;
			eptr = GetPtr(sptr, nt->OptionalHeader.SizeOfImage);
			if (sptr <= ptr && ptr < eptr)
				return module_base;
		}
	}

	return nullptr;
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
		if (!GetModuleBaseFromPtr(start_address, PC_EXECUTABLE))
			RG_Report(type == TC_DllCallback ? RG_OPT_ANTI_DLL_INJECTION : RG_OPT_THREAD_CHECK, REPORT_THREAD_START_ADDRESS, start_address, (PVOID)(SIZE_T)type);

		MEMORY_BASIC_INFORMATION mbi;
		RG_QueryMemory(start_address, &mbi, sizeof(mbi), MemoryBasicInformation);

		if (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY)
			RG_Report(type == TC_DllCallback ? RG_OPT_ANTI_DLL_INJECTION : RG_OPT_THREAD_CHECK, REPORT_THREAD_PROTECTION, start_address, (PVOID)(SIZE_T)type);
	}

#if IS_ENABLED(RG_OPT_ANTI_DLL_INJECTION)
	if (IsSameFunction(APICALL_FROM_MODULE(MODULE_KERNEL32, LoadLibraryA), start_address))
		RG_Report(RG_OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_KERNEL32_LoadLibraryA, start_address, (PVOID)(SIZE_T)type);

	if (IsSameFunction(APICALL_FROM_MODULE(MODULE_KERNEL32, LoadLibraryW), start_address))
		RG_Report(RG_OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_KERNEL32_LoadLibraryW, start_address, (PVOID)(SIZE_T)type);

	if (IsSameFunction(APICALL_FROM_MODULE(MODULE_KERNEL32, LoadLibraryExA), start_address))
		RG_Report(RG_OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_KERNEL32_LoadLibraryExA, start_address, (PVOID)(SIZE_T)type);

	if (IsSameFunction(APICALL_FROM_MODULE(MODULE_KERNEL32, LoadLibraryExW), start_address))
		RG_Report(RG_OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_KERNEL32_LoadLibraryExW, start_address, (PVOID)(SIZE_T)type);

	if (IsSameFunction(APICALL_FROM_MODULE(MODULE_KERNELBASE, LoadLibraryA), start_address))
		RG_Report(RG_OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_KERNELBASE_LoadLibraryA, start_address, (PVOID)(SIZE_T)type);

	if (IsSameFunction(APICALL_FROM_MODULE(MODULE_KERNELBASE, LoadLibraryW), start_address))
		RG_Report(RG_OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_KERNELBASE_LoadLibraryW, start_address, (PVOID)(SIZE_T)type);

	if (IsSameFunction(APICALL_FROM_MODULE(MODULE_KERNELBASE, LoadLibraryExA), start_address))
		RG_Report(RG_OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_KERNELBASE_LoadLibraryExA, start_address, (PVOID)(SIZE_T)type);

	if (IsSameFunction(APICALL_FROM_MODULE(MODULE_KERNELBASE, LoadLibraryExW), start_address))
		RG_Report(RG_OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_KERNELBASE_LoadLibraryExW, start_address, (PVOID)(SIZE_T)type);

	if (IsSameFunction(APICALL_FROM_MODULE(MODULE_NTDLL, LdrLoadDll), start_address))
		RG_Report(RG_OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_NTDLL_LdrLoadDll, start_address, (PVOID)(SIZE_T)type);
#endif
}

VOID CheckMemory()
{
#if IS_ENABLED(RG_OPT_MEMORY_CHECK)
	for (PVOID ptr = 0; ptr < (PVOID)MEMORY_END;)
	{
		MEMORY_BASIC_INFORMATION mbi;
		RG_QueryMemory(ptr, &mbi, sizeof(mbi), MemoryBasicInformation);

		if (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) && !GetModuleBaseFromPtr(ptr, PC_IMAGE_SIZE))
        {
            BYTE buffer[PAGE_SIZE] = { 0, };
            NTSTATUS ns = RG_QueryMemory(ptr, buffer, sizeof(buffer), MemoryMappedFilenameInformation);
			if (!NT_SUCCESS(ns))
				RG_Report(RG_OPT_MEMORY_CHECK, REPORT_MEMORY_SUSPICIOUS, ptr, (PVOID)(SIZE_T)mbi.Protect);
        }

		ptr = GetPtr(ptr, mbi.RegionSize);
	}

	for (DWORD i = 0; rgdata->rmi[i].module_base; i++)
	{
        PVOID module_base = rgdata->rmi[i].module_base;
		if (!IsRebirthed(module_base))
			RG_Report(RG_OPT_MEMORY_CHECK, REPORT_MEMORY_UNLOCKED, module_base, 0);
	}
#endif
}

VOID CheckCRC()
{
#if IS_ENABLED(RG_OPT_INTEGRITY_CHECK)
	LDR_MODULE module_info = { 0, };

	for (DWORD i = 0; RG_GetNextModule(&module_info); i++)
	{
		PVOID module_base = module_info.BaseAddress;
		LPWSTR module_path = module_info.FullDllName.Buffer;

		MEMORY_BASIC_INFORMATION mbi;
		RG_QueryMemory(module_base, &mbi, sizeof(mbi), MemoryBasicInformation);

		if (!(mbi.Protect & PAGE_WRITECOPY))
		{
#if IS_ENABLED(RG_OPT_INTEGRITY_CHECK_HIDE_FROM_DEBUGGER)
			for (int i = 0;; i++)
			{
				if (!rgdata->rmi[i].module_base)
					RG_Report(RG_OPT_INTEGRITY_CHECK, REPORT_INTEGRITY_SECTION_CHECK, module_base, 0);

				if (rgdata->rmi[i].module_base == module_base)
				{
					LARGE_INTEGER section_offset;
					section_offset.QuadPart = NULL;
					PIMAGE_NT_HEADERS nt = GetNtHeader(module_base);
					SIZE_T view_size = nt->OptionalHeader.SizeOfImage;

					module_base = NULL;
					while (!module_base)
					{
						module_base = NULL;
						APICALL(NtMapViewOfSection)(rgdata->rmi[i].section, CURRENT_PROCESS, &module_base, NULL, NULL, &section_offset, &view_size, ViewUnmap, SEC_NO_CHANGE, PAGE_READONLY);
					}

					break;
				}
			}
#endif
			PVOID mapped_module = ManualMap(module_path);
#ifdef _WIN64
#if IS_ENABLED(RG_OPT_THREAD_CHECK)
			if (i == MODULE_NTDLL)
			{
				SIZE_T RtlUserThreadStart_offset = GetOffset(RG_GetModuleHandleW(RG_GetModulePath(MODULE_NTDLL)), APICALL(RtlUserThreadStart));
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
				RG_Report(RG_OPT_INTEGRITY_CHECK, REPORT_INTEGRITY_CRC64_CHECK, module_base, 0);

#if IS_ENABLED(RG_OPT_INTEGRITY_CHECK_HIDE_FROM_DEBUGGER)
			APICALL(NtUnmapViewOfSection)(CURRENT_PROCESS, module_base);
#endif

			RG_FreeMemory(mapped_module);
		}
	}
#endif
}