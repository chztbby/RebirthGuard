
/*
	chztbby::RebirthGuard/mapping.cpp
*/

#include "RebirthGuard.h"


VOID RebirthModule(PVOID hmodule, PVOID module_base)
{
	if (IsRebirthed(module_base))
		return;

	PVOID original_ntdll = RG_GetModuleHandleW(RG_GetModulePath(MODULE_NTDLL));
	PVOID mapped_ntdll = NULL;

	decltype(&NtCreateSection) pNtCreateSection = APICALL(NtCreateSection);
	decltype(&NtMapViewOfSection) pNtMapViewOfSection = APICALL(NtMapViewOfSection);
	decltype(&NtUnmapViewOfSection) pNtUnmapViewOfSection = APICALL(NtUnmapViewOfSection);
	decltype(&NtLockVirtualMemory) pNtLockVirtualMemory = APICALL(NtLockVirtualMemory);
	decltype(&NtQueryInformationProcess) pNtQueryInformationProcess = APICALL(NtQueryInformationProcess);
	decltype(&RtlAcquirePrivilege) pRtlAcquirePrivilege = APICALL(RtlAcquirePrivilege);
	decltype(&NtSetInformationProcess) pNtSetInformationProcess = APICALL(NtSetInformationProcess);
	decltype(&RtlReleasePrivilege) pRtlReleasePrivilege = APICALL(RtlReleasePrivilege);

	if (!IsRebirthed(original_ntdll))
	{
		mapped_ntdll = ManualMap(original_ntdll);
		pNtCreateSection = (decltype(pNtCreateSection))GetPtr(mapped_ntdll, GetOffset(original_ntdll, pNtCreateSection));
		pNtMapViewOfSection = (decltype(pNtMapViewOfSection))GetPtr(mapped_ntdll, GetOffset(original_ntdll, pNtMapViewOfSection));
		pNtUnmapViewOfSection = (decltype(pNtUnmapViewOfSection))GetPtr(mapped_ntdll, GetOffset(original_ntdll, pNtUnmapViewOfSection));
		pNtLockVirtualMemory = (decltype(pNtLockVirtualMemory))GetPtr(mapped_ntdll, GetOffset(original_ntdll, pNtLockVirtualMemory));
		pNtQueryInformationProcess = (decltype(pNtQueryInformationProcess))GetPtr(mapped_ntdll, GetOffset(original_ntdll, pNtQueryInformationProcess));
		pRtlAcquirePrivilege = (decltype(pRtlAcquirePrivilege))GetPtr(mapped_ntdll, GetOffset(original_ntdll, pRtlAcquirePrivilege));
		pNtSetInformationProcess = (decltype(pNtSetInformationProcess))GetPtr(mapped_ntdll, GetOffset(original_ntdll, pNtSetInformationProcess));
		pRtlReleasePrivilege = (decltype(pRtlReleasePrivilege))GetPtr(mapped_ntdll, GetOffset(original_ntdll, pRtlReleasePrivilege));
	}

	PVOID file_buffer = LoadFile(module_base);
	PIMAGE_NT_HEADERS nt = GetNtHeader(file_buffer);
	PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
	HANDLE section = NULL;
	LARGE_INTEGER section_size;
	section_size.QuadPart = nt->OptionalHeader.SizeOfImage;
	pNtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &section_size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

	PVOID view_base = NULL;
	SIZE_T view_size = NULL;
	pNtMapViewOfSection(section, CURRENT_PROCESS, &view_base, NULL, NULL, NULL, &view_size, ViewUnmap, NULL, PAGE_READWRITE);

	PVOID src_module;
#if IS_ENABLED(RG_OPT_COMPAT_THEMIDA) || IS_ENABLED(RG_OPT_COMPAT_VMPROTECT)
	if (hmodule == module_base)
		src_module = module_base;
	else
#endif
		src_module = ManualMap(module_base);

	CopyPeData(view_base, src_module, PE_TYPE_IMAGE);

	for (DWORD i = 0; i < nt->FileHeader.NumberOfSections; i++)
		for (DWORD j = 0; j < sec[i].Misc.VirtualSize; j += sizeof(PVOID))
			if ((sec[i].Characteristics & IMAGE_SCN_MEM_WRITE))
				*(PVOID*)GetPtr(view_base, (SIZE_T)sec[i].VirtualAddress + j) = *(PVOID*)GetPtr(module_base, (SIZE_T)sec[i].VirtualAddress + j);

#if IS_ENABLED(RG_OPT_COMPAT_THEMIDA) || IS_ENABLED(RG_OPT_COMPAT_VMPROTECT)
	if (hmodule != module_base)
#endif
		RG_FreeMemory(src_module);

#if IS_ENABLED(RG_OPT_THREAD_CHECK)
#ifdef _WIN64
	if (module_base == original_ntdll)
	{
		SIZE_T offset = GetOffset(original_ntdll, APICALL(RtlUserThreadStart));
		BYTE jmp_myRtlUserThreadStart[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, };
		*(PVOID*)(jmp_myRtlUserThreadStart + 6) = ThreadCallback;
		memcpy(GetPtr(view_base, offset), jmp_myRtlUserThreadStart, sizeof(jmp_myRtlUserThreadStart));
	}
#else
	// x86
#endif
#endif
	pNtUnmapViewOfSection(CURRENT_PROCESS, view_base);

	pNtUnmapViewOfSection(CURRENT_PROCESS, module_base);

	MAP_INFO mapinfo;
	mapinfo.pNtMapViewOfSection = pNtMapViewOfSection;
	mapinfo.pNtLockVirtualMemory = pNtLockVirtualMemory;
	mapinfo.pNtQueryInformationProcess = pNtQueryInformationProcess;
	mapinfo.pNtSetInformationProcess = pNtSetInformationProcess;
	mapinfo.pRtlAcquirePrivilege = pRtlAcquirePrivilege;
	mapinfo.pRtlReleasePrivilege = pRtlReleasePrivilege;
	mapinfo.base = module_base;
	mapinfo.hsection = section;
	mapinfo.nt = nt;
	mapinfo.chunk_offset = 0;
	mapinfo.chunk_size = PADDING(nt->OptionalHeader.SizeOfHeaders, nt->OptionalHeader.SectionAlignment);
	mapinfo.chunk_Characteristics = IMAGE_SCN_MEM_READ;
	MapAllSections(&mapinfo);

	if (mapinfo.chunk_size)
		MapChunk(&mapinfo, mapinfo.chunk_offset, mapinfo.chunk_size, mapinfo.chunk_Characteristics);

	RG_ProtectMemory(module_base, PADDING(nt->OptionalHeader.SizeOfHeaders, nt->OptionalHeader.SectionAlignment), PAGE_READONLY);
	for (DWORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
		RG_ProtectMemory(GetPtr(module_base, sec[i].VirtualAddress), PADDING(sec[i].Misc.VirtualSize, nt->OptionalHeader.SectionAlignment), GetProtection(sec[i].Characteristics));

	AddRebirthedModule(module_base, section);

	RG_FreeMemory(file_buffer);

	if (mapped_ntdll)
		RG_FreeMemory(mapped_ntdll);

	RG_HideModule(module_base);
}

PVOID LoadFile(PVOID module_base)
{
	HANDLE file = APICALL(CreateFileW)(RG_GetModulePath(module_base), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	DWORD file_size = APICALL(GetFileSize)(file, NULL);
	PVOID file_base = RG_AllocMemory(NULL, file_size, PAGE_READWRITE);
	APICALL(ReadFile)(file, file_base, file_size, 0, 0);
	APICALL(NtClose)(file);

	return file_base;
}

PVOID ManualMap(PVOID module_base)
{
	PVOID file_buffer = LoadFile(module_base);
	PIMAGE_NT_HEADERS nt = GetNtHeader(file_buffer);

	PVOID image_base = RG_AllocMemory(NULL, nt->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE);
	CopyPeData(image_base, file_buffer, PE_TYPE_FILE);
	RG_FreeMemory(file_buffer);

	nt = GetNtHeader(image_base);

	HMODULE ntdll = RG_GetModuleHandleW(RG_GetModulePath(MODULE_NTDLL));
	HMODULE kernel32 = RG_GetModuleHandleW(RG_GetModulePath(MODULE_KERNEL32));
	HMODULE kernelbase = RG_GetModuleHandleW(RG_GetModulePath(MODULE_KERNELBASE));

	PIMAGE_BASE_RELOCATION base_reloc = (PIMAGE_BASE_RELOCATION)GetPtr(image_base, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	SIZE_T delta = GetOffset(nt->OptionalHeader.ImageBase, module_base);

	while (base_reloc->VirtualAddress)
	{
		if (base_reloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{
			DWORD count = (base_reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD* list = (PWORD)(base_reloc + 1);

			for (DWORD i = 0; i < count; i++)
			{
				if (list[i])
				{
					PVOID ptr = ((LPBYTE)image_base + (base_reloc->VirtualAddress + (list[i] & 0xFFF)));
					*(SIZE_T*)ptr += delta;
				}
			}
		}

		base_reloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)base_reloc + base_reloc->SizeOfBlock);
	}

	PIMAGE_IMPORT_DESCRIPTOR import = (PIMAGE_IMPORT_DESCRIPTOR)GetPtr(image_base, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while (import->Characteristics)
	{
		PIMAGE_THUNK_DATA oft = (PIMAGE_THUNK_DATA)GetPtr(image_base, import->OriginalFirstThunk);
		PIMAGE_THUNK_DATA ft = (PIMAGE_THUNK_DATA)GetPtr(image_base, import->FirstThunk);

		WCHAR import_module_path[MAX_PATH];
		LPCSTR str = (CHAR*)GetPtr(image_base, import->Name);
		for (DWORD i = 0; str[i] != 0; i++)
		{
			import_module_path[i] = str[i];
			import_module_path[i + 1] = 0;
		}

		HMODULE hmodule = APICALL(LoadLibraryW)(import_module_path);
		if (!hmodule)
			break;

		while (oft->u1.AddressOfData)
		{
			PVOID func = NULL;

			if (oft->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				func = RG_GetProcAddress(hmodule, (LPCSTR)(oft->u1.Ordinal & 0xFFFF));
				if (!func)
					break;
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)GetPtr(image_base, oft->u1.AddressOfData);
				
				PVOID redirect;
				if (module_base == kernel32)
				{
					if (redirect = APICALL(GetProcAddress)(ntdll, (LPCSTR)ibn->Name))
						func = redirect;

					else if (redirect = APICALL(GetProcAddress)(kernelbase, (LPCSTR)ibn->Name))
						func = redirect;
				}
				else
				{
					func = APICALL(GetProcAddress)(hmodule, (LPCSTR)ibn->Name);
				}

				if (!func)
					break;
			}

			*(PVOID*)ft = func;

			oft++;
			ft++;
		}

		import++;
	}

	nt->OptionalHeader.ImageBase = (SIZE_T)module_base;

	return image_base;
}

VOID ExtendWorkingSet(PMAP_INFO info)
{
	QUOTA_LIMITS ql;
	info->pNtQueryInformationProcess(CURRENT_PROCESS, (PROCESSINFOCLASS)ProcessQuotaLimits, &ql, sizeof(ql), NULL);

	ql.MinimumWorkingSetSize += PAGE_SIZE;
	if (ql.MaximumWorkingSetSize < ql.MinimumWorkingSetSize)
		ql.MaximumWorkingSetSize = ql.MinimumWorkingSetSize;

	PVOID privilege_state = NULL;
	DWORD privilege_value = SE_AUDIT_PRIVILEGE;
	info->pRtlAcquirePrivilege(&privilege_value, 1, 0, &privilege_state);

	info->pNtSetInformationProcess(CURRENT_PROCESS, ProcessQuotaLimits, &ql, sizeof(ql));
	info->pRtlReleasePrivilege(privilege_state);
}

VOID AddRebirthedModule(PVOID module_base, HANDLE section)
{
    for (DWORD i = 0; i < ARRAYSIZE(rgdata->rmi); i++)
    {
        if (rgdata->rmi[i].module_base == module_base)
            return;

        if (!rgdata->rmi[i].module_base)
        {
			rgdata->rmi[i].module_base = module_base;
#if IS_ENABLED(RG_OPT_INTEGRITY_CHECK_HIDE_FROM_DEBUGGER)
            rebirthed_module_list[i].section = section;
#else
			APICALL(NtClose)(section);
#endif
			return;
        }
    }
}

VOID MapAllSections(PMAP_INFO info)
{
	if (info->nt->OptionalHeader.SectionAlignment % ALLOCATION_GRANULARITY == 0)
	{
		PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(info->nt);

		for (DWORD i = 0; i < info->nt->FileHeader.NumberOfSections; ++i)
		{
			DWORD chr = sec[i].Characteristics;

#if IS_ENABLED(RG_OPT_COMPAT_THEMIDA)
			if (sec[i].Name[1] == 't' && sec[i].Name[2] == 'h' && sec[i].Name[3] == 'e' && sec[i].Name[4] == 'm' && sec[i].Name[5] == 'i' && sec[i].Name[6] == 'd' && sec[i].Name[7] == 'a')
				chr = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
#endif
#if IS_ENABLED(RG_OPT_COMPAT_VMPROTECT)
			if (sec[i].Name[1] == 'v' && sec[i].Name[2] == 'm' && sec[i].Name[3] == 'p')
				chr = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
#endif

			MapChunk(info, sec[i].VirtualAddress, (SIZE_T)PADDING(sec[i].Misc.VirtualSize, info->nt->OptionalHeader.SectionAlignment), chr);
		}
	}
	else
	{
		PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(info->nt);

		for (DWORD i = 0; i < info->nt->FileHeader.NumberOfSections; ++i)
		{
			SIZE_T sec_size = (SIZE_T)PADDING(sec[i].Misc.VirtualSize, info->nt->OptionalHeader.SectionAlignment);
			SIZE_T full_chunk_size = info->chunk_size + sec_size;

			if (full_chunk_size < ALLOCATION_GRANULARITY || (!(sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && !(info->chunk_Characteristics & IMAGE_SCN_MEM_EXECUTE)))
			{
				if (info->chunk_size)
				{
					info->chunk_Characteristics |= sec[i].Characteristics;
				}
				else
				{
					info->chunk_offset = sec[i].VirtualAddress;
					info->chunk_Characteristics = sec[i].Characteristics;
				}

				info->chunk_size = full_chunk_size;
			}
			else
			{
				if (info->chunk_size)
				{
					MapChunk(info, info->chunk_offset, ALLOCATION_GRANULARITY, (info->chunk_Characteristics | sec[i].Characteristics));
					full_chunk_size -= ALLOCATION_GRANULARITY;
					info->chunk_offset += ALLOCATION_GRANULARITY;
					info->chunk_size = full_chunk_size;
					info->chunk_Characteristics = sec[i].Characteristics;
				}
				else
				{
					info->chunk_offset = sec[i].VirtualAddress;
				}

				SIZE_T chunk_size = full_chunk_size / ALLOCATION_GRANULARITY * ALLOCATION_GRANULARITY;
				if (chunk_size)
					MapChunk(info, info->chunk_offset, chunk_size, sec[i].Characteristics);

				if (full_chunk_size > chunk_size)
				{
					info->chunk_offset += chunk_size;
					info->chunk_size = full_chunk_size - chunk_size;
					info->chunk_Characteristics = sec[i].Characteristics;
				}
				else
				{
					info->chunk_offset = 0;
					info->chunk_size = 0;
					info->chunk_Characteristics = NULL;
				}
			}
		}
	}
}

VOID MapChunk(PMAP_INFO info, SIZE_T offset, SIZE_T size, DWORD chr)
{
	DWORD nochange = GetNoChange(chr);
	DWORD protect = GetProtection(chr);

	PVOID view_base = GetPtr(info->base, offset);
	LARGE_INTEGER view_offset;
	view_offset.QuadPart = offset;

	info->pNtMapViewOfSection(info->hsection, CURRENT_PROCESS, &view_base, NULL, NULL, &view_offset, &size, ViewUnmap, nochange, protect);

	SIZE_T lock_size = PAGE_SIZE;
	while (info->pNtLockVirtualMemory(CURRENT_PROCESS, &view_base, &lock_size, VM_LOCK_1) == STATUS_WORKING_SET_QUOTA)
		ExtendWorkingSet(info);
}

DWORD GetProtection(DWORD chr)
{
	DWORD protect = NULL;

	if (chr & IMAGE_SCN_MEM_EXECUTE)
	{
		if (chr & IMAGE_SCN_MEM_WRITE)
			protect = PAGE_EXECUTE_READWRITE;
		else
			protect = PAGE_EXECUTE_READ;
	}
	else
	{
		if (chr & IMAGE_SCN_MEM_WRITE)
			protect = PAGE_READWRITE;
		else
			protect = PAGE_READONLY;
	}

	return protect;
}

DWORD GetNoChange(DWORD chr)
{
	if (GetProtection(chr) == PAGE_EXECUTE_READ)
		return SEC_NO_CHANGE;

	return NULL;
}