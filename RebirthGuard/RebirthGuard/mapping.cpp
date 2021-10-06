
/*
	chztbby::RebirthGuard/mapping.cpp
*/

#include "RebirthGuard.h"


PVOID ManualMap(LPCWSTR module_path)
{
	HANDLE file = ((CreateFileW_T)ApiCall(kernelbase, API_CreateFileW))(module_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	DWORD file_size = GetFileSize(file, NULL);
	PVOID image_base = NULL;
	PVOID file_base = NULL;
	SIZE_T alloc_size = file_size;

	((NtAllocateVirtualMemory_T)ApiCall(ntdll, API_NtAllocateVirtualMemory))(CURRENT_PROCESS, &file_base, NULL, &alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	((ReadFile_T)ApiCall(kernelbase, API_ReadFile))(file, file_base, file_size, 0, 0);
	CloseHandle(file);

	PIMAGE_NT_HEADERS nt = GetNtHeader(file_base);
	PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

	SIZE_T image_size = nt->OptionalHeader.SizeOfImage;
	((NtAllocateVirtualMemory_T)ApiCall(ntdll, API_NtAllocateVirtualMemory))(CURRENT_PROCESS, &image_base, NULL, &image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	for (DWORD i = 0; i < nt->OptionalHeader.SizeOfHeaders; i += sizeof(PVOID))
		*(PVOID*)GetPtr(image_base, i) = *(PVOID*)GetPtr(file_base, i);

	for (DWORD i = 0; i < nt->FileHeader.NumberOfSections; i++)
		for (DWORD j = 0; j < sec[i].SizeOfRawData; j += sizeof(PVOID))
			*(PVOID*)GetPtr(image_base, sec[i].VirtualAddress + j) = *(PVOID*)GetPtr(file_base, sec[i].PointerToRawData + j);

	alloc_size = NULL;
	((NtFreeVirtualMemory_T)ApiCall(ntdll, API_NtFreeVirtualMemory))(CURRENT_PROCESS, &file_base, &alloc_size, MEM_RELEASE);

	nt = GetNtHeader(image_base);

	PVOID original_image_base = RG_GetModuleHandleEx(CURRENT_PROCESS, module_path);

	PIMAGE_BASE_RELOCATION base_reloc = (PIMAGE_BASE_RELOCATION)GetPtr(image_base, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	SIZE_T delta = GetOffset(nt->OptionalHeader.ImageBase, original_image_base);

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
		LPCSTR str = (CHAR*)((DWORD64)image_base + import->Name);
		for (DWORD i = 0; str[i] != 0; i++)
		{
			import_module_path[i] = str[i];
			import_module_path[i + 1] = 0;
		}

		HMODULE hmodule = ((LoadLibraryW_T)ApiCall(kernelbase, API_LoadLibraryW))(import_module_path);
		if (!hmodule)
			break;

		GetModuleFileNameW(hmodule, import_module_path, sizeof(import_module_path));

		while (oft->u1.AddressOfData)
		{
			if (oft->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				*(PVOID*)ft = GetProcAddress(hmodule, (LPCSTR)(oft->u1.Ordinal & 0xFFFF));
			}
			else 
			{
				PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)image_base + oft->u1.AddressOfData);
				HMODULE hkernel32 = RG_GetModuleHandleEx(CURRENT_PROCESS, GetModulePath(kernel32));
				HMODULE hkernelbase = RG_GetModuleHandleEx(CURRENT_PROCESS, GetModulePath(kernelbase));

				if (original_image_base == hkernel32 && GetProcAddress(hkernelbase, (LPCSTR)ibn->Name))
					hmodule = hkernelbase;

				*(PVOID*)ft = GetProcAddress(hmodule, (LPCSTR)ibn->Name);
			}

			oft++;
			ft++;
		}

		import++;
	}

	return image_base;
}

VOID ExtendWorkingSet(HANDLE process)
{
	QUOTA_LIMITS ql;
	((NtQueryInformationProcess_T) ApiCall(ntdll, API_NtQueryInformationProcess))(process, ProcessQuotaLimits, &ql, sizeof(ql), NULL);

	ql.MinimumWorkingSetSize += PAGE_SIZE;
	if (ql.MaximumWorkingSetSize < ql.MinimumWorkingSetSize)
		ql.MaximumWorkingSetSize = ql.MinimumWorkingSetSize;

	PVOID privilege_state = NULL;
	DWORD privilege_value = SE_AUDIT_PRIVILEGE;
	((RtlAcquirePrivilege_T)ApiCall(ntdll, API_RtlAcquirePrivilege))(&privilege_value, 1, 0, &privilege_state);

	((NtSetInformationProcess_T)ApiCall(ntdll, API_NtSetInformationProcess))(process, ProcessQuotaLimits, &ql, sizeof(ql));
	((RtlReleasePrivilege_T)ApiCall(ntdll, API_RtlReleasePrivilege))(privilege_state);
}

VOID AddSection(HANDLE process, HANDLE section, PVOID module_base)
{
	static BOOL first = TRUE;
	static BOOL first2 = TRUE;

	if (first && IsRebirthed(CURRENT_PROCESS, RG_GetModuleHandleEx(CURRENT_PROCESS, NULL)) == NULL)
	{
		first = FALSE;
	}
	else
	{
		if (process != CURRENT_PROCESS)
			((NtDuplicateObject_T)ApiCall(ntdll, API_NtDuplicateObject))(CURRENT_PROCESS, section, process, &section, PROCESS_DUP_HANDLE, NULL, DUPLICATE_SAME_ACCESS);

		for (int i = 0;; i++)
		{
			if (section_list[i].base == module_base)
				return;

			if (section_list[i].section == NULL)
			{
				section_list[i].section = section;
				section_list[i].base = module_base;
				break;
			}
		}

		if (process != CURRENT_PROCESS)
		{
			if (first2)
			{
				first2 = FALSE;

				SIZE_T size = MAX_SECTION_LIST_SIZE;
				NTSTATUS ns = ((NtAllocateVirtualMemory_T)ApiCall(ntdll, API_NtAllocateVirtualMemory))(process, (PVOID*)&section_list, NULL, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
				if (ns)
					Report(process, RG_ENABLE | RG_ENABLE_LOG | RG_ENABLE_POPUP | RG_ENABLE_KILL, REPORT_ALLOC_SECTION_LIST, (PVOID)ns, (PVOID)2);
			}

			((NtWriteVirtualMemory_T)ApiCall(ntdll, API_NtWriteVirtualMemory))(process, section_list, section_list, MAX_SECTION_LIST_SIZE, NULL);
		}
	}
}

VOID RebirthModule(HANDLE process, LPCWSTR module_path)
{
	PVOID origin_ntdll = RG_GetModuleHandleEx(CURRENT_PROCESS, GetModulePath(ntdll));
	PVOID proxy_ntdll = NULL;

	NtCreateSection_T NtCreateSection = (NtCreateSection_T)ApiCall(ntdll, API_NtCreateSection);
	NtMapViewOfSection_T NtMapViewOfSection = (NtMapViewOfSection_T)ApiCall(ntdll, API_NtMapViewOfSection);
	NtUnmapViewOfSection_T NtUnmapViewOfSection = (NtUnmapViewOfSection_T)ApiCall(ntdll, API_NtUnmapViewOfSection);
	NtLockVirtualMemory_T NtLockVirtualMemory = (NtLockVirtualMemory_T)ApiCall(ntdll, API_NtLockVirtualMemory);

	if (!IsRebirthed(CURRENT_PROCESS, origin_ntdll))
	{
		proxy_ntdll = ManualMap(GetModulePath(ntdll));
		NtCreateSection = (NtCreateSection_T)GetPtr(proxy_ntdll, GetOffset(origin_ntdll, NtCreateSection));
		NtMapViewOfSection = (NtMapViewOfSection_T)GetPtr(proxy_ntdll, GetOffset(origin_ntdll, NtMapViewOfSection));
		NtUnmapViewOfSection = (NtUnmapViewOfSection_T)GetPtr(proxy_ntdll, GetOffset(origin_ntdll, NtUnmapViewOfSection));
	}
	
	PVOID module_base = RG_GetModuleHandleEx(process, module_path);

	if (!IsRebirthed(process, module_base))
	{
		PVOID mapped_module = ManualMap(module_path);
		PIMAGE_NT_HEADERS nt = GetNtHeader(mapped_module);
		PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
		HANDLE section = NULL;
		PVOID view_base = NULL;
		SIZE_T view_size = NULL;
		SIZE_T lock_size = 1;
		SIZE_T image_size = nt->OptionalHeader.SizeOfImage;
		LARGE_INTEGER SectionOffset;
		LARGE_INTEGER SectionSize;

		for (DWORD i = 0; i < sizeof(LARGE_INTEGER); i += sizeof(PVOID))
			*(PVOID*)GetPtr(&SectionOffset, i) = *(PVOID*)GetPtr(&SectionSize, i) = 0;

		SectionSize.QuadPart = image_size;

		nt->OptionalHeader.ImageBase = (SIZE_T)RG_GetModuleHandleEx(process, module_path);;

		if (nt->OptionalHeader.SectionAlignment == ALLOCATION_GRANULARITY)
		{
			NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &SectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT | SEC_NO_CHANGE, NULL);

			NtMapViewOfSection(section, CURRENT_PROCESS, &view_base, NULL, NULL, NULL, &view_size, ViewUnmap, SEC_NO_CHANGE, PAGE_READWRITE);

			for (DWORD i = 0; i < nt->OptionalHeader.SizeOfHeaders; i += sizeof(PVOID))
				*(PVOID*)GetPtr(view_base, i) = *(PVOID*)GetPtr(mapped_module,i);

			for (DWORD i = 0; i < nt->FileHeader.NumberOfSections; i++)
				for (DWORD j = 0; j < sec[i].Misc.VirtualSize; j += sizeof(DWORD64))
					*(PVOID*)GetPtr(view_base, sec[i].VirtualAddress + j) = *(PVOID*)GetPtr(mapped_module, sec[i].VirtualAddress + j);

			NtUnmapViewOfSection(CURRENT_PROCESS, view_base);

			NtUnmapViewOfSection(process, module_base);

			view_base = module_base;
			view_size = ALLOCATION_GRANULARITY;
			NtMapViewOfSection(section, process, &view_base, NULL, NULL, NULL, &view_size, ViewUnmap, SEC_NO_CHANGE, PAGE_READONLY);

			while (NtLockVirtualMemory(process, &view_base, &lock_size, 1) == STATUS_WORKING_SET_QUOTA)
				ExtendWorkingSet(process);

			for (DWORD i = 0, Protect; i < nt->FileHeader.NumberOfSections; i++)
			{
				view_base = GetPtr(module_base, sec[i].VirtualAddress);
				view_size = PADDING(sec[i].Misc.VirtualSize, ALLOCATION_GRANULARITY);
				SectionOffset.QuadPart = sec[i].VirtualAddress;

				if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
					Protect = PAGE_EXECUTE_READ;
				else if (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE)
					Protect = PAGE_READWRITE;
				else
					Protect = PAGE_READONLY;

				NtMapViewOfSection(section, process, &view_base, NULL, NULL, &SectionOffset, &view_size, ViewUnmap, SEC_NO_CHANGE, Protect);

				while (NtLockVirtualMemory(process, &view_base, &lock_size, 1) == STATUS_WORKING_SET_QUOTA)
					ExtendWorkingSet(process);
			}
		}
		else
		{
			NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &SectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

			NtMapViewOfSection(section, CURRENT_PROCESS, &view_base, NULL, NULL, NULL, &view_size, ViewUnmap, NULL, PAGE_READWRITE);

			for (DWORD i = 0; i < image_size; i += sizeof(PVOID))
				*(PVOID*)GetPtr(view_base, i) = *(PVOID*)GetPtr(mapped_module, i);

			for (DWORD i = 0; i < nt->FileHeader.NumberOfSections; i++)
			{
				if (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE)
				{
					((NtReadVirtualMemory_T)ApiCall(ntdll, API_NtReadVirtualMemory))(process, GetPtr(module_base, sec[i].VirtualAddress), GetPtr(view_base, sec[i].VirtualAddress), image_size - sec[i].VirtualAddress, 0);
					break;
				}
			}

			if (module_base == origin_ntdll)
			{
				SIZE_T offset = (DWORD64)ApiCall(ntdll, API_RtlUserThreadStart) - (DWORD64)origin_ntdll;
				BYTE jmp_myRtlUserThreadStart[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, };
				*(PVOID*)(jmp_myRtlUserThreadStart + 6) = Thread_Callback;
				for (DWORD i = 0; i < 14; i++)
				{
					*(BYTE*)GetPtr(view_base, offset + i) = jmp_myRtlUserThreadStart[i];
					*(BYTE*)GetPtr(mapped_module, offset + i) = jmp_myRtlUserThreadStart[i];
				}
			}

			SIZE_T execute_size = 0;
			SIZE_T readonly_size = 0;
			for (DWORD i = 0; i < nt->FileHeader.NumberOfSections; i++)
			{
				if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
					execute_size += PADDING(sec[i].Misc.VirtualSize, PAGE_SIZE);
				else
				{
					readonly_size = PADDING(sec[i].Misc.VirtualSize, PAGE_SIZE);
					execute_size += PAGE_SIZE;
					break;
				}
			}

			NtUnmapViewOfSection(CURRENT_PROCESS, view_base);

			NtUnmapViewOfSection(process, module_base);

			view_base = module_base;
			view_size = SectionSize.QuadPart;

			if (execute_size + readonly_size >= ALLOCATION_GRANULARITY && execute_size + readonly_size >= PADDING(execute_size, ALLOCATION_GRANULARITY))
			{
				view_size = PADDING(execute_size, ALLOCATION_GRANULARITY);
				NtMapViewOfSection(section, process, &view_base, NULL, NULL, NULL, &view_size, ViewUnmap, SEC_NO_CHANGE, PAGE_EXECUTE_READ);
				while (NtLockVirtualMemory(process, &view_base, &lock_size, 1) == STATUS_WORKING_SET_QUOTA)
					ExtendWorkingSet(process);

				SectionOffset.QuadPart = view_size;
				view_base = GetPtr(module_base, view_size);
				view_size = image_size - view_size;
				NtMapViewOfSection(section, process, &view_base, NULL, NULL, &SectionOffset, &view_size, ViewUnmap, NULL, PAGE_READWRITE);
			}

			else
				NtMapViewOfSection(section, process, &view_base, NULL, NULL, NULL, &view_size, ViewUnmap, NULL, PAGE_EXECUTE_WRITECOPY);

			DWORD protect = 0;
			SIZE_T size = PAGE_SIZE;
			PVOID ptr = module_base;
			((NtProtectVirtualMemory_T)ApiCall(ntdll, API_NtProtectVirtualMemory))(process, &ptr, &size, PAGE_READONLY, &protect);
			for (DWORD i = 0, new_protect; i < nt->FileHeader.NumberOfSections; i++)
			{
				if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
					new_protect = PAGE_EXECUTE_READ;
				else if (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE)
					new_protect = PAGE_WRITECOPY;
				else
					new_protect = PAGE_READONLY;

				protect = 0;
				size = sec[i].Misc.VirtualSize;
				ptr = GetPtr(module_base, sec[i].VirtualAddress);
				((NtProtectVirtualMemory_T)ApiCall(ntdll, API_NtProtectVirtualMemory))(process, &ptr, &size, new_protect, &protect);
			}

			view_base = GetPtr(view_base, PAGE_SIZE);
			while (NtLockVirtualMemory(process, &view_base, &lock_size , 1) == STATUS_WORKING_SET_QUOTA)
				ExtendWorkingSet(process);
		}

#if RG_OPT_CRC_HIDE_FROM_DEBUGGER & RG_ENABLE
		AddSection(process, section, module_base);
#endif
#if !(RG_OPT_CRC_HIDE_FROM_DEBUGGER & RG_ENABLE)
		CloseHandle(section);
#endif
		SIZE_T size = NULL;
		((NtFreeVirtualMemory_T)ApiCall(ntdll, API_NtFreeVirtualMemory))(CURRENT_PROCESS, &mapped_module, &size, MEM_RELEASE);
	}

	if (proxy_ntdll)
	{
		SIZE_T size = NULL;
		((NtFreeVirtualMemory_T)ApiCall(ntdll, API_NtFreeVirtualMemory))(CURRENT_PROCESS, &proxy_ntdll, &size, MEM_RELEASE);
	}
}
