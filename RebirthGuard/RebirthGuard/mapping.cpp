
/********************************************
*											*
*	RebirthGuard/mapping.cpp - chztbby		*
*											*
********************************************/

#include "RebirthGuard.h"


//-------------------------------------------------------
//  1. Check the file integrity
//	2. Load the file to memory
//  2. Relocate image
//  3. Resolve image imports
//-------------------------------------------------------
PVOID ManualMap(HANDLE hProcess, CONST WCHAR* ModulePath)
{
	// 1. Check the file integrity
#if FILE_CHECK & ENABLE
	if (!(IsExcepted(ModulePath) & EXCEPT_FILE_INTEGRITY) && GetFileCheckSum(ModulePath) != (GetNtHeader(myGetModuleHandleEx(CURRENT_PROCESS, ModulePath)))->OptionalHeader.CheckSum)
		Report(hProcess, FILE_CHECK, FILE_INTEGRITY_Fail, (PVOID)myGetModuleHandleEx(hProcess, ModulePath), (PVOID)0);
#endif

	// 2. Load the file to memory
	HANDLE			hFile		= ((_CreateFileW)APICall(kernelbase, APICall_CreateFileW))(ModulePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	DWORD			FileSize	= GetFileSize(hFile, NULL);
	PVOID			ImageBase	= NULL;
	PVOID			ImageBase2	= NULL;
	DWORD64			AllocSize	= FileSize;

	((_NtAllocateVirtualMemory)APICall(ntdll, APICall_NtAllocateVirtualMemory))(CURRENT_PROCESS, &ImageBase2, NULL, &AllocSize, MEM_COMMIT, PAGE_READWRITE);
	
	((_ReadFile)APICall(kernelbase, APICall_ReadFile))(hFile, ImageBase2, FileSize, 0, 0);
	CloseHandle(hFile);

	PIMAGE_NT_HEADERS	pNtHeader	= GetNtHeader(ImageBase2);
	DWORD64				ImageSize	= pNtHeader->OptionalHeader.SizeOfImage;

	((_NtAllocateVirtualMemory)APICall(ntdll, APICall_NtAllocateVirtualMemory))(CURRENT_PROCESS, &ImageBase, NULL, &ImageSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	for (DWORD64 i = 0; i < pNtHeader->OptionalHeader.SizeOfHeaders; i += sizeof(DWORD64))
		*(DWORD64*)((DWORD64)ImageBase + i) = *(DWORD64*)((DWORD64)ImageBase2 + i);

	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);

	for (DWORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
		for (DWORD64 j = 0; j < pSectionHeader[i].SizeOfRawData; j += sizeof(DWORD64))
			*(DWORD64*)((DWORD64)ImageBase + pSectionHeader[i].VirtualAddress + j) = *(DWORD64*)((DWORD64)ImageBase2 + pSectionHeader[i].PointerToRawData + j);

	AllocSize = NULL;
	((_NtFreeVirtualMemory)APICall(ntdll, APICall_NtFreeVirtualMemory))(CURRENT_PROCESS, &ImageBase2, &AllocSize, MEM_RELEASE);

	pNtHeader = GetNtHeader(ImageBase);

	PVOID OriginImageBase = myGetModuleHandleEx(CURRENT_PROCESS, ModulePath);

	PIMAGE_BASE_RELOCATION pBaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)ImageBase + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	DWORD64 delta = (DWORD64)((LPBYTE)OriginImageBase - pNtHeader->OptionalHeader.ImageBase);

	// 3. Relocate Image
	while (pBaseRelocation->VirtualAddress)
	{
		if (pBaseRelocation->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{
			DWORD count = (pBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD* list = (PWORD)(pBaseRelocation + 1);

			for (DWORD64 i = 0; i < count; i++)
			{
				if (list[i])
				{
					PVOID ptr = ((LPBYTE)ImageBase + (pBaseRelocation->VirtualAddress + (list[i] & 0xFFF)));
					*(DWORD64*)ptr += delta;
				}
			}
		}

		pBaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)pBaseRelocation + pBaseRelocation->SizeOfBlock);
	}

	// 4. Resolve Image imports
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)ImageBase + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while (pImportDescriptor->Characteristics)
	{
		PIMAGE_THUNK_DATA OrigFirstThunk	= (PIMAGE_THUNK_DATA)((LPBYTE)ImageBase + pImportDescriptor->OriginalFirstThunk);
		PIMAGE_THUNK_DATA FirstThunk		= (PIMAGE_THUNK_DATA)((LPBYTE)ImageBase + pImportDescriptor->FirstThunk);

		WCHAR ModulePath2[MAX_PATH];
		CHAR* str = (CHAR*)((DWORD64)ImageBase + pImportDescriptor->Name);
		for (DWORD i = 0; str[i] != 0; i++)
		{
			ModulePath2[i] = str[i];
			ModulePath2[i + 1] = 0;
		}

		if (((_LoadLibraryW)APICall(kernelbase, APICall_LoadLibraryW))(ModulePath2))
			GetModuleFileName(((_LoadLibraryW)APICall(kernelbase, APICall_LoadLibraryW))(ModulePath2), ModulePath2, sizeof(ModulePath2));
		HMODULE hModule = myGetModuleHandleEx(CURRENT_PROCESS, ModulePath2);

		if (!hModule)	break;

		while (OrigFirstThunk->u1.AddressOfData)
		{
			// Import by ordinal
			if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				DWORD64 Function = NULL;
				if (myGetModuleHandleEx(CURRENT_PROCESS, ModulePath2) != hModule)
					Function = (DWORD64)myGetModuleHandleEx(CURRENT_PROCESS, ModulePath2) + (DWORD64)myGetProcAddress(myGetModuleHandleEx(CURRENT_PROCESS, ModulePath2), (LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF)) - (DWORD64)myGetModuleHandleEx(CURRENT_PROCESS, ModulePath2);
				else
					Function = (DWORD64)myGetProcAddress(hModule, (LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));
				
				if (!Function)
					break;

				*(DWORD64*)FirstThunk = Function;
			}
			// Import by name 
			else 
			{
				PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)ImageBase + OrigFirstThunk->u1.AddressOfData);
				DWORD64 Function;
				HMODULE hkernel32	= myGetModuleHandleEx(CURRENT_PROCESS, GetModulePath(kernel32));
				HMODULE hkernelbase = myGetModuleHandleEx(CURRENT_PROCESS, GetModulePath(kernelbase));
				if (OriginImageBase == hkernel32 && myGetProcAddress(hkernelbase, (LPCSTR)pIBN->Name))
					Function = (DWORD64)GetProcAddress(hkernelbase, (LPCSTR)pIBN->Name);
				else
				{
					if (myGetModuleHandleEx(CURRENT_PROCESS, ModulePath2) != hModule)
						Function = (DWORD64)myGetModuleHandleEx(CURRENT_PROCESS, ModulePath2) + ((DWORD64)GetProcAddress(myGetModuleHandleEx(CURRENT_PROCESS, ModulePath2), (LPCSTR)pIBN->Name) - (DWORD64)myGetModuleHandleEx(CURRENT_PROCESS, ModulePath2));
					else
						Function = (DWORD64)GetProcAddress(hModule, (LPCSTR)pIBN->Name);
				}

				if (!Function)
					break;

				*(DWORD64*)FirstThunk = Function;
			}

			OrigFirstThunk++;
			FirstThunk++;
		}

		pImportDescriptor++;
	}

	return ImageBase;
}


//-------------------------------------------------------
//	Extend WorkingSet size to lock memory
//-------------------------------------------------------
VOID ExtendWorkingSet(HANDLE hProcess)
{
	QUOTA_LIMITS ql;
	DWORD PrivilegeValue = SE_AUDIT_PRIVILEGE;
	PVOID PrivilegeState = NULL;

	((_NtQueryInformationProcess)	APICall(ntdll, APICall_NtQueryInformationProcess))	(hProcess, ProcessQuotaLimits, &ql, sizeof(ql), NULL);

	ql.MinimumWorkingSetSize += PAGE_SIZE;
	if (ql.MaximumWorkingSetSize < ql.MinimumWorkingSetSize)
		ql.MaximumWorkingSetSize = ql.MinimumWorkingSetSize;

	((_RtlAcquirePrivilege)			APICall(ntdll, APICall_RtlAcquirePrivilege))	(&PrivilegeValue, 1, 0, &PrivilegeState);
	((_NtSetInformationProcess)		APICall(ntdll, APICall_NtSetInformationProcess))	(hProcess, ProcessQuotaLimits, &ql, sizeof(ql));
	((_RtlReleasePrivilege)			APICall(ntdll, APICall_RtlReleasePrivilege))	(PrivilegeState);
}


//-------------------------------------------------------
//	Add section handle in list 
//-------------------------------------------------------
VOID AddSection(HANDLE hProcess, HANDLE hSection, PVOID ModuleBase)
{
	static BOOL b_first = TRUE, b_first2 = TRUE;

	if (b_first && IsRebirthed(CURRENT_PROCESS, myGetModuleHandleEx(CURRENT_PROCESS, NULL)) == NULL)
		b_first = FALSE;
	else
	{
		if (hProcess != CURRENT_PROCESS)
			((_NtDuplicateObject)APICall(ntdll, APICall_NtDuplicateObject))(CURRENT_PROCESS, hSection, hProcess, &hSection, PROCESS_DUP_HANDLE, NULL, DUPLICATE_SAME_ACCESS);

		for (int i = 0;; i++)
		{
			if (SectionList[i].ModuleBase == ModuleBase)
				return;

			if (SectionList[i].hSection == NULL)
			{
				SectionList[i].hSection = hSection;
				SectionList[i].ModuleBase = ModuleBase;
				break;
			}
		}

		if (hProcess != CURRENT_PROCESS)
		{
			if (b_first2)
			{
				b_first2 = FALSE;

				DWORD64 AllocSize = SECTION_LIST_SIZE;
				NTSTATUS result = ((_NtAllocateVirtualMemory)APICall(ntdll, APICall_NtAllocateVirtualMemory))(hProcess, (PVOID*)&SectionList, NULL, &AllocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
				if (result)
					Report(hProcess, ENABLE | _LOG | _POPUP | _KILL, Allocation_SectionList, (PVOID)(DWORD64)result, (PVOID)2);
			}

			((_NtWriteVirtualMemory)APICall(ntdll, APICall_NtWriteVirtualMemory))	(hProcess, SectionList, SectionList, SECTION_LIST_SIZE, NULL);
		}
	}
}


//-------------------------------------------------------
//  1. Load the file to memory manually
//	2. Create section to remap the image
//  3. Map view of section
//  4. Copy memory
//  5. Unmap the view
//  6. Unmap the original image
//  7. Remap with SEC_NO_CHANGE flag
//  8. Lock memory
//-------------------------------------------------------
VOID RebirthModule(HANDLE hProcess, CONST WCHAR* ModulePath)
{
	// Get ntdll.dll path and address
	HMODULE origin_ntdll			= myGetModuleHandleEx(CURRENT_PROCESS, GetModulePath(ntdll));
	HMODULE	proxy_ntdll				= NULL;

	// Get original API
	_NtCreateSection		NtCreateSection			= (_NtCreateSection)		APICall(ntdll, APICall_NtCreateSection);
	_NtMapViewOfSection		NtMapViewOfSection		= (_NtMapViewOfSection)		APICall(ntdll, APICall_NtMapViewOfSection);
	_NtUnmapViewOfSection	NtUnmapViewOfSection	= (_NtUnmapViewOfSection)	APICall(ntdll, APICall_NtUnmapViewOfSection);
	_NtLockVirtualMemory	NtLockVirtualMemory		= (_NtLockVirtualMemory)	APICall(ntdll, APICall_NtLockVirtualMemory);

	// If ntdll.dll is not rebirthed, use proxy ntdll.dll
	if (IsRebirthed(CURRENT_PROCESS, origin_ntdll) == NULL)
	{
		proxy_ntdll = (HMODULE)ManualMap(CURRENT_PROCESS, GetModulePath(ntdll));

		NtCreateSection			= (_NtCreateSection)		((DWORD64)proxy_ntdll + (DWORD64)NtCreateSection		- (DWORD64)origin_ntdll);
		NtMapViewOfSection		= (_NtMapViewOfSection)		((DWORD64)proxy_ntdll + (DWORD64)NtMapViewOfSection	- (DWORD64)origin_ntdll);
		NtUnmapViewOfSection	= (_NtUnmapViewOfSection)	((DWORD64)proxy_ntdll + (DWORD64)NtUnmapViewOfSection	- (DWORD64)origin_ntdll);
	}
	
	DWORD64 ModuleBase = (DWORD64)myGetModuleHandleEx(hProcess, ModulePath);

	// Check this module is already rebirthed
	if (IsRebirthed(hProcess, (PVOID)ModuleBase) == NULL)
	{
		// 1. Load the file to memory manually
		DWORD64 MappedModule = (DWORD64)ManualMap(hProcess, ModulePath);

		PIMAGE_NT_HEADERS		pNtHeader		= GetNtHeader(MappedModule);
		PIMAGE_SECTION_HEADER	pSectionHeader	= IMAGE_FIRST_SECTION(pNtHeader);
		DWORD					SizeOfImage		= pNtHeader->OptionalHeader.SizeOfImage;
		HANDLE					hSection		= NULL;
		DWORD64					ViewBase		= NULL;
		DWORD64					ViewSize		= NULL;
		DWORD64					LockSize		= 1;
		LARGE_INTEGER			SectionOffset;
		LARGE_INTEGER			SectionSize;

		for (DWORD64 i = 0; i < sizeof(LARGE_INTEGER); i += sizeof(DWORD64))
			*(DWORD64*)(&SectionOffset + i) = *(DWORD64*)(&SectionSize + i) = 0;

		SectionSize.QuadPart = SizeOfImage;

		pNtHeader->OptionalHeader.ImageBase = (DWORD64)myGetModuleHandleEx(hProcess, ModulePath);;

		// SectionAlignment == 0x10000
		if (pNtHeader->OptionalHeader.SectionAlignment == AllocationGranularity)
		{
			// 2. Create section to remap the image
			NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &SectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT | SEC_NO_CHANGE, NULL);

			// 3. Map view of section
			NtMapViewOfSection(hSection, CURRENT_PROCESS, &ViewBase, NULL, NULL, NULL, &ViewSize, ViewUnmap, SEC_NO_CHANGE, PAGE_READWRITE);

			// 4. Copy memory (PE Header)
			for (DWORD64 i = 0; i < PAGE_SIZE; i += sizeof(DWORD64))
				*(DWORD64*)(ViewBase + i) = *(DWORD64*)(MappedModule + i);

			// 4. Copy memory (Each section)
			for (DWORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
				for (DWORD64 j = 0; j < pSectionHeader[i].Misc.VirtualSize; j += sizeof(DWORD64))
					*(DWORD64*)(ViewBase + pSectionHeader[i].VirtualAddress + j) = *(DWORD64*)(MappedModule + pSectionHeader[i].VirtualAddress + j);

			// 5. Unmap the view
			NtUnmapViewOfSection(CURRENT_PROCESS, ViewBase);

			// 6. Unmap the original image
			NtUnmapViewOfSection(hProcess, ModuleBase);

			// 7. Remap with SEC_NO_CHANGE flag (PE Header)
			ViewBase = ModuleBase;
			ViewSize = AllocationGranularity;
			NtMapViewOfSection(hSection, hProcess, &ViewBase, NULL, NULL, NULL, &ViewSize, ViewUnmap, SEC_NO_CHANGE, PAGE_READONLY);

			// 8. Lock memory (PE Header)
			while (NtLockVirtualMemory(hProcess, &ViewBase, &LockSize, 1) == STATUS_WORKING_SET_QUOTA)
				ExtendWorkingSet(hProcess);

			for (DWORD i = 0, Protect; i < pNtHeader->FileHeader.NumberOfSections; i++)
			{
				// Calculate size and get page protection
				ViewBase = ModuleBase + pSectionHeader[i].VirtualAddress;
				ViewSize = PADDING(pSectionHeader[i].Misc.VirtualSize, AllocationGranularity);
				SectionOffset.QuadPart = pSectionHeader[i].VirtualAddress;
				if (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)		Protect = PAGE_EXECUTE_READ;
				else if (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE)	Protect = PAGE_READWRITE;
				else																Protect = PAGE_READONLY;

				// 7. Remap with SEC_NO_CHANGE flag (Each section)
				NtMapViewOfSection(hSection, hProcess, &ViewBase, NULL, NULL, &SectionOffset, &ViewSize, ViewUnmap, SEC_NO_CHANGE, Protect);

				// 8. Lock memory (Each section)
				while (NtLockVirtualMemory(hProcess, &ViewBase, &LockSize, 1) == STATUS_WORKING_SET_QUOTA)
					ExtendWorkingSet(hProcess);
			}
		}
		// SectionAlignment == 0x1000
		else
		{
			// 2. Create section to remap the image
			NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &SectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

			// 3. Map view of section
			NtMapViewOfSection(hSection, CURRENT_PROCESS, &ViewBase, NULL, NULL, NULL, &ViewSize, ViewUnmap, NULL, PAGE_READWRITE);

			// 4. Copy memory
			for (DWORD64 j = 0; j < SizeOfImage; j += sizeof(DWORD64))
				*(DWORD64*)(ViewBase + j) = *(DWORD64*)(MappedModule + j);

			// Overwrite the writable section data
			for (DWORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
			{
				if (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE)
				{
					((_NtReadVirtualMemory)APICall(ntdll, APICall_NtReadVirtualMemory))(hProcess, (PVOID)(ModuleBase + pSectionHeader[i].VirtualAddress), (PVOID)(ViewBase + pSectionHeader[i].VirtualAddress), SizeOfImage - pSectionHeader[i].VirtualAddress, 0);
					break;
				}
			}

			// RtlUserThreadStart Hook
			if (ModuleBase == (DWORD64)origin_ntdll)
			{
				DWORD64 offset = (DWORD64)APICall(ntdll, APICall_RtlUserThreadStart) - (DWORD64)origin_ntdll;
				BYTE jmp_myRtlUserThreadStart[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, };
				*(DWORD64*)(jmp_myRtlUserThreadStart + 6) = (DWORD64)Thread_Callback;
				for (DWORD64 i = 0; i < 14; i++)
				{
					*(BYTE*)(ViewBase + offset + i) = jmp_myRtlUserThreadStart[i];
					*(BYTE*)(MappedModule + offset + i) = jmp_myRtlUserThreadStart[i];
				}
			}

			// Calculate size to map with PAGE_EXECUTE_READ protection
			DWORD64 ExecuteSize = 0;
			DWORD64 ReadOnlySize = 0;
			for (DWORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
			{
				if (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
					ExecuteSize += PADDING(pSectionHeader[i].Misc.VirtualSize, PAGE_SIZE);
				else
				{
					ReadOnlySize = PADDING(pSectionHeader[i].Misc.VirtualSize, PAGE_SIZE);
					ExecuteSize += PAGE_SIZE;
					break;
				}
			}

			// 5. Unmap the view
			NtUnmapViewOfSection(CURRENT_PROCESS, ViewBase);

			DWORD Flag = IsExcepted(ModulePath);

			// 6. Unmap the original image
			NtUnmapViewOfSection(hProcess, ModuleBase);

			ViewBase = ModuleBase;
			ViewSize = SectionSize.QuadPart;
			
			// Check this module is excepted (PAGE_EXECUTE_READWRITE)
			if (Flag & EXCEPT_REBIRTH)
				NtMapViewOfSection(hSection, hProcess, &ViewBase, NULL, NULL, NULL, &ViewSize, ViewUnmap, NULL, PAGE_EXECUTE_READWRITE);

			// This module is not excepted and enough size to remap with PAGE_EXECUTE_READ
			else if (ExecuteSize + ReadOnlySize >= AllocationGranularity && ExecuteSize + ReadOnlySize >= PADDING(ExecuteSize, AllocationGranularity))
			{
				// 7. Remap with SEC_NO_CHANGE flag and PAGE_EXECUTE_READ (.text + .rdata section)
				ViewSize = PADDING(ExecuteSize, AllocationGranularity);
				NtMapViewOfSection(hSection, hProcess, &ViewBase, NULL, NULL, NULL, &ViewSize, ViewUnmap, SEC_NO_CHANGE, PAGE_EXECUTE_READ);
				while (NtLockVirtualMemory(hProcess, &ViewBase, &LockSize, 1) == STATUS_WORKING_SET_QUOTA)
					ExtendWorkingSet(hProcess);

				// 7. Remap with PAGE_READWRITE (writable section)
				SectionOffset.QuadPart = ViewSize;
				ViewBase = ModuleBase + ViewSize;
				ViewSize = SizeOfImage - ViewSize;
				NtMapViewOfSection(hSection, hProcess, &ViewBase, NULL, NULL, &SectionOffset, &ViewSize, ViewUnmap, NULL, PAGE_READWRITE);
			}

			// This module is not excepted but too small size to remap with PAGE_EXECUTE_READ
			else
				NtMapViewOfSection(hSection, hProcess, &ViewBase, NULL, NULL, NULL, &ViewSize, ViewUnmap, NULL, PAGE_EXECUTE_WRITECOPY);

			// Restore page protection
			DWORD OldProtect = 0;
			DWORD64 Size = PAGE_SIZE;
			PVOID Address = (PVOID)ModuleBase;
			((_NtProtectVirtualMemory)APICall(ntdll, APICall_NtProtectVirtualMemory))(hProcess, &Address, &Size, PAGE_READONLY, &OldProtect);
			for (DWORD i = 0, Protect; i < pNtHeader->FileHeader.NumberOfSections; i++)
			{
				if (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)		Protect = PAGE_EXECUTE_READ;
				else if (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE)	Protect = PAGE_WRITECOPY;
				else																Protect = PAGE_READONLY;
				OldProtect = 0;
				Size = pSectionHeader[i].Misc.VirtualSize;
				Address = (PVOID)(ModuleBase + pSectionHeader[i].VirtualAddress);
				((_NtProtectVirtualMemory)APICall(ntdll, APICall_NtProtectVirtualMemory))(hProcess, &Address, &Size, Protect, &OldProtect);
			}

			// 8. Lock memory (.text section)
			ViewBase += PAGE_SIZE;
			while (NtLockVirtualMemory(hProcess, &ViewBase, &LockSize, 1) == STATUS_WORKING_SET_QUOTA)
				ExtendWorkingSet(hProcess);
		}

#if _HIDE_FROM_DEBUGGER & ENABLE
		// Add this module's section handle in list.
		AddSection(hProcess, hSection, (PVOID)ModuleBase);
#endif
#if !(_HIDE_FROM_DEBUGGER & ENABLE)
		CloseHandle(hSection);
#endif
		// Release mapped module
		DWORD64 ImageSize = NULL;
		((_NtFreeVirtualMemory)APICall(ntdll, APICall_NtFreeVirtualMemory))(CURRENT_PROCESS, (PVOID*)&MappedModule, &ImageSize, MEM_RELEASE);
	}

	// Release proxy ntdll.dll
	if (proxy_ntdll)
	{
		DWORD64 ImageSize = NULL;
		((_NtFreeVirtualMemory)APICall(ntdll, APICall_NtFreeVirtualMemory))(CURRENT_PROCESS, (PVOID*)&proxy_ntdll, &ImageSize, MEM_RELEASE);
	}
}
