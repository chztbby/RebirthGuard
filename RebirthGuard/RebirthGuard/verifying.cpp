
/********************************************
*											*
*	RebirthGuard/verifying.cpp - chztbby	*
*											*
********************************************/

#include "RebirthGuard.h"


//-----------------------------------------------------------------
//	Check Whitelist
//-----------------------------------------------------------------
DWORD IsExcepted(CONST WCHAR* ModulePath)
{
	DWORD Flag = 0;

	for (int i = 0; Whitelist_ForcePageProtection[i][0] != 0; i++)
		if (mywcsistr(ModulePath, Whitelist_ForcePageProtection[i]))
			Flag |= EXCEPT_REBIRTH;

	for (int i = 0; Whitelist_FileCheck[i][0] != 0; i++)
		if (mywcsistr(ModulePath, Whitelist_FileCheck[i]))
			Flag |= EXCEPT_FILE_INTEGRITY;

	return Flag;
}


//-----------------------------------------------------------------
//	Check this module is rebirthed
//-----------------------------------------------------------------
BOOL IsRebirthed(HANDLE hProcess, PVOID ModuleBase)
{
	PSAPI_WORKING_SET_EX_INFORMATION wsi;
	wsi.VirtualAddress = ModuleBase;
	((_NtQueryVirtualMemory)APICall(ntdll, APICall_NtQueryVirtualMemory))(hProcess, ModuleBase, MemoryWorkingSetExList, &wsi, sizeof(wsi), 0);

	if (wsi.VirtualAttributes.Locked == 0)	return FALSE;	// This module is not rebirthed
	else									return TRUE;	// This module is already rebirthed
}


//-----------------------------------------------------------------
//	Check this address is in module region and return data
//
//  Type 0 : .text Section (return ModuleBase)
//  Type 1 : Full range (return ModuleBase)
//  Type 2 : Full range (return InMemoryOrderModuleList index)
//-----------------------------------------------------------------
DWORD64 IsInModule(HANDLE hProcess, PVOID Address, DWORD Type)
{
	LDR_DATA_TABLE_ENTRY List;
	*(DWORD64*)&List = 0;

	// Search module
	for (int i = 0; NextModule(hProcess, &List); i++)
	{
		DWORD64 ModuleBase = (DWORD64)(*(DWORD64*)((BYTE*)&List + 0x20));

		PVOID					PEHeader		= GetPEHeader(hProcess, (PVOID)ModuleBase);
		DWORD64					PEHeaderSize	= PAGE_SIZE;
		PIMAGE_NT_HEADERS		pNtHeader		= GetNtHeader(PEHeader);
		PIMAGE_SECTION_HEADER	pSectionHeader	= IMAGE_FIRST_SECTION(pNtHeader);

		DWORD64 ExecuteSize = 0;
		for (DWORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
		{
			if (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
				ExecuteSize += PADDING(pSectionHeader[i].Misc.VirtualSize, pNtHeader->OptionalHeader.SectionAlignment);
			else
				break;
		}

		DWORD64 result = -1;

		// The address is in .text section
		if (Type == 0 && (DWORD64)ModuleBase + (DWORD64)pNtHeader->OptionalHeader.SectionAlignment <= (DWORD64)Address && (DWORD64)Address < (DWORD64)ModuleBase + (DWORD64)pNtHeader->OptionalHeader.SectionAlignment + ExecuteSize)
			result = ModuleBase;

		// The address is in module (return base address)
		else if (Type == 1 && (DWORD64)ModuleBase <= (DWORD64)Address && (DWORD64)Address < (DWORD64)ModuleBase + (DWORD64)pNtHeader->OptionalHeader.SizeOfImage)
			result = ModuleBase;

		// The address is in module (return module's InMemoryOrderModuleList order)
		else if (Type == 2 && (DWORD64)ModuleBase <= (DWORD64)Address && (DWORD64)Address < (DWORD64)ModuleBase + (DWORD64)pNtHeader->OptionalHeader.SizeOfImage)
			result = i;

		if (hProcess != CURRENT_PROCESS)
			((_NtFreeVirtualMemory)APICall(ntdll, APICall_NtFreeVirtualMemory))(CURRENT_PROCESS, &PEHeader, &PEHeaderSize, MEM_RELEASE);

		if (result != -1)
			return result;

	}
	// The address is invalid.
	return -1;
}


//-----------------------------------------------------------------
//	Compare Byte
//-----------------------------------------------------------------
BOOL CompareByte(PVOID Original, PVOID Target)
{
	DWORD count = 0, i = 0;

	for (; *((BYTE*)Original + i) != 0xCC; i++)
		if (*((BYTE*)Original + i) == *((BYTE*)Target + i))
			count++;

	return count == i;
}


//-----------------------------------------------------------------
//	Check thread start address.
//-----------------------------------------------------------------
VOID ThreadCheck(PVOID StartAddress, DWORD Type)
{
	// Set thread information (ThreadHideFromDebugger)
#if ANTI_DEBUGGING & ENABLE
	((_NtSetInformationThread)APICall(ntdll, APICall_NtSetInformationThread))(CURRENT_THREAD, ThreadHideFromDebugger, NULL, NULL);
#endif

	// Query memory information of thread start address
	MEMORY_BASIC_INFORMATION mbi;
	((_NtQueryVirtualMemory)APICall(ntdll, APICall_NtQueryVirtualMemory))(CURRENT_PROCESS, StartAddress, MemoryBasicInformation, &mbi, sizeof(mbi), 0);

#if THREAD_CHECK & ENABLE
	// Start address is not module memory
	if (IsInModule(CURRENT_PROCESS, StartAddress, 0) == -1)
		Report(CURRENT_PROCESS, THREAD_CHECK, THREAD_StartAddress, StartAddress, (PVOID)(DWORD64)Type);

	// Start address is writable
	else if (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY)
		Report(CURRENT_PROCESS, THREAD_CHECK, THREAD_Protection, StartAddress, (PVOID)(DWORD64)Type);
#endif

	// Anti-DLL Injection
#if ANTI_DLL_INJECTION & ENABLE
		// DLL Injection with LoadLibraryA in Kernel32.dll
	if (CompareByte(APICall(kernel32, APICall_LoadLibraryA), StartAddress))
		Report(CURRENT_PROCESS, ANTI_DLL_INJECTION, DLL_INJECTION_Kernel32_LoadLibraryA, StartAddress, (PVOID)(DWORD64)Type);

	// DLL Injection with LoadLibraryW in Kernel32.dll
	else if (CompareByte(APICall(kernel32, APICall_LoadLibraryW), StartAddress))
		Report(CURRENT_PROCESS, ANTI_DLL_INJECTION, DLL_INJECTION_Kernel32_LoadLibraryW, StartAddress, (PVOID)(DWORD64)Type);

	// DLL Injection with LoadLibraryExA in Kernel32.dll
	else if (CompareByte(APICall(kernel32, APICall_LoadLibraryExA), StartAddress))
		Report(CURRENT_PROCESS, ANTI_DLL_INJECTION, DLL_INJECTION_Kernel32_LoadLibraryExA, StartAddress, (PVOID)(DWORD64)Type);

	// DLL Injection with LoadLibraryExW in Kernel32.dll
	else if (CompareByte(APICall(kernel32, APICall_LoadLibraryExW), StartAddress))
		Report(CURRENT_PROCESS, ANTI_DLL_INJECTION, DLL_INJECTION_Kernel32_LoadLibraryExW, StartAddress, (PVOID)(DWORD64)Type);

	// DLL Injection with LoadLibraryA in KernelBase.dll
	else if (CompareByte(APICall(kernelbase, APICall_LoadLibraryA), StartAddress))
		Report(CURRENT_PROCESS, ANTI_DLL_INJECTION, DLL_INJECTION_KernelBase_LoadLibraryA, StartAddress, (PVOID)(DWORD64)Type);

	// DLL Injection with LoadLibraryW in KernelBase.dll
	else if (CompareByte(APICall(kernelbase, APICall_LoadLibraryW), StartAddress))
		Report(CURRENT_PROCESS, ANTI_DLL_INJECTION, DLL_INJECTION_KernelBase_LoadLibraryW, StartAddress, (PVOID)(DWORD64)Type);

	// DLL Injection with LoadLibraryExA in KernelBase.dll
	else if (CompareByte(APICall(kernelbase, APICall_LoadLibraryExA), StartAddress))
		Report(CURRENT_PROCESS, ANTI_DLL_INJECTION, DLL_INJECTION_KernelBase_LoadLibraryExA, StartAddress, (PVOID)(DWORD64)Type);

	// DLL Injection with LoadLibraryExW in KernelBase.dll
	else if (CompareByte(APICall(kernelbase, APICall_LoadLibraryExW), StartAddress))
		Report(CURRENT_PROCESS, ANTI_DLL_INJECTION, DLL_INJECTION_KernelBase_LoadLibraryExW, StartAddress, (PVOID)(DWORD64)Type);

	// DLL Injection with LdrLoadDll in ntdll.dll
	else if (CompareByte(APICall(ntdll, APICall_LdrLoadDll), StartAddress))
		Report(CURRENT_PROCESS, ANTI_DLL_INJECTION, DLL_INJECTION_Ntdll_LdrLoadDll, StartAddress, (PVOID)(DWORD64)Type);
#endif
}


//-----------------------------------------------------------------
//	Destory the code section in module region.
//  If the module has been rebirthed, it will not be affected.
//-----------------------------------------------------------------
VOID DestoryModule(HANDLE hProcess)
{
	LDR_DATA_TABLE_ENTRY List;
	*(DWORD64*)&List = 0;

	while (NextModule(hProcess, &List))
	{
		WCHAR ModulePath[MAX_PATH];
		((_NtReadVirtualMemory)APICall(ntdll, APICall_NtReadVirtualMemory))(hProcess, *(PVOID*)((BYTE*)&List + 0x40), ModulePath, MAX_PATH, NULL);

		// Check this module is excepted
		if (!(IsExcepted(ModulePath) & EXCEPT_REBIRTH))
		{
			DWORD64					ModuleBase		= (DWORD64)(*(DWORD64*)((BYTE*)&List + 0x20));
			DWORD					Protect			= NULL;
			PVOID					mem				= NULL;

			PVOID					PEHeader		= GetPEHeader(hProcess, (PVOID)ModuleBase);
			DWORD64					PEHeaderSize	= PAGE_SIZE;
			PIMAGE_NT_HEADERS		pNtHeader		= GetNtHeader(PEHeader);
			PIMAGE_SECTION_HEADER	pSectionHeader	= IMAGE_FIRST_SECTION(pNtHeader);

			PVOID					Address			= (PVOID)((DWORD64)ModuleBase + pNtHeader->OptionalHeader.SectionAlignment);
			DWORD64					WriteSize		= NULL;

			// Get size of (.text + .rdata) section
			for (DWORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
			{
				if (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE)
				{
					WriteSize = pSectionHeader[i].VirtualAddress;
					break;
				}
			}

			// Destory memory
			((_NtAllocateVirtualMemory)	APICall(ntdll, APICall_NtAllocateVirtualMemory))	(CURRENT_PROCESS, &mem, NULL, &WriteSize, MEM_COMMIT, PAGE_READWRITE);
			((_NtProtectVirtualMemory)	APICall(ntdll, APICall_NtProtectVirtualMemory))	(hProcess, &Address, &WriteSize, PAGE_EXECUTE_READWRITE, &Protect);
			((_NtWriteVirtualMemory)	APICall(ntdll, APICall_NtWriteVirtualMemory))	(hProcess, Address, mem, WriteSize, NULL);
			WriteSize = NULL;
			((_NtFreeVirtualMemory)		APICall(ntdll, APICall_NtFreeVirtualMemory))	(CURRENT_PROCESS, &mem, &WriteSize, MEM_RELEASE);

			if (hProcess != CURRENT_PROCESS)
				((_NtFreeVirtualMemory)APICall(ntdll, APICall_NtFreeVirtualMemory))(CURRENT_PROCESS, &PEHeader, &PEHeaderSize, MEM_RELEASE);
		}
	}
}


//-----------------------------------------------------------------
//	Check the all memory region
//-----------------------------------------------------------------
VOID MemCheck(HANDLE hProcess)
{
#if MEM_CHECK & ENABLE
	// Destory module memory
	DestoryModule(hProcess);

	// Scan all of memory regions
	for (PVOID Address = 0; (DWORD64)Address < 0x7FFFFFFF0000;)
	{
		// Query memory information of target address
		MEMORY_BASIC_INFORMATION mbi;
		((_NtQueryVirtualMemory)APICall(ntdll, APICall_NtQueryVirtualMemory))(hProcess, Address, MemoryBasicInformation, &mbi, sizeof(mbi), 0);

		// This region is not rebirthed
		if (mbi.Type == MEM_IMAGE && !(mbi.Protect & PAGE_WRITECOPY))
			Report(hProcess, MEM_CHECK, MEMORY_Image, Address, (PVOID)0);

		// This region is EXECUTABLE but is not in module
		else if (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) && IsInModule(hProcess, Address, 2) == -1)
			Report(hProcess, MEM_CHECK, MEMORY_Private_Execute, Address, (PVOID)0);

		// This region is not rebirthed
		else if (mbi.Protect == PAGE_EXECUTE_WRITECOPY && IsRebirthed(hProcess, Address) == FALSE)
			Report(hProcess, MEM_CHECK, MEMORY_NotRebirthed, Address, (PVOID)0);

		// This region's page protection is not restored
		else if (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY)
			Report(hProcess, MEM_CHECK, MEMORY_Execute_Write, Address, (PVOID)0);

		// This region is invalid
		else if (mbi.Protect == PAGE_EXECUTE_READ || (IsInModule(hProcess, Address, 1) == (DWORD64)myGetModuleHandleEx(CURRENT_PROCESS, NULL)))
		{
			PSAPI_WORKING_SET_EX_INFORMATION wsi;
			wsi.VirtualAddress = Address;
			((_NtQueryVirtualMemory)APICall(ntdll, APICall_NtQueryVirtualMemory))(hProcess, Address, MemoryWorkingSetExList, &wsi, sizeof(wsi), 0);

			if (wsi.VirtualAttributes.Locked == 0)
				Report(hProcess, MEM_CHECK, MEMORY_Unlocked, Address, (PVOID)0);

			else if (*((BYTE*)&wsi.VirtualAttributes.Flags + 2) != 0x40)
				Report(hProcess, MEM_CHECK, MEMORY_Unlocked_2, Address, (PVOID)0);
		}

		Address = (PVOID)((DWORD64)Address + mbi.RegionSize);
	}
#endif
}


//-----------------------------------------------------------------------
//	Check the integrity of .text and .rdata section
//-----------------------------------------------------------------------
VOID CRCCheck(VOID)
{
#if CRC_CHECK & ENABLE
	LDR_DATA_TABLE_ENTRY List;
	*(DWORD64*)&List = 0;

	for (DWORD i = 0; NextModule(CURRENT_PROCESS, &List); i++)
	{
		// Get base address of module.
		DWORD64 ModuleBase = (DWORD64)myGetModuleHandleEx(CURRENT_PROCESS, List.FullDllName.Buffer);
		WCHAR* ModulePath = (WCHAR*)*(PVOID*)((BYTE*)&List + 0x40);

		// Query memory information of target address
		MEMORY_BASIC_INFORMATION mbi;
		((_NtQueryVirtualMemory)APICall(ntdll, APICall_NtQueryVirtualMemory))(CURRENT_PROCESS, (PVOID)ModuleBase, MemoryBasicInformation, &mbi, sizeof(mbi), 0);

		if (!(IsExcepted(ModulePath) & EXCEPT_REBIRTH) && !(mbi.Protect & PAGE_WRITECOPY))
		{
			// Mapping mirror view to CRC check.
#if _HIDE_FROM_DEBUGGER & ENABLE
			for (int i = 0;; i++)
			{
				if (SectionList[i].ModuleBase == NULL)
					Report(CURRENT_PROCESS, CRC_CHECK, CRCCheck_Section_Error, (PVOID)ModuleBase, (PVOID)0);

				if (SectionList[i].ModuleBase == (PVOID)ModuleBase)
				{
					LARGE_INTEGER SectionOffset;
					SectionOffset.QuadPart = NULL;
					PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(ModuleBase);
					DWORD64 ViewSize = pNtHeader->OptionalHeader.SizeOfImage;

					ModuleBase = NULL;
					while (!ModuleBase)
					{
						ModuleBase = NULL;
						((_NtMapViewOfSection)APICall(ntdll, APICall_NtMapViewOfSection))(SectionList[i].hSection, CURRENT_PROCESS, &ModuleBase, NULL, NULL, &SectionOffset, &ViewSize, ViewUnmap, SEC_NO_CHANGE, PAGE_READONLY);
					}

					break;
				}
			}
#endif
			// Manually map this module from file.
			DWORD64 MappedModule = (DWORD64)ManualMap(CURRENT_PROCESS, ModulePath);
			if (i == ntdll)
			{
				DWORD64 offset = (DWORD64)APICall(ntdll, APICall_RtlUserThreadStart) - (DWORD64)myGetModuleHandleEx(CURRENT_PROCESS, GetModulePath(ntdll));
				BYTE jmp_myRtlUserThreadStart[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, };
				*(DWORD64*)(jmp_myRtlUserThreadStart + 6) = (DWORD64)Thread_Callback;
				for (DWORD64 i = 0; i < 14; i++)
					*(BYTE*)(MappedModule + offset + i) = jmp_myRtlUserThreadStart[i];
			}

			(GetNtHeader(MappedModule))->OptionalHeader.ImageBase = (DWORD64)myGetModuleHandleEx(CURRENT_PROCESS, ModulePath);;

			// CRC64 Check
			if (CRC64((PVOID)ModuleBase) != CRC64((PVOID)MappedModule))
				Report(CURRENT_PROCESS, CRC_CHECK, CRCCheck_Integrity, (PVOID)myGetModuleHandleEx(CURRENT_PROCESS, List.FullDllName.Buffer), (PVOID)0);

			// Unmapping mirror view
#if _HIDE_FROM_DEBUGGER & ENABLE
			((_NtUnmapViewOfSection)APICall(ntdll, APICall_NtUnmapViewOfSection))(CURRENT_PROCESS, ModuleBase);
#endif

			// Release mapped module
			DWORD64 ImageSize = NULL;
			((_NtFreeVirtualMemory)APICall(ntdll, APICall_NtFreeVirtualMemory))(CURRENT_PROCESS, (PVOID*)&MappedModule, &ImageSize, MEM_RELEASE);
		}
	}
#endif
}


//-----------------------------------------------------------------------
//	Calculate CheckSum
//-----------------------------------------------------------------------
WORD CalculateCheckSum(UINT CheckSum, PVOID FileBase, INT Length)
{
	INT* Data;
	INT sum;

	if (Length && FileBase != NULL)
	{
		Data = (INT *)FileBase;
		do
		{
			sum = *(WORD*)Data + CheckSum;
			Data = (INT*)((CHAR*)Data + 2);
			CheckSum = (WORD)sum + (sum >> 16);
		} while (--Length);
	}

	return CheckSum + (CheckSum >> 16);
}


//-----------------------------------------------------------------------
//	Get File CheckSum.
//-----------------------------------------------------------------------
DWORD GetFileCheckSum(CONST WCHAR* ModulePath)
{
	DWORD CheckSum = 0;

	HANDLE hFile = ((_CreateFileW)APICall(kernelbase, APICall_CreateFileW))(ModulePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);

	if (hFile != INVALID_HANDLE_VALUE)
	{
		DWORD			FileSize	= GetFileSize(hFile, NULL);
		PVOID			ImageBase	= NULL;
		DWORD64			AllocSize	= FileSize;

		((_NtAllocateVirtualMemory)APICall(ntdll, APICall_NtAllocateVirtualMemory))(CURRENT_PROCESS, &ImageBase, NULL, &AllocSize, MEM_COMMIT, PAGE_READWRITE);
		((_ReadFile)APICall(kernelbase, APICall_ReadFile))(hFile, ImageBase, FileSize, NULL, NULL);
		CloseHandle(hFile);

		PVOID RemainData;
		INT RemainDataSize;
		DWORD64 PeHeaderSize;
		DWORD PeHeaderCheckSum;
		DWORD FileCheckSum;
		PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(ImageBase);

		if (pNtHeader)
		{
			PeHeaderSize = (DWORD64)pNtHeader - (DWORD64)ImageBase + ((DWORD64)&pNtHeader->OptionalHeader.CheckSum - (DWORD64)pNtHeader);
			RemainDataSize = (INT)((FileSize - PeHeaderSize - 4) >> 1);
			RemainData = &pNtHeader->OptionalHeader.Subsystem;
			PeHeaderCheckSum = CalculateCheckSum(0, (PVOID)ImageBase, (INT)PeHeaderSize >> 1);
			FileCheckSum = CalculateCheckSum(PeHeaderCheckSum, RemainData, RemainDataSize);

			if (FileSize & 1)
				FileCheckSum += (WORD)*((CHAR*)ImageBase + FileSize - 1);
		}
		else
			FileCheckSum = 0;

		CheckSum = FileSize + FileCheckSum;

		AllocSize = NULL;
		((_NtFreeVirtualMemory)APICall(ntdll, APICall_NtFreeVirtualMemory))(CURRENT_PROCESS, &ImageBase, &AllocSize, MEM_RELEASE);
	}

	return CheckSum;
}