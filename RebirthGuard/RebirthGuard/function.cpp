
/********************************************
*											*
*	RebirthGuard/function.cpp - chztbby		*
*											*
********************************************/

#include "RebirthGuard.h"


//-----------------------------------------------------------------
//	Get PE Header
//-----------------------------------------------------------------
PVOID GetPEHeader(HANDLE hProcess, PVOID ModuleBase)
{
	if (hProcess == CURRENT_PROCESS)
		return ModuleBase;

	PVOID	PEHeader = NULL;
	DWORD64 PEHeaderSize = PAGE_SIZE;
	((_NtAllocateVirtualMemory)APICall(ntdll, APICall_NtAllocateVirtualMemory))(CURRENT_PROCESS, &PEHeader, NULL, &PEHeaderSize, MEM_COMMIT, PAGE_READWRITE);
	((_NtReadVirtualMemory)APICall(ntdll, APICall_NtReadVirtualMemory))(hProcess, (PVOID)ModuleBase, PEHeader, (DWORD)PEHeaderSize, NULL);
	return PEHeader;
}


//-----------------------------------------------------------------
//	Get module path by InMemoryOrderModuleList index
//-----------------------------------------------------------------
WCHAR* GetModulePath(DWORD ModuleIndex)
{
	static WCHAR ModulePath[4][MAX_PATH] = { 0, };

	if (ModulePath[ModuleIndex][0] == 0)
	{
		LDR_DATA_TABLE_ENTRY List;
		*(DWORD64*)&List = 0;

		for (DWORD i = 0; i <= ModuleIndex; i++)
			NextModule(CURRENT_PROCESS, &List);

		mywcscpy(ModulePath[ModuleIndex], (WCHAR*)*(PVOID*)((DWORD64)&List + 0x40));
	}

	return ModulePath[ModuleIndex];
}


//-----------------------------------------------------------------
//	Get module list of process
//-----------------------------------------------------------------
PVOID NextModule(HANDLE hProcess, PLDR_DATA_TABLE_ENTRY pList)
{
	static LDR_DATA_TABLE_ENTRY* FirstLink = NULL;

	if (hProcess == CURRENT_PROCESS)
	{
		// Get module list of current process
		if (*(DWORD64*)pList == NULL)
		{
			if (FirstLink == NULL)
			{
				FirstLink = (LDR_DATA_TABLE_ENTRY*)(*(*((PTEB)__readgsqword(0x30))->ProcessEnvironmentBlock).Ldr).InMemoryOrderModuleList.Flink;
				*pList = *(LDR_DATA_TABLE_ENTRY*)(*(*((PTEB)__readgsqword(0x30))->ProcessEnvironmentBlock).Ldr).InMemoryOrderModuleList.Flink;
			}
			else
				*pList = *FirstLink;
		}
		else
			*pList = *(LDR_DATA_TABLE_ENTRY*)(*(DWORD64*)pList);
	}
	else
	{
		// Get module list of target process
		if (*(DWORD64*)pList == NULL)
		{
			PROCESS_BASIC_INFORMATION pbi;
			((_NtQueryInformationProcess)APICall(ntdll, APICall_NtQueryInformationProcess))(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);

			PEB pPEB;
			PEB_LDR_DATA Ldr;
			((_NtReadVirtualMemory)APICall(ntdll, APICall_NtReadVirtualMemory))(hProcess, pbi.PebBaseAddress, &pPEB, sizeof(pPEB), NULL);
			((_NtReadVirtualMemory)APICall(ntdll, APICall_NtReadVirtualMemory))(hProcess, pPEB.Ldr, &Ldr, sizeof(Ldr), NULL);
			((_NtReadVirtualMemory)APICall(ntdll, APICall_NtReadVirtualMemory))(hProcess, Ldr.InMemoryOrderModuleList.Flink, pList, sizeof(LDR_DATA_TABLE_ENTRY), NULL);
		}
		else
			((_NtReadVirtualMemory)APICall(ntdll, APICall_NtReadVirtualMemory))(hProcess, (PVOID)*(DWORD64*)pList, pList, sizeof(LDR_DATA_TABLE_ENTRY), NULL);
	}

	return pList->DllBase;
}


//-----------------------------------------------------------------
//	Hide Module
//-----------------------------------------------------------------
VOID HideModule(VOID)
{
	PPEB_LDR_DATA_ pLdrData = (PPEB_LDR_DATA_)(*((PTEB)__readgsqword(0x30))->ProcessEnvironmentBlock).Ldr;

	PLIST_ENTRY pUserModule = NULL;
	pUserModule = pLdrData->InLoadOrderModuleList.Flink;
	pUserModule->Blink->Flink = pUserModule->Flink;
	pUserModule->Flink->Blink = pUserModule->Blink;

	pUserModule = pLdrData->InMemoryOrderModuleList.Flink;
	pUserModule->Blink->Flink = pUserModule->Flink;
	pUserModule->Flink->Blink = pUserModule->Blink;

	pUserModule = pLdrData->InInitializationOrderModuleList.Flink;
	pUserModule->Blink->Flink = pUserModule->Flink;
	pUserModule->Flink->Blink = pUserModule->Blink;
}


//-----------------------------------------------------------------
//	GetModuleHandleEx
//-----------------------------------------------------------------
HMODULE myGetModuleHandleEx(HANDLE hProcess, CONST WCHAR* ModulePath)
{
	LDR_DATA_TABLE_ENTRY List;
	*(DWORD64*)&List = 0;

	while (NextModule(hProcess, &List))
	{
		if (ModulePath == NULL)
			return *(HMODULE*)((DWORD64)&List + 0x20);

		WCHAR ModuleName[MAX_PATH];
		ModuleName[0] = '\0';

		if (hProcess == CURRENT_PROCESS)	
			mywcscpy(ModuleName, List.FullDllName.Buffer);
		else								
			((_NtReadVirtualMemory)APICall(ntdll, APICall_NtReadVirtualMemory))(hProcess, List.FullDllName.Buffer, ModuleName, MAX_PATH, NULL);

		if (mywcsistr(ModulePath, ModuleName))
			return *(HMODULE*)((DWORD64)&List + 0x20);
	}

	return NULL;
}


//-----------------------------------------------------------------
//	GetProcAddress
//-----------------------------------------------------------------
FARPROC myGetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
	PIMAGE_NT_HEADERS		pnh = GetNtHeader(hModule);
	PIMAGE_DATA_DIRECTORY	pdd = &pnh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	PIMAGE_EXPORT_DIRECTORY ped = (PIMAGE_EXPORT_DIRECTORY)((DWORD64)hModule + pdd->VirtualAddress);

	PDWORD	pFuncTbl = (PDWORD)((DWORD64)hModule + ped->AddressOfFunctions);
	PWORD	pOrdnTbl = (PWORD)((DWORD64)hModule + ped->AddressOfNameOrdinals);
	if ((DWORD_PTR)lpProcName <= 0xFFFF)
	{
		WORD wOrdinal = (WORD)IMAGE_ORDINAL((DWORD_PTR)lpProcName);
		wOrdinal -= (WORD)ped->Base;
		if (wOrdinal < ped->NumberOfFunctions)
			return (FARPROC)((DWORD64)hModule + pFuncTbl[wOrdinal]);
	}
	else
	{
		PDWORD pFuncNameTbl = (PDWORD)((DWORD64)hModule + ped->AddressOfNames);
		for (DWORD dwFuncIdx = 0; dwFuncIdx < ped->NumberOfNames; dwFuncIdx++)
		{
			PCSTR pFuncName = (PCSTR)((DWORD64)hModule + pFuncNameTbl[dwFuncIdx]);
			if (!mystrcmp(lpProcName, pFuncName))
			{
				WORD wOrdinal = pOrdnTbl[dwFuncIdx];
				return (FARPROC)((DWORD64)hModule + pFuncTbl[wOrdinal]);
			}
		}
	}
	return NULL;
}


//-----------------------------------------------------------------
//	Call API by encrypted string
//-----------------------------------------------------------------
FARPROC APICall(DWORD ModuleIndex, APICall_Number API)
{
	if (ModuleIndex > 3)
		Report(CURRENT_PROCESS, ENABLE | _LOG | _POPUP | _KILL, APICALL_Invalid_Module, (PVOID)(DWORD64)ModuleIndex, (PVOID)API);

	CHAR APIName[50];
	DecryptXOR(APIName, API);

	FARPROC APIAddress = myGetProcAddress(myGetModuleHandleEx(CURRENT_PROCESS, GetModulePath(ModuleIndex)), APIName);

	for (DWORD i = 0; i < sizeof(APIName); i++)
		APIName[i] = 0;

	return APIAddress;
}


//-----------------------------------------------------------------
//	Report violation
//-----------------------------------------------------------------
VOID Report(HANDLE hProcess, DWORD ErrorFlag, REBIRTHGUARD_REPORT_CODE ErrorCode, PVOID ErrorAddress, PVOID ErrorAddress2)
{
	WCHAR Buffer[MAX_PATH];
	WCHAR Buffer2[MAX_PATH];
	WCHAR ModuleName[MAX_PATH] = L"";
	WCHAR ModuleName2[MAX_PATH] = L"";
	WCHAR ModulePath[MAX_PATH] = L"";
	WCHAR ModulePath2[MAX_PATH] = L"";

	// Time stamp
	time_t t = time(NULL);
	tm tm;
	localtime_s(&tm, &t);

	// Address check
	DWORD64 order = IsInModule(hProcess, ErrorAddress, 2);
	DWORD64 order2 = IsInModule(hProcess, ErrorAddress2, 2);

	// Search module
	LDR_DATA_TABLE_ENTRY List;
	*(DWORD64*)&List = 0;
	for (int i = 0; NextModule(hProcess, &List); i++)
	{
		((_NtReadVirtualMemory)APICall(ntdll, APICall_NtReadVirtualMemory))(hProcess, List.FullDllName.Buffer, Buffer, MAX_PATH, NULL);
		((_NtReadVirtualMemory)APICall(ntdll, APICall_NtReadVirtualMemory))(hProcess, *(PVOID*)((BYTE*)&List + 0x40), Buffer2, MAX_PATH, NULL);

		if (order == i)
		{
			mywcscpy(ModuleName, Buffer);
			mywcscat(ModuleName, L" + ");
			mywcscpy(ModulePath, Buffer2);
		}
		if (order2 == i)
		{
			mywcscpy(ModuleName2, Buffer2);
			mywcscat(ModuleName2, L" + ");
			mywcscpy(ModulePath2, Buffer2);
		}
	}

	// Print log to the file
	if (ErrorFlag & _LOG)
	{
		FILE* log = NULL;
		fopen_s(&log, "RebirthGuard.log", "a+");
		fprintf(log,
			"[ %04d-%02d-%02d %02d:%02d:%02d ]\n\n"
			"    Pid\t: %d\n"
			"    Code\t: 0x%08X\n\n"
			"    %S0x%I64X (0x%X)\n"
			"    %S0x%I64X (0x%X)\n\n"
			"-----------------------------------------------------------------------------------\n",
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
			GetCurrentProcessId(),
			ErrorCode,
			ModuleName, (DWORD64)ErrorAddress - (DWORD64)myGetModuleHandleEx(hProcess, ModulePath), GetFileCheckSum(ModulePath),
			ModuleName2, (DWORD64)ErrorAddress2 - (DWORD64)myGetModuleHandleEx(hProcess, ModulePath2), GetFileCheckSum(ModulePath2));
		fclose(log);
	}

	// Pop up
	if (ErrorFlag & _POPUP)
	{
		CHAR scriptpath[MAX_PATH];
		GetCurrentDirectoryA(MAX_PATH, scriptpath);
		mystrcat(scriptpath, "\\RebirthGuard.vbs");

		FILE* log = NULL;
		fopen_s(&log, "RebirthGuard.vbs", "w+");
		fprintf(log,
			"Dim obj, file\n"
			"Set obj = CreateObject(\"Scripting.FileSystemObject\")\n"
			"Set file = obj.GetFile(\"%s\")\n"
			"file.Delete\n"
			"msgbox \"[ %04d-%02d-%02d %02d:%02d:%02d ]\" & Chr(13) & Chr(13) &"
			"\"Pid\t:  %d\" & Chr(13) & "
			"\"Code\t:  0x%08X\" & Chr(13) & Chr(13) &"
			"\"%S0x%I64X (0x%X)\" & Chr(13) &"
			"\"%S0x%I64X (0x%X)\", 0 + 48, \"RebirthGuard\""
			, scriptpath,
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
			GetCurrentProcessId(),
			ErrorCode,
			ModuleName, (DWORD64)ErrorAddress - (DWORD64)myGetModuleHandleEx(hProcess, ModulePath), GetFileCheckSum(ModulePath),
			ModuleName2, (DWORD64)ErrorAddress2 - (DWORD64)myGetModuleHandleEx(hProcess, ModulePath2), GetFileCheckSum(ModulePath2));
		fclose(log);

		CHAR path[MAX_PATH] = "wscript.exe \"";
		mystrcat(path, scriptpath);
		mystrcat(path, "\"");

		((_WinExec)APICall(kernel32, APICall_WinExec))(path, SW_SHOW);
	}

	// Free memory
	if (ErrorFlag & _MEM_FREE)
	{
		DWORD64 Size = NULL;
		PVOID Address = ErrorAddress;
		((_NtFreeVirtualMemory)APICall(ntdll, APICall_NtFreeVirtualMemory))(hProcess, &Address, &Size, MEM_RELEASE);
		((_NtFreeVirtualMemory)APICall(ntdll, APICall_NtFreeVirtualMemory))(hProcess, &Address, &Size, MEM_RELEASE | MEM_DECOMMIT);
	}

	// Terminate process
	if (ErrorFlag & _KILL)
	{
		((_NtTerminateProcess)APICall(ntdll, APICall_NtTerminateProcess))(hProcess, 0);
		((_NtTerminateProcess)APICall(ntdll, APICall_NtTerminateProcess))(CURRENT_PROCESS, 0);
	}
}