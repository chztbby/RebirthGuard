
/*
	chztbby::RebirthGuard/log.cpp
*/

#include "RebirthGuard.h"


VOID RG_DebugLog(LPCWSTR format, ...)
{
#if RG_OPT_DEBUG_LOG & RG_ENABLE

#endif
}

VOID RG_Report(DWORD flag, RG_REPORT_CODE code, PVOID data1, PVOID data2)
{
	WCHAR module_name1[MAX_PATH] = L"";
	WCHAR module_name2[MAX_PATH] = L"";
	WCHAR module_path1[MAX_PATH] = L"";
	WCHAR module_path2[MAX_PATH] = L"";

	time_t t = time(NULL);
	tm tm;
	localtime_s(&tm, &t);

	PVOID module_base1 = GetModuleBaseFromPtr(data1, PC_IMAGE_SIZE);
	PVOID module_base2 = GetModuleBaseFromPtr(data2, PC_IMAGE_SIZE);

	LDR_MODULE module_info = { 0, };
	for (DWORD i = 0; RG_GetNextModule(&module_info); ++i)
	{
		if (module_base1 == module_info.BaseAddress)
		{
			RG_wcscpy(module_name1, module_info.BaseDllName.Buffer);
			RG_wcscat(module_name1, L" +");
			RG_wcscpy(module_path1, module_info.FullDllName.Buffer);
		}
		if (module_base2 == module_info.BaseAddress)
		{
			RG_wcscpy(module_name2, module_info.BaseDllName.Buffer);
			RG_wcscat(module_name2, L" +");
			RG_wcscpy(module_path2, module_info.FullDllName.Buffer);
		}
	}

	if (flag & RG_ENABLE_LOG)
	{
		FILE* log = NULL;
		fopen_s(&log, "RebirthGuard.log", "a+");
		fprintf(log,
			"[%04d-%02d-%02d %02d:%02d:%02d] Pid : %d / Code : 0x%08X / %S 0x%p / %S 0x%p\n",
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
			GetCurrentProcessId(),
			code,
			module_name1, (PVOID)GetOffset(RG_GetModuleHandleW(module_path1), data1),
			module_name2, (PVOID)GetOffset(RG_GetModuleHandleW(module_path2), data2));
		fclose(log);
	}

	if (flag & RG_ENABLE_POPUP)
	{
		CHAR scriptpath[MAX_PATH];
		APICALL(GetCurrentDirectoryA)(MAX_PATH, scriptpath);
		RG_strcat(scriptpath, "\\RebirthGuard.vbs");

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
			"\"%S 0x%p\" & Chr(13) &"
			"\"%S 0x%p\", 0 + 48, \"RebirthGuard\""
			, scriptpath,
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
			GetCurrentProcessId(),
			code,
			module_name1, (PVOID)GetOffset(RG_GetModuleHandleW(module_path1), data1),
			module_name2, (PVOID)GetOffset(RG_GetModuleHandleW(module_path2), data2));
		fclose(log);

		CHAR path[MAX_PATH] = "wscript.exe \"";
		RG_strcat(path, scriptpath);
		RG_strcat(path, "\"");

		APICALL(WinExec)(path, SW_SHOW);
	}

	if (flag & RG_ENABLE_DEALLOC)
		RG_FreeMemory(data1);

	if (flag & RG_ENABLE_KILL)
		APICALL(NtTerminateProcess)(CURRENT_PROCESS, 0);
}