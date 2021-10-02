
/********************************************
*											*
*	RebirthGuard/Settings.h - chztbby		*
*											*
********************************************/



//**********************************//
//		RebirthGuard Options		//
//**********************************//

#define DISABLE				0x00000000
#define ENABLE				0x00000001
#define		_LOG			0x00000002	
#define		_POPUP			0x00000004
#define		_KILL			0x00000008
#define		_MEM_FREE		0x00000010

//------------------------------------------------------------------------------------------------
//	#define	MODULE_REMAPPING			(DEFAULT)

										static CONST WCHAR* Whitelist_ForcePageProtection[] =
										{
											L"nvoglv64.dll",
											L""
										};
//------------------------------------------------------------------------------------------------
	#define HIDE_MODULELIST				ENABLE
//------------------------------------------------------------------------------------------------
	#define PROCESS_POLICY				ENABLE

		#define	_MS_SIGNED_ONLY			DISABLE
//------------------------------------------------------------------------------------------------
	#define FILE_CHECK					ENABLE | _LOG | _POPUP | _KILL

										static CONST WCHAR* Whitelist_FileCheck[] =
										{
											L"glew32.dll",
											L"assimp-vc140-mt.dll",
											L"freetype.dll",
											L"fmod64.dll",
											L""
										};
//------------------------------------------------------------------------------------------------
	#define THREAD_CHECK				ENABLE | _LOG | _POPUP | _KILL
//------------------------------------------------------------------------------------------------
	#define MEM_CHECK					ENABLE | _LOG // | _MEM_FREE
//------------------------------------------------------------------------------------------------
	#define CRC_CHECK					ENABLE | _LOG | _POPUP | _KILL

		#define	_HIDE_FROM_DEBUGGER		ENABLE
//------------------------------------------------------------------------------------------------
	#define ANTI_DLL_INJECTION			ENABLE | _LOG | _POPUP | _KILL
//------------------------------------------------------------------------------------------------
	#define ANTI_DEBUGGING				ENABLE | _LOG | _POPUP | _KILL
//------------------------------------------------------------------------------------------------
	#define EXCEPTION_HANDLING			ENABLE | _LOG | _POPUP
//------------------------------------------------------------------------------------------------
