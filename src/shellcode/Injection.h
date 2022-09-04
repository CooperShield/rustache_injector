#pragma once

//All our header files and declarations here in Injection.h:

#include <Windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>


using f_LoadLibraryA	 = HINSTANCE	(WINAPI*)(const char * lpLibFilename);
using f_GetProcAddress	 = UINT_PTR	(WINAPI*)(HINSTANCE hModule, const char * lpProcName);
using f_DLL_ENTRY_POINT  = BOOL		(WINAPI*)(void * hDll, DWORD dwReason, void * pReserved);

/*
struct MANUAL_MAPPING_DATA {
	void *pLoadLibraryA;
	void *pGetProcAddress;
	void *pDllBase;
	uint64_t Done;
}
*/

struct MANUAL_MAPPING_DATA
{
	f_LoadLibraryA		pLoadLibraryA;
	f_GetProcAddress	pGetProcAddress;

	void*				pDllBase;
	uint64_t				Done;
};

bool ManualMap(HANDLE hProc, const char * szDllFile);