#pragma once

#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

#define INITIAL_SEED 9 
#define INITIAL_HASH 8989

#define KERNEL32_HASH                   3346037101
#define VIRTUALALLOC_HASH               1121715183
#define VIRTUALPROTECT_HASH             2410263781
#define CREATETHREAD_HASH               2313769417
#define WAITFORSINGLEOBJECT_HASH		3156938386
//#define CREATEREMOTETHREAD_HASH         1860648501

typedef LPVOID	(WINAPI* ftVirtualAlloc)		(IN OPTIONAL LPVOID lpAddress, IN SIZE_T dwSize, IN DWORD flAllocationType, IN DWORD flProtect);
typedef BOOL	(WINAPI* ftVirtualProtect)		(IN LPVOID lpAddress, IN SIZE_T dwSize, IN DWORD flNewProtect, OUT PDWORD lpflOldProtect);
typedef HANDLE	(WINAPI* ftCreateThread)		(IN OPTIONAL LPSECURITY_ATTRIBUTES lpThreadAttributes, IN SIZE_T dwStackSize, IN LPTHREAD_START_ROUTINE lpStartAddress, IN OPTIONAL __drv_aliasesMem LPVOID lpParameter, IN DWORD dwCreationFlags, OUT OPTIONAL LPDWORD lpThreadId);
typedef DWORD	(WINAPI* ftWaitForSingleObject) (IN HANDLE hHandle, IN DWORD  dwMilliseconds);

typedef struct _API_TABLE
{
	HMODULE hKernel32;
	ftVirtualAlloc pVirtualAlloc;
	ftVirtualProtect pVirtualProtect;
	ftCreateThread pCreateThread;
	ftWaitForSingleObject pWaitForSingleObject;
	//FARPROC fpCreateRemoteThread;
} API_TABLE, * PAPI_TABLE;

// API Hashing functions defined in APIHashing.c
DWORD HashStringDjb2W(_In_ PWCHAR String);
DWORD HashStringDjb2A(_In_ PCHAR String);
BOOL IsStringEqual(IN LPCWSTR Str1, IN LPCWSTR Str2);
HMODULE CustomGetModuleHandleH(IN DWORD dwModuleHash);
FARPROC GetProcAddressReplacementH(IN HMODULE hModule, IN DWORD dwApiHash);
VOID InitializeAPITable(IN PAPI_TABLE pApiTable);
LPCWSTR GetFileFromPathW(IN wchar_t* wPath);
