#pragma once

#include <windows.h>
#include <tlhelp32.h>

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define STATUS_SUCCESS 0x00000000
#define STATUS_UNSUCCESSFUL 0xC0000001
#define STATUS_NOT_ALL_ASSIGNED 0x00000106

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$Process32First(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$Process32Next(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT int MSVCRT$_stricmp(const char*, const char*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupPrivilegeValueW(LPCWSTR, LPCWSTR, PLUID);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR, LPCSTR, PLUID);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$SetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD);
DECLSPEC_IMPORT DWORD WINAPI ADVAPI32$GetLengthSid(PSID);

#define CreateToolhelp32Snapshot KERNEL32$CreateToolhelp32Snapshot
#define Process32First KERNEL32$Process32First
#define Process32Next KERNEL32$Process32Next
#define _stricmp MSVCRT$_stricmp
#define LookupPrivilegeValueW ADVAPI32$LookupPrivilegeValueW
#define LookupPrivilegeValueA ADVAPI32$LookupPrivilegeValueA
#define SetTokenInformation ADVAPI32$SetTokenInformation
#define GetLengthSid ADVAPI32$GetLengthSid
