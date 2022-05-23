/*
Author: Berkan ER (B3R-SEC) - 24/05/2022
Check SeBackupPrivilege is Enable/Disable
To-Do: Dump SAM, SYSTEM, SECURITY files

Just practice for write BOF and fun !
*/

#include <windows.h>
#include <tchar.h>
#include "beacon.h"

WINBASEAPI HANDLE WINAPI Kernel32$GetCurrentProcess (VOID);
WINADVAPI WINBOOL WINAPI Advapi32$OpenProcessToken (HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
WINADVAPI WINBOOL WINAPI Advapi32$LookupPrivilegeValueW (LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid);
WINADVAPI WINBOOL WINAPI Advapi32$PrivilegeCheck (HANDLE ClientToken, PPRIVILEGE_SET RequiredPrivileges, LPBOOL pfResult);


BOOL CheckWindowsPrivilege(char* Privilege)
{
    LUID luid;
    PRIVILEGE_SET privs;
    HANDLE hProcess;
    HANDLE hToken;

    hProcess = Kernel32$GetCurrentProcess();

    if (!Advapi32$OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) return FALSE;
    if (!Advapi32$LookupPrivilegeValueW(NULL, Privilege, &luid)) return FALSE;

    privs.PrivilegeCount = 1;
    privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
    privs.Privilege[0].Luid = luid;

    BOOL bResult;
    Advapi32$PrivilegeCheck(hToken, &privs, &bResult);
    
    return bResult;
}

void go(char * args, int len)
{
    if (!CheckWindowsPrivilege(SE_BACKUP_NAME))
    {
        BeaconPrintf(CALLBACK_OUTPUT, (char*)"Do not have SeBackupPrivilege!");
    }
    else 
    {
        BeaconPrintf(CALLBACK_OUTPUT, (char*)"SeBackupPrivilege found!");
    }
}
