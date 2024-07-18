//---------------------------------------------------------------------------------------------------------------------
// SeDebugPrivilege.c
//
// Utility for enabling/disabling SeDebugPrivilege
//---------------------------------------------------------------------------------------------------------------------
#include "SeDebugPrivilege.h"
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>


/* Enables or Disables SeDebugPrivilege */
bool SetDebugPrivilege(bool Enable)
{
    // get a token for the current process for adjusting access rights
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))	// XP+, processthreadsapi.h
    {
        fprintf(stderr, "Error, OpenProcessToken failed (%u)\n", GetLastError());
        return false;
    }

    // lookup the LUID for SeDebugPrivilege
    TOKEN_PRIVILEGES tp = { 0, .PrivilegeCount = 1 };
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid))			// XP+, winbase.h (include Windows.h)
    {
        fprintf(stderr, "Error, LookupPrivilegeValue failed(% u)\n", GetLastError());
        CloseHandle(hToken);
        return false;
    }

    // set the privilege to either enabled or disabled, dependant on the Enable parameter
    tp.Privileges[0].Attributes = Enable ? SE_PRIVILEGE_ENABLED : 0;
    bool result = AdjustTokenPrivileges(hToken, false, &tp, 0, NULL, NULL);	// XP+, securitybaseapi.h (include Windows.h)
    if (!result)
    {
        fprintf(stderr, "Error, AdjustTokenPrivileges failed (%u)\n", GetLastError());
    }
    CloseHandle(hToken);
    return result;
}
