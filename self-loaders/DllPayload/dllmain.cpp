// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#include <Windows.h>
#include <strsafe.h>
#include <stdint.h>

uint32_t MsgBoxCurrentProcess(void *lpParameter) 
{
    (void)lpParameter;
    unsigned pid = GetCurrentProcessId();
    wchar_t pidStr[256];
    wchar_t moduleStr[256];
    GetModuleFileNameW(nullptr, moduleStr, 256);
    StringCbPrintfW(pidStr, sizeof(pidStr), L"Loaded Module running in process: %s (pid: %u)", moduleStr, pid);
    MessageBoxW(0, pidStr, L"Module Successfully Loaded", MB_SYSTEMMODAL);
    return 0;
}


BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    (void)hModule;
    (void)lpReserved;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        /*
            Here, the payload is launched in a new thread for two reasons:
            1) DllMain should avoid calling libraries besides kernel32.dll
            2) Return execution ASAP if our execution method didn't make a new thread.
        */
        {
            HANDLE hThread = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)MsgBoxCurrentProcess, nullptr, 0, nullptr);
            if (hThread != nullptr)
            {
                CloseHandle(hThread);
            }
        }
        break;
    case DLL_PROCESS_DETACH:
        // Nothing to do. If this were a module loaded by an implant, we may need to signal it to shut down and cleanup after it
        break;
    }

    return true;
}

