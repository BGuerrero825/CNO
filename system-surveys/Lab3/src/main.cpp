//-------------------------------------------------------------------------------------------------
// main.cpp
//
// HW & App Fingerprinting
//-------------------------------------------------------------------------------------------------
#include "..\include\adapter_info.h"
#include "..\include\bios_info.h"
#include "..\include\volume_info.h"
#include "..\include\app_info.h"

#include <stdio.h>

int __cdecl main()
{
    if (Hardware::GetAdapterInfo() != ERROR_SUCCESS)
    {
        printf("Failed to get Adapter info.\n");
        return 1;
    }

    if (Hardware::GetBIOSInfo() != ERROR_SUCCESS)
    {
        printf("Failed to get BIOS info.\n");
        return 1;
    }

    if (Hardware::GetVolumeInfo() != ERROR_SUCCESS)
    {
        printf("Failed to get Volume info.\n");
        return 1;
    }

    if (Application::GetAppInfo() != ERROR_SUCCESS)
    {
        printf("Failed to get Application info.\n");
        return 1;
    }

    return 0;
}
