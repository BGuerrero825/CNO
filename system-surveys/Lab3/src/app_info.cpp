//-------------------------------------------------------------------------------------------------
// app_info.cpp
//
// Active Process info
//-------------------------------------------------------------------------------------------------
#include "..\include\app_info.h"

#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <shlobj_core.h>
#include <knownfolders.h>
#include <shlwapi.h>

#pragma comment(lib, "SHLWAPI.lib")

/**
 * Implements Powershell get-StartApps cmdlet.
 * Gets and prints all installed application names and
 * Application User Model IDs (AUMID).
 *
 * @return Error code
 */
uint32_t Application::GetAppInfo()
{
    uint32_t ret_val = 0;
    HRESULT result = 0;
    PIDLIST_ABSOLUTE pAppsFolderIDList = nullptr;
    IShellFolder *pDesktopFolder = nullptr;
    IShellFolder *pAppsFolder = nullptr;
    IEnumIDList *pEnumIDList = nullptr;
    ITEMIDLIST *pItemIDList = nullptr;
    wchar_t* pItemName = nullptr;

    result = CoInitializeEx(nullptr, 0); // Initializes COM library for use in calling thread; needed to call COM functions
    if (result != S_OK)
    {
        printf("COM Initialization failed. Error: 0x%08X\n", result);
        return result;
    }

    // Get the AppsFolder ID
    // https://docs.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetknownfolderidlist
    // https://docs.microsoft.com/en-us/windows/win32/shell/knownfolderid
    if ((result = SHGetKnownFolderIDList(FOLDERID_AppsFolder, 0, nullptr, &pAppsFolderIDList)) != S_OK)
    {
        printf("Failed to get known folder ID list. Error: 0x%X\n", result);
        ret_val = (uint32_t)result;
        goto cleanup;
    }

    //
    // In this lab, you will acquire active process information using the desktop COM interface, instead of
    // the Toolhelp32 API.
    // https://docs.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetdesktopfolder
    //
    // 1) This explains how to get the application IDs to loop over:
    //    https://docs.microsoft.com/en-us/windows/win32/shell/folder-info
    // 2) Refer to the example under Remarks here to get the application names and AUMIDs:
    //    https://docs.microsoft.com/en-us/windows/win32/api/shobjidl_core/ne-shobjidl_core-_shgdnf#remarks
    // HINT: Compare your result to the output of running `get-StartApps` in Powershell
    //
    // START: //////////////////////////// LAB3: Print Application Info (Part 3) ////////////////////////////

    printf("-----| Installed Apps Information |-----\n");
    // Retrieve the object interface for the desktop folder (root of shell namespace)
    if ((result = SHGetDesktopFolder(&pDesktopFolder)) != S_OK)
    {
        printf("Failed to get desktop folder object. Error: 0x%X\n", result);
        ret_val = (uint32_t)result;
        goto cleanup;
    }

    // Use desktop interface to retrieve the object interface for the apps folder from its PIDL
    if ((result = pDesktopFolder->BindToObject(pAppsFolderIDList, NULL, IID_IShellFolder, (void**)&pAppsFolder)) != S_OK)
    {
        printf("Failed to get apps folder object. Error: 0x%X\n", result);
        ret_val = (uint32_t)result;
        goto cleanup;
    }

    // Create an enumeration object within the object folder
    if ((result = pAppsFolder->EnumObjects(NULL, SHCONTF_NONFOLDERS, &pEnumIDList)) != S_OK)
    {
        printf("Failed to create enumeration object in apps folder. Error: 0x%X\n", result);
        ret_val = (uint32_t)result;
        goto cleanup;
    }

    // Use the enumeration object to retrieve the next folder item as an ID list
    printf("%-40s   Full Path\n", "App Name");
    printf("%-40s   ---------\n", "--------");
    while ((result = pEnumIDList->Next(1, &pItemIDList, nullptr)) == S_OK )
    {
        STRRET stringReturn = { 0 };
        stringReturn.uType = STRRET_WSTR;
        // retrieve display name in human readable format
        result = pAppsFolder->GetDisplayNameOf(pItemIDList, SHGDN_NORMAL, &stringReturn);
        if (result != S_OK)
        {
            printf("Failed to get display name of item.\n");
            ret_val = (uint32_t)result;
            goto cleanup;
        }
        pItemName = stringReturn.pOleStr;
        printf("%-40ls   ", pItemName);
        // retrieve display name in full length format
        result = pAppsFolder->GetDisplayNameOf(pItemIDList, SHGDN_FORPARSING, &stringReturn);
        if (result != S_OK)
        {
            printf("Failed to get display name of item.\n");
            ret_val = (uint32_t)result;
            goto cleanup;
        }
        pItemName = stringReturn.pOleStr;
        printf("%ls\n", pItemName);
        //SFGAOF flags = SFGAO_SYSTEM;
        //pAppsFolder->GetAttributesOf(1, (LPCITEMIDLIST *)&pItemIDList, &flags);
        CoTaskMemFree(pItemIDList);
        pItemIDList = nullptr;
    }
    if (result != S_FALSE && result != S_OK)
    {
        printf("Failure while enumerating folder items.\n");
        ret_val = (uint32_t)result;
        goto cleanup;
    }
    pEnumIDList->Release();
    pEnumIDList = nullptr;
    ret_val = S_OK;

    // END:   //////////////////////////// LAB3: Print Application Info (Part 3) ////////////////////////////

cleanup:
    if (pItemName)
    {
        CoTaskMemFree(pItemName);
        pItemName = nullptr;
    }

    if (pItemIDList)
    {
        CoTaskMemFree(pItemIDList);
        pItemIDList = nullptr;
    }

    if (pEnumIDList)
    {
        pEnumIDList->Release();
        pEnumIDList = nullptr;
    }

    if (pAppsFolder)
    {
        pAppsFolder->Release();
        pAppsFolder = nullptr;
    }

    if (pDesktopFolder)
    {
        pDesktopFolder->Release();
        pDesktopFolder = nullptr;
    }

    if (pAppsFolderIDList)
    {
        ILFree(pAppsFolderIDList);
        pAppsFolderIDList = nullptr;
    }

    CoUninitialize();

    return ret_val;
}
