//-------------------------------------------------------------------------------------------------
// volume_info.cpp
//
// List drive volumes
//-------------------------------------------------------------------------------------------------
#include "..\include\volume_info.h"

#include <windows.h>
#include <stdint.h>
#include <stdio.h>

/**
 * Get and prints drive/volume information.
 *
 * @return Error code
 */
uint32_t Hardware::GetVolumeInfo()
{
    uint32_t ret_val = 0;

    // Initial call to get length in WCHARs required
    uint32_t buff_chars;
    if ((buff_chars = GetLogicalDriveStringsW(0, nullptr)) == 0)
    {
        ret_val = GetLastError();
        wprintf(L"Error: 0x%X\nFailed to get logical drive string length.\n", ret_val);
        return ret_val;
    }
    wchar_t* pBuffer = (wchar_t*)calloc((size_t)buff_chars + 1, sizeof(wchar_t));
    if (pBuffer == nullptr)
    {
        printf("Error allocating memory needed to call GetVolumeInformationW.\n");
        return ERROR_OUTOFMEMORY;
    }

    //
    // 1) Make follow-up call to GetLogicalDriveStringsW() to get drive strings
    // 2) Loop through drive strings to get info about each (requires another function call)
    //      a) Get Display Name, Serial Number, and File System Type
    //
    // START: //////////////////////////// LAB3: Print Volume Info (Part 4) ////////////////////////////

#define TEMP_BUF_SIZE 128

    if ((buff_chars = GetLogicalDriveStringsW(buff_chars, pBuffer)) == 0)
    {
        ret_val = GetLastError();
        wprintf(L"Error: 0x%X\nFailed to get logical drive string length.\n", ret_val);
        return ret_val;
    }

    wchar_t* pDrive = pBuffer;
    wchar_t currDriveName[TEMP_BUF_SIZE] = { 0 };
    while (pDrive < pBuffer + buff_chars)
    {
        wchar_t name[TEMP_BUF_SIZE] = { 0 };
        unsigned long serialNumber = 0;
        wchar_t fileSystem[TEMP_BUF_SIZE] = { 0 };

        printf("-----| Logical Drive Information |-----\n");
        printf("Root: %ls\n", pDrive);
        if (!GetVolumeInformationW(pDrive, name, TEMP_BUF_SIZE, &serialNumber, nullptr, nullptr, fileSystem, TEMP_BUF_SIZE))
        {
            wprintf(L"Error: 0x%X\nFailed to retrieve all drive information.\n", GetLastError());
        }
        printf("Display Name: %ls\n", name);
        printf("Serial Number: %08X\n", serialNumber);
        printf("File System Type: %ls\n", fileSystem);
        printf("\n");

        pDrive += wcslen(pDrive) + 1;
    }

    // END:   //////////////////////////// LAB3: Print Volume Info (Part 4) ////////////////////////////

    // cleanup
    if (pBuffer)
    {
        free(pBuffer);
    }
    return ret_val;
}
