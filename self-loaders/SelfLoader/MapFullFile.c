//---------------------------------------------------------------------------------------------------------------------
// MapFullFile.c
//
// Maps a file into memory and returns image and size
//---------------------------------------------------------------------------------------------------------------------
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "MapFullFile.h"


//---------------------------------------------------------------------------------------------------------------------
// Local Function Declarations
//---------------------------------------------------------------------------------------------------------------------
/// <summary>
/// Validate Desired Access, and prep for CreateFile(). Should be combination of GENERIC_READ, GENERIC_WRITE, and GENERIC_EXECUTE (or GENERIC_ALL)
/// </summary>
/// <param name="desiredAccess">Flags given for desired access</param>
/// <returns>Normalized combination of GENERIC_READ, GENERIC_WRITE, and GENERIC_EXECUTE, 0 on failure</returns>
_Success_(return != 0) static unsigned getCreateFileAccess(_In_ unsigned desiredAccess);


/// <summary>
/// Calculate CreateFileMapping's flProtect value from CreateFile's dwDesiredAccess
/// </summary>
/// <param name="desiredAccess">Desired access given</param>
/// <returns>Appropriate flProtect value</returns>
_Success_(return != 0) static unsigned getCreateFileMappingAccess(_In_ unsigned desiredAccess);


/// <summary>
/// Calculate MapViewOfFile's dwDesiredAccess value from CreateFile's dwDesiredAccess
/// </summary>
/// <param name="desiredAccess">Desired access given</param>
/// <returns>Appropriate dwDesiredAccess value</returns>
_Success_(return != 0) static unsigned getMapViewAccess(_In_ unsigned desiredAccess);


//---------------------------------------------------------------------------------------------------------------------
// Begin Code
//---------------------------------------------------------------------------------------------------------------------
//******************************************************************************
//******************************************************************************
_Success_(return != NULL) void* MapFullFile(_In_ const char* const filePath, _In_ unsigned dwDesiredAccess, _Out_opt_ size_t * pSize)
{
    // initialize size to null
    if (pSize)
    {
        *pSize = 0;
    }

    // validate dwDesiredAccess, and prep for CreateFile()
    unsigned createFileAccess = getCreateFileAccess(dwDesiredAccess);
    // validate dwDesiredAccess (must be combination of GENERIC_READ, GENERIC_WRITE, and GENERIC_EXECUTE (or GENERIC_ALL)
    if (!createFileAccess)
    {
        fprintf(stderr, "Error, invalid dwDesiredAccess passed to MapFullFile() (%08x)\n", dwDesiredAccess);
        return NULL;
    }

    // map full dll into memory for read
    HANDLE hFile = CreateFileA(filePath, createFileAccess, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error, Unable to open payload file '%s' (%u)\n", filePath, GetLastError());
        return NULL;
    }

    HANDLE hMapping = CreateFileMappingA(hFile, NULL, getCreateFileMappingAccess(createFileAccess), 0, 0, NULL);
    // hFile was only needed to create the mapping, so let's close it here, whether file file mapping was successfully created or not, so we don't need to manage it further
    unsigned saveError = GetLastError();    // grab GetLastError() in case CloseHandle() fails and changes it
    CloseHandle(hFile);
    if (hMapping == NULL) {
        fprintf(stderr, "Error, Unable to create file mapping '%s' (%u)\n", filePath, saveError);
        return NULL;
    }

    void *image = MapViewOfFile(hMapping, getMapViewAccess(createFileAccess), 0, 0, 0);
    // hMapping was only needed to map the view, so let's close it here, whether map view was successful or not, so we don't need to manage it further
    saveError = GetLastError();    // grab GetLastError() in case CloseHandle() fails and changes it
    CloseHandle(hMapping);
    if (image == NULL) {
        fprintf(stderr, "Error, Unable to map view of file (%u)\n", saveError);
        return NULL;
    }

    // determine size of image if requested
    if (pSize != NULL)
    {
        MEMORY_BASIC_INFORMATION meminfo;
        if (VirtualQuery(image, &meminfo, sizeof(meminfo)) == 0)
        {
            fprintf(stderr, "Unexpected Error, VirtualQuery() failed (%u)\n", GetLastError());
            UnmapViewOfFile(image);
            return NULL;
        }
        *pSize = meminfo.RegionSize;
    }

    return image;
}


//---------------------------------------------------------------------------------------------------------------------
// Local Utility Functions
//---------------------------------------------------------------------------------------------------------------------
//******************************************************************************
//******************************************************************************
_Success_(return != 0) static unsigned getCreateFileAccess(_In_ unsigned desiredAccess)
{
    // should only include GENERIC_READ, GENERIC_WRITE, GENERIC_EXECUTE, and possibly GENERIC_ALL
    if (desiredAccess & 0x0FFFFFFF)
    {
        return 0;
    }

    // if no access requested, assume read only
    if (!desiredAccess)
    {
        return GENERIC_READ;
    }

    // convert GENERIC_ALL to avoid the ambiguity
    if (desiredAccess & GENERIC_ALL)
    {
        return GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE;
    }

    // else, use access as-is
    return desiredAccess;
}


//******************************************************************************
//******************************************************************************
_Success_(return != 0) static unsigned getCreateFileMappingAccess(_In_ unsigned desiredAccess)
{
    // check for (read)+write+execute
    if ((desiredAccess & GENERIC_WRITE) && (desiredAccess & GENERIC_EXECUTE))
    {
        return PAGE_EXECUTE_READWRITE;
    }

    // check for (read)+write
    if (desiredAccess & GENERIC_WRITE)
    {
        return PAGE_READWRITE;
    }

    // check for (read)+execute
    if (desiredAccess & GENERIC_EXECUTE)
    {
        return PAGE_EXECUTE_READ;
    }

    // else, read-only
    return PAGE_READONLY;
}


//******************************************************************************
//******************************************************************************
_Success_(return != 0) static unsigned getMapViewAccess(_In_ unsigned desiredAccess)
{
    // check for (read)+write+execute
    if ((desiredAccess & GENERIC_WRITE) && (desiredAccess & GENERIC_EXECUTE))
    {
        return FILE_MAP_READ | FILE_MAP_WRITE | FILE_MAP_EXECUTE;
    }

    // check for (read)+write
    if (desiredAccess & GENERIC_WRITE)
    {
        return FILE_MAP_READ | FILE_MAP_WRITE;
    }

    // check for (read)+execute
    if (desiredAccess & GENERIC_EXECUTE)
    {
        return FILE_MAP_READ | FILE_MAP_EXECUTE;
    }

    // else, read-only
    return FILE_MAP_READ;
}
