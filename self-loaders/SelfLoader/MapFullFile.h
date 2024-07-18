//---------------------------------------------------------------------------------------------------------------------
// MapFullFile.h
//
// Maps a file into memory and returns image and size
//---------------------------------------------------------------------------------------------------------------------
#pragma once
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>


//---------------------------------------------------------------------------------------------------------------------
// Function Declarations
//---------------------------------------------------------------------------------------------------------------------
/// <summary>
/// Maps the given file into memory using file mappings, and returns a pointer to the view and optionally the size of the view 
/// </summary>
/// <param name="filePath">File to map into memory</param>
/// <param name="dwDesiredAccess">Access desired. Should be combination of GENERIC_READ, GENERIC_WRITE, and GENERIC_EXECUTE</param>
/// <param name="pSize">Optional pointer to a variable to receive the size of the mapped image</param>
/// <returns>Pointer to the mapped view or null on failure. Use UnmapViewOfFile() when done with this pointer</returns>
_Success_(return != NULL) void* MapFullFile(_In_ const char* const filePath, _In_ unsigned dwDesiredAccess, _Out_opt_ size_t *pSize);
