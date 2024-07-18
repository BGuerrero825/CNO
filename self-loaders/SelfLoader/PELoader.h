//---------------------------------------------------------------------------------------------------------------------
// PELoader.h
//
// Definitions, structures, and function declarations related to loading a PE64 module
//---------------------------------------------------------------------------------------------------------------------
#pragma once
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

#include "PEUtils.h"


//---------------------------------------------------------------------------------------------------------------------
// Function Declarations
//---------------------------------------------------------------------------------------------------------------------

/// <summary>
/// Loads a DLL from disk and prepares it for execution and optionally calls DllMain() with DLL_PROCESS_ATTACH
/// </summary>
/// <remarks>
/// Caution: This code can technically load an EXE, but be aware that since EXE's are assumed to always be loadable at 
///  their preferred address, they often omit the relocations section, and thus cannot be loaded at an arbitrary address. 
/// </remarks>
/// <param name="dllPath">Path to DLL to load</param>
/// <returns>Handle (base address) to loaded module, or null on failure</returns>
_Success_(return != NULL) HMODULE LoadDllFromFile(_In_ const char* const dllPath);


/// <summary>
/// Loads a DLL from an in memory image and prepares it for execution and optionally calls DllMain() with DLL_PROCESS_ATTACH
/// </summary>
/// <param name="fileImage">File PE image to load (as opposed to in-memory loaded image)</param>
/// <param name="imageSize">Size of PE image</param>
/// <returns>Handle (base address) to loaded module, or null on failure</returns>
_Success_(return != NULL) HMODULE InMemoryLoader(_In_ const void* const fileImage, _In_ size_t imageSize);


