//---------------------------------------------------------------------------------------------------------------------
// PEUtils.h
//
// Utilities for validating and managing PE files (works with bitness of build architecture)
//---------------------------------------------------------------------------------------------------------------------
#pragma once
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>


//---------------------------------------------------------------------------------------------------------------------
// Definitions and Structures
//---------------------------------------------------------------------------------------------------------------------
// convert an RVA to an address
#define ADDR(imageBase, rva)	(void*)((uintptr_t)(imageBase) + (uintptr_t)(rva))


#ifdef _WIN64
#define BITNESS         64
#else
#define BITNESS         32
#endif


// define const pointers to existing structures
typedef const IMAGE_DOS_HEADER* PCIMAGE_DOS_HEADER;
typedef const IMAGE_NT_HEADERS* PCIMAGE_NT_HEADERS;
typedef const IMAGE_NT_HEADERS32* PCIMAGE_NT_HEADERS32;
typedef const IMAGE_NT_HEADERS64* PCIMAGE_NT_HEADERS64;
typedef const IMAGE_SECTION_HEADER* PCIMAGE_SECTION_HEADER;
typedef const IMAGE_EXPORT_DIRECTORY* PCIMAGE_EXPORT_DIRECTORY;
typedef const IMAGE_IMPORT_DESCRIPTOR* PCIMAGE_IMPORT_DESCRIPTOR;


/// <summary>
/// Definition of DllMain() function type
/// </summary>
/// <param name="hinstDLL">Module handle to the DLL containing DllMain()</param>
/// <param name="fdwReason">Reason for calling DllMain() (e.g. DLL_PROCESS_ATTACH)</param>
/// <param name="lpvReserved">Reserved value (Not null on DLL_PROCESS_DETACH for process terminating)</param>
/// <returns>Returns true if action is successful, else false</returns>
typedef bool (WINAPI* DllMain_t) (
                        _In_ void* hinstDLL,
                        _In_ uint32_t fdwReason,
                        _In_opt_ void* lpvReserved
                    );


// Handy macros that Microsoft neglects to provide for processing relocations
#define IMAGE_REL_BASED_TYPE(reloc)     ((uint16_t)(reloc) >> 12)   // top 4 bits of a relocation give the type
#define IMAGE_REL_BASED_OFFSET(reloc)   ((uint16_t)(reloc)&0x0FFF)  // bottom 12 bits give offset from base
#define IMAGE_REL_BASED_COUNT(relocs)   (unsigned)((relocs->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t)) // count of relocations in a given data set
#define IMAGE_REL_BASED_ENTRIES(relocs) (uint16_t*)ADDR(relocs, sizeof(IMAGE_BASE_RELOCATION))


//---------------------------------------------------------------------------------------------------------------------
// PE Header Functions
//---------------------------------------------------------------------------------------------------------------------
/// <summary>
/// Returns true if pointer is a DOS image
/// </summary>
/// <param name="image">Image buffer to validate</param>
bool isValidDosImage(_In_ const void* image);


/// <summary>
/// Returns true if pointer is a valid x86 PE image
/// </summary>
/// <param name="image">Image buffer to validate</param>
bool isValidNtImage32(_In_ const void* image);


/// <summary>
/// Returns true if pointer is a valid x64 PE image
/// </summary>
/// <param name="image">Image buffer to validate</param>
bool isValidNtImage64(_In_ const void* image);

#ifdef _WIN64
#define isValidNtImage(image)   isValidNtImage64(image)
#else
#define isValidNtImage(image)   isValidNtImage32(image)
#endif


/**
 * @brief Search AddressOfNameOrdinals to determine whether given function is exported by name
 *
 * @param[in] ordinal Ordinal value of import (0-based index to AddressOfFunctions)
 * @param[in] addressOfNameOrdinals Array of ordinals for names (AddressOfNameOrdinals)
 * @param[in] numberOfNames Number of items in addressOfNameOrdinals[]
 *
 * @return Returns name index (for AddressOfNames) or -1 if not found
 */
_Success_(return >= 0) int FindNameIndexForOrdinal(_In_ unsigned ordinal, _In_reads_(numberOfNames) const uint16_t addressOfNameOrdinals[], _In_ unsigned numberOfNames);


/// <summary>
/// Return pointer to validated PE header (IMAGE_NT_HEADERS) for a PE file or in-memory image 
/// </summary>
/// <param name="image">File or in-memory PE image</param>
/// <returns>Validated pointer to PE header for image, or null on failure</returns>
_Success_(return != NULL) PCIMAGE_NT_HEADERS getPEHeader(_In_ const void* hModule);


/// <summary>
/// Returns the entry point to a loaded module (DllMain())
/// </summary>
/// <param name="hModule">Module handle (image base)</param>
/// <returns>Function pointer to DllMain(), or null on failure</returns>
_Success_(return != NULL) DllMain_t getModuleEntryPoint(_In_ HMODULE hModule);


/// <summary>
/// Call the module entry point for a DLL
/// </summary>
/// <param name="hModule">Module handle of the DLL containing DllMain()</param>
/// <param name="fdwReason">Reason for calling DllMain() (e.g. DLL_PROCESS_ATTACH)</param>
/// <returns>Returns true if action is successful, else false</returns>
_Success_(return) bool callDllMain(_In_ HMODULE hModule, _In_ unsigned fdwReason);

