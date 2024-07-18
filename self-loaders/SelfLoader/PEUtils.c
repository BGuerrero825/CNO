//---------------------------------------------------------------------------------------------------------------------
// PEUtils.c
//
// Utilities for validating and managing PE files (works with bitness of build architecture)
//---------------------------------------------------------------------------------------------------------------------
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "PEUtils.h"
#include "debug.h"

//---------------------------------------------------------------------------------------------------------------------
// Begin Code
//---------------------------------------------------------------------------------------------------------------------

/* Returns true if pointer is a valid DOS image */
bool isValidDosImage(_In_ const void* image)
{
    return (image != NULL) && (IMAGE_DOS_SIGNATURE == ((PCIMAGE_DOS_HEADER)image)->e_magic);
}


/* Returns true if pointer is a valid x86 PE image */
bool isValidNtImage32(_In_ const void* image)
{

    PCIMAGE_NT_HEADERS32 pe64 = (PCIMAGE_NT_HEADERS32)image;

    if (image == NULL)
    {
        return false;
    }
    if (pe64->Signature != IMAGE_NT_SIGNATURE)
    {
        return false;
    }
    if ((pe64->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) || (pe64->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC))
    {
        return false;
    }
    return true;
}


/* Returns true if pointer is a valid x64 PE image */
bool isValidNtImage64(_In_ const void* image)
{

    PCIMAGE_NT_HEADERS64 pe64 = (PCIMAGE_NT_HEADERS64)image;

    if (image == NULL)
    {
        return false;
    }
    if (pe64->Signature != IMAGE_NT_SIGNATURE)
    {
        return false;
    }
    if ((pe64->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) || (pe64->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC))
    {
        return false;
    }
    return true;
}


/* Search AddressOfNameOrdinals to determine whether given function is exported by name */
_Success_(return >= 0) int FindNameIndexForOrdinal(_In_ unsigned ordinal, _In_reads_(numberOfNames) const uint16_t addressOfNameOrdinals[], _In_ unsigned numberOfNames)
{
    for (unsigned idx = 0; idx < numberOfNames; idx++)
    {
        if (addressOfNameOrdinals[idx] == ordinal)
        {
            return idx;
        }
    }
    return -1;
}


/* Return pointer to validated PE header (IMAGE_NT_HEADERS) for a PE file or in-memory image  */
_Success_(return != NULL) PCIMAGE_NT_HEADERS getPEHeader(_In_ const void* image)
{
    // cast the image to a DOS MZ header and validate
    PCIMAGE_DOS_HEADER dosHdr = (PCIMAGE_DOS_HEADER)image;

    // validate DOS header portion
    if (!isValidDosImage(dosHdr))
    {
        fprintf(stderr, "Error, image does not contain a valid DOS MZ header\n");
        return NULL;
    }

    // Use the DOS header's e_lfanew to locate the PE header (new EXE header)
    //      PE Header contains:
    //          Signature (32-bit)      "PE\0\0"
    //          FileHeader (IMAGE_FILE_HEADER) - Describes file layout, size is constant across versions
    //          OptionalHeader (IMAGE_OPTIONAL_HEADER32/64) - Non-optional for PE format, describes PE content and how to load
    //
    PCIMAGE_NT_HEADERS peHdr = (PCIMAGE_NT_HEADERS)ADDR(image, dosHdr->e_lfanew);
    if (!isValidNtImage(peHdr))
    {
        fprintf(stderr, "Error, not a valid NT%u image\n", BITNESS);
        return NULL;
    }
    return peHdr;
}


/* Returns the entry point to a loaded module(DllMain()) */
_Success_(return != NULL) DllMain_t getModuleEntryPoint(_In_ HMODULE hModule)
{
    PCIMAGE_NT_HEADERS peHdr = getPEHeader(hModule);
    if (peHdr == NULL)
    {
        return NULL;
    }

    //
    // Create a pointer to the loaded module's DllMain() function using OptionalHeader.AddressOfEntryPoint
    //
    // START: //////////////////////////////// Part 2 ////////////////////////////////

    DllMain_t moduleEntryPoint = (DllMain_t) ADDR(hModule, peHdr->OptionalHeader.AddressOfEntryPoint);
    return moduleEntryPoint;

    //return NULL;

    // END:   //////////////////////////////// Part 2 ////////////////////////////////
}


/* Call the module entry point for a DLL */
_Success_(return) bool callDllMain(_In_ HMODULE hModule, _In_ unsigned fdwReason)
{
    DllMain_t dllMain = getModuleEntryPoint(hModule);
    if (dllMain == NULL)
    {
        return false;
    }
    const char* reason = (fdwReason == DLL_PROCESS_ATTACH ? "DLL_PROCESS_ATTACH" : (fdwReason == DLL_PROCESS_DETACH ? "DLL_PROCESS_DETACH" : "OTHER"));
    DBGPRINT("Calling DllMain(%s) (%p)\n\n", reason, dllMain);
    return dllMain(hModule, fdwReason, NULL);
}