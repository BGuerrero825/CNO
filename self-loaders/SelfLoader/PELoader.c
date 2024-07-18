//---------------------------------------------------------------------------------------------------------------------
// PELoader.c
//
// Functionality related to loading a PE module (bitness matches build architecture)
//---------------------------------------------------------------------------------------------------------------------
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "PELoader.h"
#include "PEUtils.h"
#include "MapFullFile.h"
#include "debug.h"


//---------------------------------------------------------------------------------------------------------------------
// Local Function Declarations
//---------------------------------------------------------------------------------------------------------------------

/// <summary>
/// Build the allocated in-memory image from the file image being loaded
/// </summary>
/// <param name="fileImage">Pointer to PE file image being loaded</param>
/// <param name="imageBase">Base pointer of in-memory image being loaded</param>
/// <returns>False if the process fails</returns>
_Success_(return) static bool buildMemoryImage(const void* fileImage, void* imageBase);


/// <summary>
/// Determine whether relocations are necessary, and if so, process them
/// </summary>
/// <param name="imageBase">Base pointer of in-memory image being loaded</param>
/// <returns>False if the process fails</returns>
_Success_(return) static bool performRelocations(void* imageBase);


/// <summary>
/// Process all import tables, if any
/// </summary>
/// <param name="imageBase">Pointer to base of module being loaded</param>
/// <returns>False if import table processing fails</returns>
_Success_(return) static bool linkImports(void* imageBase);


/// <summary>
/// Process imports for a single module being imported from
/// </summary>
/// <param name="imageBase">Pointer to base of module being loaded</param>
/// <param name="hModule">Handle to module being linked</param>
/// <param name="importDesc">Import descriptor to process</param>
/// <returns>False if import descriptor processing fails</returns>
_Success_(return) static bool processImportDescriptor(void* imageBase, HMODULE hModule, PIMAGE_IMPORT_DESCRIPTOR importDesc);


/// <summary>
/// TLS Callbacks - Call all TLS callbacks, if any, for loaded module
/// </summary>
/// <param name="imageBase">Pointer to base of module being loaded</param>
/// <returns>False if import table processing fails</returns>
_Success_(return) static bool callTLSCallbacks(void* imageBase);


//---------------------------------------------------------------------------------------------------------------------
// Begin Code
//---------------------------------------------------------------------------------------------------------------------

/* Loads a DLL from an in memory image and prepares it for execution and optionally calls DllMain() with DLL_PROCESS_ATTACH */
_Success_(return != NULL) HMODULE InMemoryLoader(_In_ const void* const fileImage, _In_ size_t imageSize)
{
    // Caution: This code can technically load an EXE, but be aware that since EXE's are assumed to always be loadable at
    //  their preferred address, they often omit the relocations section, and thus cannot be loaded at an arbitrary address.
    DBGPRINT("\nLoading %zu byte image (0x%05zX)\n\n", imageSize, imageSize);

    // these values are needed for cleanup after goto, so they need to be declared and initialized early
    bool successful = false;
    uint8_t* loadedModule = NULL;       // use uint8_t* so we can easily do math with the pointer

    // validate the file image and get a pointer to the PE headers
    PCIMAGE_NT_HEADERS peHdr = getPEHeader(fileImage);
    if (peHdr == NULL)
    {
        return NULL;
    }

    //
    // Allocate in-memory (loaded) image (loadedModule)
    //      - Read + Write + Execute because we plan to write to it and then execute it
    //      - Image size is given by OptionalHeader.SizeOfImage
    //      - First attempt to allocate memory at the preferred ImageBase (OptionalHeader.ImageBase)
    //      - If that fails, allocate it at an arbitrary location
    //
    // START: //////////////////////////////// Part 3 ////////////////////////////////
    loadedModule = VirtualAlloc((void *) peHdr->OptionalHeader.ImageBase, peHdr->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!loadedModule)
    {
        loadedModule = VirtualAlloc(NULL, peHdr->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!loadedModule)
        {
            fprintf(stderr, "Error, Failed to allocate virtual memory of image size: %llu bytes.\n", imageSize);
            goto cleanup;
        }
    }
    printf("Loaded the program image at address: 0x%p.\n", loadedModule);

    // END:   //////////////////////////////// Part 3 ////////////////////////////////

    //
    // Build executable in-memory image from the file image being loaded
    //
    if (!buildMemoryImage(fileImage, loadedModule))
    {
        goto cleanup;
    }

    //
    // Relocations - If the in-memory image was not allocated at the DLL's preferred address, relocations must be processed
    //
    if (!performRelocations(loadedModule))
    {
        goto cleanup;
    }

    //
    // Import Tables - Process import tables to link external functions needed by this process
    //
    if (!linkImports(loadedModule))
    {
        goto cleanup;
    }

    //
    // TLS Callbacks - Call all TLS callbacks, if any, for loaded module
    //
    if (!callTLSCallbacks(loadedModule))
    {
        goto cleanup;
    }

    // mark process successful and fall through to cleanup
    successful = true;

    cleanup:
    //
    // Perform necessary clean-up, if any
    //
    // START: //////////////////////////////// Part 4 ////////////////////////////////

    if (!successful && loadedModule)
    {
        VirtualFree(loadedModule, 0, MEM_RELEASE);
        loadedModule = NULL;
    }

    // END:   //////////////////////////////// Part 4 ////////////////////////////////
    return (HMODULE)loadedModule;
}


/* Loads a DLL from disk and prepares it for execution and optionally calls DllMain() with DLL_PROCESS_ATTACH */
_Success_(return != NULL) HMODULE LoadDllFromFile(_In_ const char* const dllPath)
{
    size_t imageSize = 0;
    const void* fileImage = MapFullFile(dllPath, GENERIC_READ, &imageSize);
    if (fileImage == NULL)
    {
        return NULL;
    }

    // call in memory loader
    HMODULE loadedModule = InMemoryLoader(fileImage, imageSize);

    if (fileImage != NULL)
    {
        UnmapViewOfFile(fileImage);
    }
    return loadedModule;
}


/* Build the allocated in - memory image from the file image being loaded */
_Success_(return) static bool buildMemoryImage(const void* fileImage, void* imageBase)
{
    PCIMAGE_NT_HEADERS peHdr = getPEHeader(fileImage);
    if (peHdr == NULL)
    {
        return false;
    }

    //
    // Copy full PE headers into the allocated memory, the remainder of the image will need to be mapped into memory
    //
    //      - "Full PE Headers includes:        (e.g. 1024 bytes for x64)
    //          DOS Stub to e_lfanew                (e.g.  256 bytes for x64)
    //          PE Headers:                         (e.g.  264 bytes for x64)
    //              Signature (4)
    //              IMAGE_FILE_HEADER (20)
    //              IMAGE_OPTIONAL_HEADER64 (240)
    //          Section Table                       (e.g.  440 bytes for x64)
    //              FileHeader.NumberOfSections (e.g. 11)
    //              IMAGE_SECTION_HEADER (40)
    //          --- 64 bytes remaining of 1024 ---
    //
    // START: //////////////////////////////// Part 5a ////////////////////////////////

    memcpy(imageBase, fileImage, peHdr->OptionalHeader.SizeOfHeaders);

    // END:   //////////////////////////////// Part 5a ////////////////////////////////

    //
    // Map sections into the in-memory image (Uses section table to expand file image sections to memory image)
    //      - Section table contains FileHeader.NumberOfSections IMAGE_SECTION_HEADER entries
    //      - Each section describes a piece of the in-memory image that needs to be created/initialized, sometimes from a section of the
    //        file image, sometimes just by zeroizing it. Our image is initially zeroized, so we kdon't need to process those sections
    //      - Section Table immediately follows OptionalHeader. IMAGE_FIRST_SECTION macro calculates the location and typecasts it to
    //        IMAGE_SECTION_HEADER*.
    //      - The following code walks through those entries and processes each
    //
    PCIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(peHdr);
    for (unsigned idx = 0; idx < peHdr->FileHeader.NumberOfSections; idx++, SectionHeader++)
    {
        // IMAGE_SECTION_HEADER:
        //      Name - Section name, not null terminated if 8 characters or longer (e.g. ".text")
        //      PointerToRawData/SizeOfRawData - File offset and size of source data
        //              - SizeOfRawData rounded up to FileAlignment (usually 512 bytes)
        //              - PointerToRawData - relative offset from start of file image, is an even multiple of FileAlignment
        //              - Both zero if section contains only uninitilized data
        //      VirtualAddress/Misc.VirtualSize - Location and size of destination in memory image
        //              - VirtualAddress - relative offset from the imageBase of the in-memory image, even multiple of page size (nominally 4K)
        //              - VirtualSize - Actual size of destination.
        //
        //      Cases:
        //          SizeOfRawData == 0: Section is uninitialized (e.g. stack space or uninitialized data segment). Zeroize virtual address/size if
        //                  image allocation is not initially zeroized
        //          VirtualSize > SizeOfRawData: This probably won't happen, but is possible. It is an indication that part of the section has initialized
        //                  data and the rest does not. In this case, use SizeOfRawData for the copy size.
        //          SizeOfRawData > VirtualSize: Because SizeOfRawData is rounded up, it may be larger than the actual size of the section. In this
        //                  case, use VirtualSize instead.
        //          In short, use VirtualSize unless it is greater than SizeOfRawData
        //
        // Map the current section (SectionHeader) into imageBase
        //
        // START: //////////////////////////////// Part 5b ////////////////////////////////

        if (SectionHeader->SizeOfRawData == 0)
        {
            // do nothing since already zeroized
        }
        else if (SectionHeader->Misc.VirtualSize > SectionHeader->SizeOfRawData)
        {
            memcpy(ADDR(imageBase, SectionHeader->VirtualAddress), ADDR(fileImage, SectionHeader->PointerToRawData), (size_t) SectionHeader->SizeOfRawData);
        }
        else   // SizeOfRawData > VirtualSize? use VirtualSize
        {
            memcpy(ADDR(imageBase, SectionHeader->VirtualAddress), ADDR(fileImage, SectionHeader->PointerToRawData), (size_t) SectionHeader->Misc.VirtualSize);
        }

        // END:   //////////////////////////////// Part 5b ////////////////////////////////
    }
    DBGPRINT("Memory image built.\n\n");
    return true;
}


/* Determine whether relocations are necessary, and if so, process them */
_Success_(return) static bool performRelocations(void * imageBase)
{

    //
    // Relocations - the relocation table is an array of variable sized relocation blocks, which consist of an IMAGE_BASE_RELOCATION
    //      header followed by a variable sized list of 16-bit entries that each defines a relocation action.
    //
    //      IMAGE_BASE_RELOCATION:
    //          VirtualAddress - RVA to base of region in moduleImage for this group of relocations
    //          BlockSize - Size of the relocation data for this base address (Used to skip over this block to next in array)
    //          uint16_t (RelocationActions)[] - Encoded relocation actions to perform in this region.
    //              Top 4 bits of a relocation indicates the type of relocation, as given by the IMAGE_REL_BASED_xxx defines from winnt.h
    //              The remaining 12 bits provide the RVA in the module image where this relocation should be performed.
    //                  E.g. 32-bit example:
    //                      Given:
    //                          Preferred Address:  0x00400000
    //                          Actual Address:     0x00500000
    //                          Delta:              0x00100000
    //                          Code Requiring Relocation: (Note: 00401020 is the intended address, this will actually be at 00501020)
    //                              00401020: 8B 0D 34 D4 40 00    mov ecx, dword ptr [0x0040D434]
    //                                              -----------
    //                          Type:               IMAGE_REL_BASED_HIGHLOW (Calculate new complete address <old address> + <delta>)
    //                          Loc (Base+RVA):     0x1022 (thus: imageBase (0x00500000) + 0x1022 = address of underlined address to be changed
    //                          Math:               0x0040D434 + 0x00100000 = 0x0050D434
    //                          After Relocation:
    //                              00501020: 8B 0D 34 D4 50 00    mov ecx, dword ptr [0x0050D434]
    //              As a general rule, x86 relocations are type IMAGE_REL_BASED_HIGHLOW and x64 are of type IMAGE_REL_BASED_DIR64
    //              IMAGE_REL_BASED_ABSOLUTE is like a NOP, and are used to pad the section.
    //
    //      Note: Number of RelocatinActions[] for this base is (BlockSize - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t))
    //
    //      When finished with one block, add BlockSize bytes to the pointer to find the next block, if any.
    //
    //      WARNING: While it is common practice to end when ptr->VirtualAddress is zero, there is no guarantee that there will be a
    //          "null entry" at the end. Instead, the end of the region should be calculated by imageBase + relocationsVirtualAddress + relocSize, and
    //          then for each entry, the next pointer should be calculated, and that pointer should be checked to confirm that:
    //              1. ptr + sizeof(IMAGE_BASE_RELOCATION) <= endOfRelocations
    //              2. ptr->BlockSize != 0
    //              3. ptr + sizeof(IMAGE_BASE_RELOCATION) + ptr->BlockSize <= endOfRelocations
    //
    //      Processing a relocation:
    //          Given: imageBase, relocData.VirtualAddress, and a 16-bit entry from RelocationActions[] called 'reloc':
    //              regionBase = imageBase + relocData.VirtualAddress (true for entire region)
    //              IMAGE_REL_BASED_TYPE(reloc) = type of relocation
    //                  IMAGE_REL_BASED_HIGHLOW - normal x86, add delta to 32-bit value at regionBase + IMAGE_REL_BASED_OFFSET(reloc)
    //                  IMAGE_REL_BASED_DIR64   - normal x64, add delta to 32-bit value at regionBase + IMAGE_REL_BASED_OFFSET(reloc)
    //
    //

    PCIMAGE_NT_HEADERS peHdr = getPEHeader(imageBase);
    if (peHdr == NULL)
    {
        // getPEHeader() will have reported what failed
        return false;
    }

    //
    // Calculate change in location from preferred load address. If locationDelta is 0, no relocations are necessary
    //      - imageBase is the address we are loading at
    //      - OptionalHeader.ImageBase is the preferred address the module was built to be loaded at
    //
    // Note: This is one of the few times you will see intptr_t used. The calculated value needs to be a signed integer
    //      that is the size of a pointer so it can handle large differences. size_t could also be used, but this is not
    //      a size/magnitude value, so intptr_t is more appropriate.
    //
    // Note: If the image was loaded at a higher address than the preferred address, locationDelta should be positive so
    //      that fix-ups increase addresses. If lower, locationDelta should be negative.
    //
    // START: //////////////////////////////// Part 6a ////////////////////////////////

    intptr_t locationDelta = (intptr_t) imageBase - (intptr_t) (peHdr->OptionalHeader.ImageBase) ;
    if (locationDelta == 0)     // if there is no delta, no need for relocations
    {
        return true;
    }

    // END:   //////////////////////////////// Part 6a ////////////////////////////////

    //
    // Prepare for relocations:
    //   1. Save the relocations section virtual address (RVA) and size from the DataDirectory (index = IMAGE_DIRECTORY_ENTRY_BASERELOC)
    //   2. Create a pointer to the first relocation table entry (relocEntry)
    //   3. Calculate the address of the end of the relocations section
    //
    // Tip: If the section size is zero, there are no relocations to perform
    //
    // START: //////////////////////////////// Part 6b ////////////////////////////////

    // grab the RVA and Size of the area in the loaded image where Relocations information is located
    //  Note: It is not necessary to store these values in variables here, the DataDirectory entries could be used directly in the pointer
    //      calculations below, but I am having you do it in two steps for clarity and to simplify the pointer calculation lines.
    unsigned relocationsVirtualAddress = peHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    unsigned relocationsSize = peHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    if (relocationsSize == 0)
    {
        DBGPRINT("There are no relocations to perform for this image.\n\n");
        return true;
    }

    // Using the two values from above, calculate pointers to first relocations table and to end of all relocation tables (end of .reloc section)
    IMAGE_BASE_RELOCATION* relocEntry = ADDR(imageBase, relocationsVirtualAddress);
    void* endRelocations = ADDR(imageBase, relocationsVirtualAddress + relocationsSize);

    // END:   //////////////////////////////// Part 6b ////////////////////////////////


    // While the next relocation block is within the relocations data section and its size is non-zero
    //
    //      WARNING: A common mistake is to only test that current VirtualAddress is not zero. The specs do not place a
    //              null entry at the end of this list
    //
    unsigned table = 0;
    while (ADDR(relocEntry,sizeof(IMAGE_BASE_RELOCATION)) < endRelocations     // relocEntry->SizeOfBlock is still inside .reloc section
        && relocEntry->SizeOfBlock != 0                                        // size of this block is non-zero
        && ADDR(relocEntry, relocEntry->SizeOfBlock) <= endRelocations)// should not be necessary, but make sure full block is inside .reloc section
    {
        // Relocations Data Block:
        //      IMAGE_BASE_RELOCATION:
        //          VirtualAddress - RVA to base of region in moduleImage for this group of relocations
        //          SizeOfBlock - Size of the relocation data for this base address (Used to skip over this block to next in array)
        //      uint16_t (RelocationActions)[] - Encoded relocation actions to perform in this region.
        //
        // 1. Calculate the base address of the region for this relocation entry (regionBase)
        // 2. Determine the number fixups to perform for this entry (Hint: Use the macro I provided in PEUtils.h)
        // 3. Get a pointer to the list of fixups for this entry (Hint: Use the macro I provided in PEUtils.h)
        //
        // START: //////////////////////////////// Part 6c ////////////////////////////////

        void* regionBase = ADDR(imageBase, relocEntry->VirtualAddress);
        unsigned fixupCount = IMAGE_REL_BASED_COUNT(relocEntry);
        uint16_t* fixups = IMAGE_REL_BASED_ENTRIES(relocEntry);

        // END:   //////////////////////////////// Part 6c ////////////////////////////////

        for (unsigned idx = 0; idx < fixupCount; idx++)
        {
            uint16_t entry = fixups[idx];
            switch (IMAGE_REL_BASED_TYPE(entry))
            {
            // The only relocation types we should see are the standard type for the architecture and the placeholder for padding
#ifdef _WIN64
            case IMAGE_REL_BASED_DIR64:         // standard 64-bit relocation (add locationDelta to the address indicated)
#else
            case IMAGE_REL_BASED_HIGHLOW:       // standard 32-bit relocation (add locationDelta to the address indicated)
#endif
                {
                    //
                    // Perform the fix-up by creating a pointer to the the address to patch (uintptr_t) and adding locationDelta
                    //      to the value at that address.
                    //
                    // Note: These are actually function or variable addresses, but we treat them as pointer sized unsigned
                    //      integers (uintptr_t) to avoid the possible complexities of  pointer math (e.g. void* sometimes can't
                    //      be incremented because the size of a 'void' is unknown, and pointers to anything besides char/uint8_t
                    //      do not increment by 1 byte at a time.)
                    //
                    // START: //////////////////////////////// Part 6d ////////////////////////////////

                uintptr_t * entryAddr = ADDR(regionBase, IMAGE_REL_BASED_OFFSET(entry));
                *entryAddr += locationDelta;

                    // END:   //////////////////////////////// Part 6d ////////////////////////////////
                }
                break;

            case IMAGE_REL_BASED_ABSOLUTE:      // these are nop entries used to pad list
                break;

            default:
                fprintf(stderr, "Error, unexpected relocation type table %u, entry %u: %u %u\n", table, idx, IMAGE_REL_BASED_TYPE(entry), IMAGE_REL_BASED_OFFSET(entry));
                break;
            }
        }
        table++;

        //
        // Set relocEntry to point to the next entry
        //
        // START: //////////////////////////////// Part 6e ////////////////////////////////

        relocEntry = (uintptr_t) ((uint8_t *) relocEntry +  relocEntry->SizeOfBlock); // is there any way to do this with the "+=" notation? thats why I did the weird lvalue cast initially

        // END:   //////////////////////////////// Part 6e ////////////////////////////////

    }
    DBGPRINT("Relocations complete\n\n");
    return true;
}


/* Process all import tables, if any */
_Success_(return) static bool linkImports(void* imageBase)
{
    //
    // Imports: The Imports Directory is an array of IMAGE_IMPORT_DESCRIPTOR structures, with a null (zeroized) entry at the end, followed
    //      by import tables that are defined by the Import Descriptors.
    //
    //      IMAGE_IMPORT_DESCRIPTOR:
    //          OriginalFirstThunk;             - RVA of the Import Lookup Table (ILT) (aka Import Name Table (INT))
    //          ForwarderChain;                 - Used in DLL forwarding (e.g. kernel32.dll symbol references ntdll.dll) (??)
    //          Name;                           - RVA of ASCII string giving module name
    //          FirstThunk;                     - RVA of Import Address Table (IAT)
    //
    //      For each Import Descriptor:
    //          1. Make pointer to name string (e.g. const char* moduleName = (char*)ADDR(imageBase, importDesc->Name);)
    //          2. Call LoadLibraryA() to load the current module being imported
    //          3. Calculate IAT pointer (e.g. uintptr_t *IAT = (uintptr_t*)(imageBase + importDesc->FirstThunk);)
    //          4. If OriginalFirstThunk is not zero, calculate pointer to ILT (e.g. uintptr_t *ILT = (uintptr_t*)ADDR(imageBase, importDesc->OriginalFirstThunk);),
    //             else set ILT to IAT.
    //          5. While *ILT is not zero, look up imported symbol using GetProcAddress() either by ordinal or name, according to the ILT entry, and set *IAT to
    //             that address.
    //                  - Use IMAGE_SNAP_BY_ORDINAL(*ILT) to determine if lookup is by ordinal
    //                  - Ordinal = *ILT & 0xFFFF, else *ILT is RVA to IMAGE_IMPORT_BY_NAME which contains the symbol name to import
    //          6. Increment importDesc to point to next entry, finish if importDesc->Name is zero
    //
    //

    PCIMAGE_NT_HEADERS peHdr = getPEHeader(imageBase);
    if (peHdr == NULL)
    {
        // getPEHeader() will have reported what failed
        return false;
    }

    // grab the RVA and Size of the area in the loaded image where Imports information is located
    unsigned importsVirtualAddress = peHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    unsigned importsSize = peHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    // if there are no imports for this module, we're done
    if (!importsSize)
    {
        DBGPRINT("Module has no imports (Size=%u, VA=%08X)\n\n", importsSize, importsVirtualAddress);
        return true;
    }

    // calculate pointer to first import descriptor in array
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)ADDR(imageBase, importsVirtualAddress);
    unsigned descriptors = 0;

    DBGPRINT("Processing Imports (%p - %p)\n", importDesc, ADDR(importDesc, importsSize));

    // array is terminated by a null entry
    while (importDesc->Name)
    {
        //
        // Create a pointer to the module name for this import descriptor, and load that DLL
        //
        // START: //////////////////////////////// Part 7a ////////////////////////////////
        const char* moduleName = ADDR(imageBase, importDesc->Name);
        HMODULE hModule = LoadLibraryA(moduleName);
        if (!hModule)
        {
            fprintf(stderr, "Failed to load library \"%s\". Error: %lu\n", moduleName, GetLastError());
            return false;
        }

        // END:   //////////////////////////////// Part 7a ////////////////////////////////

        // processing imports for a descriptor is too complex to have in a nested loop, so do it from a
        //  separate function
        if (!processImportDescriptor(imageBase, hModule, importDesc))
        {
            FreeLibrary(hModule);
            return false;
        }
        importDesc++;
        descriptors++;
    }
    DBGPRINT("Imports complete (%u modules linked)\n\n", descriptors);
    return true;
}


/* Process imports for a single module being imported from */
_Success_(return) static bool processImportDescriptor(void* imageBase, HMODULE hModule, PIMAGE_IMPORT_DESCRIPTOR importDesc)
{
    // Import Lists are of type: IMAGE_THUNK_DATA32/IMAGE_THUNK_DATA64 (Union of ILT info and IAT). Nothing is gained for
    //      us here by using those complex structures, so we will just treat them as uintptr_t values, and use macros
    //      to work with them

    //
    // Setup pointers to the Import Lookup Table (ILT) and Import Address Table (IAT) from the import descriptor's
    //      OriginalFirstThunk and FirstThunk members, respectively. Remember that if OriginalFirstThunk is 0, that
    //      ILT should use IAT.
    //
    // START: //////////////////////////////// Part 7b ////////////////////////////////

    uintptr_t* ILT = ADDR(imageBase, importDesc->OriginalFirstThunk);
    uintptr_t* IAT = ADDR(imageBase, importDesc->FirstThunk);
    if (importDesc->OriginalFirstThunk == 0)
    {
        ILT = IAT;
    }

    // END:   //////////////////////////////// Part 7b ////////////////////////////////

    // Step through the ILT list until the terminating null entry is found
    while (*ILT)
    {
        uintptr_t symbolAddress = 0;

        // Use the macro provided in winnt.h to determine whether this import is by ordinal (else, by name)
        if (IMAGE_SNAP_BY_ORDINAL(*ILT))
        {
            //
            // Use GetProcAddress(hMod, (char*)ordinal) to look-up the symbol address for this entry.
            //
            // Hint: Look up the IMAGE_ORDINAL() macro. Note that it resolves to a 32-bit or 64-bit version to match
            //      the build architecture.
            //
            // Question: Is GetProcAddress() guaranteed to work? If not, how should this code react to an import failure?
            //
            // START: //////////////////////////////// Part 7c ////////////////////////////////

            symbolAddress = (uintptr_t) GetProcAddress(hModule, (char *) IMAGE_ORDINAL(*ILT));
            if (!symbolAddress)
            {
                fprintf(stderr, "Failed to load procedure address by ordinal for \"%zu\". Error: %lu\n", IMAGE_ORDINAL(*ILT), GetLastError());
                return false;
            }

            // END:   //////////////////////////////// Part 7c ////////////////////////////////
        }
        // else import by name
        else
        {
            //
            // *ILT is an RVA to a IMAGE_IMPORT_BY_NAME structure that contains an actual pointer (not another RVA) to
            //      the null terminated import symbol name string. Create a pointer to that structure and use it to
            //      call GetProcAddress(hMod, <symbol-name>) to look-up the symbol address for this entry
            //
            // Question: Is GetProcAddress() guaranteed to work? If not, how should this code react to an import failure?
            //
            // START: //////////////////////////////// Part 7d ////////////////////////////////

            char * symbolName = ((PIMAGE_IMPORT_BY_NAME) ADDR(imageBase, (*ILT)))->Name;
            symbolAddress = (uintptr_t) GetProcAddress(hModule, symbolName);
            if (!symbolAddress)
            {
                fprintf(stderr, "Failed to load procedure address by name for \"%s\". Error: %lu\n", (char *) *ILT, GetLastError());
                return false;
            }

            // END:   //////////////////////////////// Part 7d ////////////////////////////////
        }

        //
        // Overwrite the entry at the current IAT pointer with the symbol address from above and
        // then increment both table pointers to go to the next import entry for this descriptor.
        //
        // START: //////////////////////////////// Part 7e ////////////////////////////////

        *IAT = symbolAddress;

        ILT++;
        IAT++;

        // END:   //////////////////////////////// Part 7e ////////////////////////////////
    }
    return true;
}


/* TLS Callbacks - Call all TLS callbacks, if any, for loaded module */
_Success_(return) static bool callTLSCallbacks(void* imageBase)
{
    //
    // TLS Callbacks: The TLS callback section contains a IMAGE_TLS_DIRECTORY entry that holds a list of TLS callback
    //      functions that should be called by the loader to allow TLS resources to be created.
    //
    //      IMAGE_TLS_DIRECTORY contains, among other things, AddressOfCallBacks, which is a pointer to an array of full
    //          addresses to callback functions, which are called similar to DllMain().
    //
    //      CAUTION: Both AddressOfCallbacks and the callbacks in the lists are actual memory addresses, not RVAs
    //

    PCIMAGE_NT_HEADERS peHdr = getPEHeader(imageBase);
    if (peHdr == NULL)
    {
        // getPEHeader() will have reported what failed
        return false;
    }

    // grab the RVA and Size of the area in the loaded image where TLS Callbacks information is located
    unsigned tlsVirtualAddress = peHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    unsigned tlsSize = peHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
    // if the section size is zero, we're done
    if (!tlsSize)
    {
        DBGPRINT("Module has no TLS Callbacks (Size=%u, VA=%08X)\n\n", tlsSize, tlsVirtualAddress);
        return true;
    }

    // calculate pointer to first import descriptor in array
    PIMAGE_TLS_DIRECTORY tlsDirectory = (PIMAGE_TLS_DIRECTORY)ADDR(imageBase, tlsVirtualAddress);

    DBGPRINT("Processing TLS Callbacks (%p - %p)\n", tlsDirectory, ADDR(tlsDirectory, tlsSize));

    if (!tlsDirectory->AddressOfCallBacks)
    {
        DBGPRINT("TLS Callback list is empty\n\n");
        return true;
    }
    // this is a pointer to a function pointer
    PIMAGE_TLS_CALLBACK* callbackList = (PIMAGE_TLS_CALLBACK*)tlsDirectory->AddressOfCallBacks;

    //
    // While there are still callbacks in the list, call the current callback with imageBase, DLL_PROCESS_ATTACH, and
    //      NULL. The list is terminated with a null pointer entry.
    //
    // Caution: These are pointers to function pointers. 'callbackList' itself is not a function pointer and should not be
    //      called.
    //
    // START: //////////////////////////////// Part 8 ////////////////////////////////

    while (callbackList)
    {
        (*callbackList)(imageBase, DLL_PROCESS_ATTACH, NULL);
        callbackList++;
    }

    // END:   //////////////////////////////// Part 8 ////////////////////////////////

    return true;
}