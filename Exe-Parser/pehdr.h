//-------------------------------------------------------------------------------------------------
// pehdr.h
//
// Definitions and structures related to parsing a PE64 file
//-------------------------------------------------------------------------------------------------
#pragma once

#include <stdint.h>

// determine offset of a field into a struct
#define FIELD_OFFSET(type, field)    ((uint32_t)(uintptr_t)&(((type *)0)->field))

//
// Excerpts from winnt.h from the Windows UM DDK
//
#define IMAGE_DOS_SIGNATURE                 0x5A4D      // MZ

#define IMAGE_NT_SIGNATURE                  0x00004550  // PE00

#define IMAGE_FILE_MACHINE_AMD64            0x8664  // AMD64 (K8)
#define IMAGE_FILE_MACHINE_I386             0x014c  // Intel 386.


typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    uint16_t   e_magic;                     // Magic number
    uint16_t   e_cblp;                      // Bytes on last page of file
    uint16_t   e_cp;                        // Pages in file
    uint16_t   e_crlc;                      // Relocations
    uint16_t   e_cparhdr;                   // Size of header in paragraphs
    uint16_t   e_minalloc;                  // Minimum extra paragraphs needed
    uint16_t   e_maxalloc;                  // Maximum extra paragraphs needed
    uint16_t   e_ss;                        // Initial (relative) SS value
    uint16_t   e_sp;                        // Initial SP value
    uint16_t   e_csum;                      // Checksum
    uint16_t   e_ip;                        // Initial IP value
    uint16_t   e_cs;                        // Initial (relative) CS value
    uint16_t   e_lfarlc;                    // File address of relocation table
    uint16_t   e_ovno;                      // Overlay number
    uint16_t   e_res[4];                    // Reserved words
    uint16_t   e_oemid;                     // OEM identifier (for e_oeminfo)
    uint16_t   e_oeminfo;                   // OEM information; e_oemid specific
    uint16_t   e_res2[10];                  // Reserved words
    int32_t    e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef const IMAGE_DOS_HEADER* PCIMAGE_DOS_HEADER;


typedef struct _IMAGE_FILE_HEADER {
    uint16_t    Machine;
    uint16_t    NumberOfSections;
    uint32_t    TimeDateStamp;
    uint32_t    PointerToSymbolTable;
    uint32_t    NumberOfSymbols;
    uint16_t    SizeOfOptionalHeader;
    uint16_t    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef const IMAGE_FILE_HEADER* PCIMAGE_FILE_HEADER;


typedef struct _IMAGE_DATA_DIRECTORY {
    uint32_t    VirtualAddress;
    uint32_t    Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef const IMAGE_DATA_DIRECTORY* PCIMAGE_DATA_DIRECTORY;


#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC      0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC      0x20b

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    uint16_t    Magic;
    uint8_t     MajorLinkerVersion;
    uint8_t     MinorLinkerVersion;
    uint32_t    SizeOfCode;
    uint32_t    SizeOfInitializedData;
    uint32_t    SizeOfUninitializedData;
    uint32_t    AddressOfEntryPoint;
    uint32_t    BaseOfCode;
    uint64_t    ImageBase;
    uint32_t    SectionAlignment;
    uint32_t    FileAlignment;
    uint16_t    MajorOperatingSystemVersion;
    uint16_t    MinorOperatingSystemVersion;
    uint16_t    MajorImageVersion;
    uint16_t    MinorImageVersion;
    uint16_t    MajorSubsystemVersion;
    uint16_t    MinorSubsystemVersion;
    uint32_t    Win32VersionValue;
    uint32_t    SizeOfImage;
    uint32_t    SizeOfHeaders;
    uint32_t    CheckSum;
    uint16_t    Subsystem;
    uint16_t    DllCharacteristics;
    uint64_t    SizeOfStackReserve;
    uint64_t    SizeOfStackCommit;
    uint64_t    SizeOfHeapReserve;
    uint64_t    SizeOfHeapCommit;
    uint32_t    LoaderFlags;
    uint32_t    NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef const IMAGE_OPTIONAL_HEADER64* PCIMAGE_OPTIONAL_HEADER64;


typedef struct _IMAGE_NT_HEADERS64 {
    uint32_t    Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef const IMAGE_NT_HEADERS64* PCIMAGE_NT_HEADERS64;

// Directory Entries (indexes into OptionalHeader.DataDirectory[])

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor


#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((uintptr_t)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS64, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

#define IMAGE_SIZEOF_SHORT_NAME              8

typedef struct _IMAGE_SECTION_HEADER {
    uint8_t     Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
            uint32_t    PhysicalAddress;
            uint32_t    VirtualSize;
    } Misc;
    uint32_t    VirtualAddress;
    uint32_t    SizeOfRawData;
    uint32_t    PointerToRawData;
    uint32_t    PointerToRelocations;
    uint32_t    PointerToLinenumbers;
    uint16_t    NumberOfRelocations;
    uint16_t    NumberOfLinenumbers;
    uint32_t    Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef const IMAGE_SECTION_HEADER* PCIMAGE_SECTION_HEADER;

#define IMAGE_SIZEOF_SECTION_HEADER          40
