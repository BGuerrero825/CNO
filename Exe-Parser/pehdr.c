/**
 * @file pehdr.c
 * @author Brian Guerrero
 * @brief Parses fields from a 64-bit PE header and prints them into a Python readable list format
 * @date 2024-05-09
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "pehdr.h"


//*********************************************************************************
// DECLARATIONS
//*********************************************************************************

/**
 * @brief Parses the second command line argument as a filepath and opens the file to buffer in process memory
 * @remark Use free() to release buffer when no longer needed
 * 
 * @param[out] fileName Name and path of file read
 * @param[out] fileSize Size of the file read
 * @return Returns allocated buffer containing file (free() when no longer needed) | 0 = ERROR
 */
static uint8_t *loadArgFile(char **fileName, size_t *fileSize, int argc, char *argv[]);

/**
 * @brief Get length of an open file
 * @remark Limited to 2GiB
 *
 * @param[in] fp Open file pointer
 * @return Returns the length of the file, on error returns 0
 */
static uint32_t FileSize(FILE* fp);

/**
 * @brief Prints the file name, file size, and column headers into python comments, then starts a python list
 * 
 * @param fileName 
 * @param fileSize 
 */
static void printPrologue(char * fileName, size_t fileSize);

/**
 * @brief Print the DOS header and its relevant fields as python tuples
 * 
 * @param DOSHeader 
 */
static void printDOSHeader(PCIMAGE_DOS_HEADER DOSHeader);

/**
 * @brief Print the NT headers and NT signature as python tuples
 * 
 * @param NTHeaders 
 */
static void printNTHeaders(PCIMAGE_NT_HEADERS64 NTHeaders);

/**
 * @brief Print the File header and its relevant fields as python tuples
 * 
 * @param NTHeaders 
 */
static void printFileHeader(PCIMAGE_NT_HEADERS64 NTHeaders);

/**
 * @brief Print the Optional header and its relevant fields as python tuples
 * 
 * @param NTHeaders 
 */
static void printOptionalHeader(PCIMAGE_NT_HEADERS64 NTHeaders);

/**
 * @brief Print the Data directories and their relevant fields as python tuples
 * 
 * @param NTHeaders
 */
static void printDataDirectories(PCIMAGE_NT_HEADERS64 NTHeaders);

/**
 * @brief Print the Section headers and their relevant fields as python tuples
 * 
 * @param NTHeaders
 */
static void printSectionHeaders(PCIMAGE_NT_HEADERS64 NTHeaders);


//*********************************************************************************
// DEFINITIONS
//********************************************************************************

// global 
static uint8_t *imageBase = 0;

int main (int argc, char * argv[]){
    
    // open file from command line argument 
    char *fileName;
    size_t fileSize = 0;
    uint8_t *buffer = loadArgFile(&fileName, &fileSize, argc, argv);
    if (!buffer){
        goto cleanup;
    }

    // verify DOS signature at start of file
    PCIMAGE_DOS_HEADER DOSHeader = (PCIMAGE_DOS_HEADER) buffer;
    if(DOSHeader->e_magic != IMAGE_DOS_SIGNATURE){
        fprintf(stderr, "Aborting, expected DOS Signature: %04X. Actual: %04X.\n", IMAGE_DOS_SIGNATURE, DOSHeader->e_magic);
        goto cleanup;
    }
    // set imageBase based on the the start of the DOS Header
    imageBase = (uint8_t *) DOSHeader;
    

    // verify NT signature at start of NT/COFF header
    PCIMAGE_NT_HEADERS64 NTHeaders = (PCIMAGE_NT_HEADERS64) ((uint8_t *) DOSHeader + DOSHeader->e_lfanew);
    if(NTHeaders->Signature != IMAGE_NT_SIGNATURE){
        fprintf(stderr, "Aborting, expected NT Signature: %08X. Actual: %08X.\n", IMAGE_NT_SIGNATURE, NTHeaders->Signature);
        goto cleanup;
    }

    // verify machine type is x86-64-bit
    if(NTHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64){
        fprintf(stderr, "Aborting, expected Image Header Machine: %04X. Actual: %04X.\n", IMAGE_FILE_MACHINE_AMD64, NTHeaders->FileHeader.Machine);
        goto cleanup;
    }

    printPrologue(fileName, fileSize);

    printDOSHeader(DOSHeader);

    printNTHeaders(NTHeaders);

    printFileHeader(NTHeaders);

    printOptionalHeader(NTHeaders);

    printDataDirectories(NTHeaders);

    printSectionHeaders(NTHeaders);

    printf("]\n");

    return 0;

    cleanup:
    if(buffer){
        free(buffer);
    }
    return 1;
}


static void printPrologue(char *fileName, size_t fileSize) {
    printf("# \'%s\' info\n", fileName);
    printf("# File Size: %llu bytes.\n", fileSize);
    printf("#\n");
    printf("#                                   offset      size        value\n");
    printf("[\n");
}


static void printDOSHeader(PCIMAGE_DOS_HEADER DOSHeader) {
    printf("('IMAGE_DOS_HEADER',                0x%05X,    %u),\n", 0, DOSHeader->e_lfanew);
    printf("    ('e_magic',                     0x%05X,    %zu,          0x%04X),\n", FIELD_OFFSET(IMAGE_DOS_HEADER, e_magic), sizeof(DOSHeader->e_magic), DOSHeader->e_magic);
    printf("    ('e_lfanew',                    0x%05X,    %zu,          0x%08X),\n", FIELD_OFFSET(IMAGE_DOS_HEADER, e_lfanew), sizeof(DOSHeader->e_lfanew), DOSHeader->e_lfanew);
    printf("\n");
}


static void printNTHeaders(PCIMAGE_NT_HEADERS64 NTHeaders) {
    size_t offset = (uint8_t *) NTHeaders - imageBase; 
    printf("('IMAGE_NT_HEADERS',                0x%05llX,    %llu),\n", offset, sizeof(IMAGE_NT_HEADERS64));
    printf("    ('Signature',                   0x%05llX,    %llu,          0x%08X),\n", offset + FIELD_OFFSET(IMAGE_NT_HEADERS64, Signature), sizeof(NTHeaders->Signature), NTHeaders->Signature);
    printf("    ('FileHeader',                  0x%05llX,    %llu),\n", offset + FIELD_OFFSET(IMAGE_NT_HEADERS64, FileHeader), sizeof(NTHeaders->FileHeader));
    printf("    ('OptionalHeader',              0x%05llX,    %llu),\n", offset + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader), sizeof(NTHeaders->OptionalHeader));
    printf("\n");
}


static void printFileHeader(PCIMAGE_NT_HEADERS64 NTHeaders) {
    PCIMAGE_FILE_HEADER fileHeader = &(NTHeaders->FileHeader);
    size_t offset = (uint8_t *) fileHeader - imageBase; 
    printf("('IMAGE_FILE_HEADER',               0x%05llX,    %llu),\n", offset, sizeof(IMAGE_FILE_HEADER));
    printf("    ('Machine',                     0x%05llX,    %llu,          0x%04X),\n", offset + FIELD_OFFSET(IMAGE_FILE_HEADER, Machine), sizeof(fileHeader->Machine), fileHeader->Machine);
    printf("    ('NumberOfSections',            0x%05llX,    %llu,          %d),\n", offset + FIELD_OFFSET(IMAGE_FILE_HEADER, NumberOfSections), sizeof(fileHeader->NumberOfSections), fileHeader->NumberOfSections);
    printf("    ('SizeOfOptionalHeader',        0x%05llX,    %llu,          %d),\n", offset + FIELD_OFFSET(IMAGE_FILE_HEADER, SizeOfOptionalHeader), sizeof(fileHeader->SizeOfOptionalHeader), fileHeader->SizeOfOptionalHeader);
    printf("\n"); 
}


static void printOptionalHeader(PCIMAGE_NT_HEADERS64 NTHeaders) {
    PCIMAGE_OPTIONAL_HEADER64 optionalHeader = &(NTHeaders->OptionalHeader);
    size_t offset = (uint8_t *) optionalHeader - imageBase;
    printf("('IMAGE_OPTIONAL_HEADER',           0x%05llX,    %llu),\n", offset, sizeof(IMAGE_OPTIONAL_HEADER64));
    printf("    ('Magic',                       0x%05llX,    %llu,          0x%04X),\n", offset + FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, Magic), sizeof(optionalHeader->Magic), optionalHeader->Magic);
    //printf("    ('MajorLinkerVersion',          0x%05llX,    %llu,      0x%04X),\n", offset + FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, MajorLinkerVersion), sizeof(optionalHeader->MajorLinkerVersion), optionalHeader->MajorLinkerVersion);
    //printf("    ('MinorLinkerVersion',          0x%05llX,    %llu,      0x%04X),\n", offset + FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, MinorLinkerVersion), sizeof(optionalHeader->MinorLinkerVersion), optionalHeader->MinorLinkerVersion);
    printf("    ('SizeOfCode',                  0x%05llX,    %llu,          %u),\n", offset + FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, SizeOfCode), sizeof(optionalHeader->SizeOfCode), optionalHeader->SizeOfCode);
    printf("    ('SizeOfInitializedData',       0x%05llX,    %llu,          %u),\n", offset + FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, SizeOfInitializedData), sizeof(optionalHeader->SizeOfInitializedData), optionalHeader->SizeOfInitializedData);
    printf("    ('SizeOfUninitializedData',     0x%05llX,    %llu,          %u),\n", offset + FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, SizeOfUninitializedData), sizeof(optionalHeader->SizeOfUninitializedData), optionalHeader->SizeOfUninitializedData);
    printf("    ('AddressOfEntryPoint',         0x%05llX,    %llu,          0x%08X),\n", offset + FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, AddressOfEntryPoint), sizeof(optionalHeader->AddressOfEntryPoint), optionalHeader->AddressOfEntryPoint);
    printf("    ('ImageBase',                   0x%05llX,    %llu,          0x%016llX),\n", offset + FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, ImageBase), sizeof(optionalHeader->ImageBase), optionalHeader->ImageBase);
    printf("    ('SectionAlignment',            0x%05llX,    %llu,          %u),\n", offset + FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, SectionAlignment), sizeof(optionalHeader->SectionAlignment), optionalHeader->SectionAlignment);
    printf("    ('FileAlignment',               0x%05llX,    %llu,          %u),\n", offset + FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, FileAlignment), sizeof(optionalHeader->FileAlignment), optionalHeader->FileAlignment);
    printf("    ('MinorOperatingSystemVersion', 0x%05llX,    %llu,          %u),\n", offset + FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, MinorOperatingSystemVersion), sizeof(optionalHeader->MinorOperatingSystemVersion), optionalHeader->MinorOperatingSystemVersion);
    printf("    ('MajorOperatingSystemVersion', 0x%05llX,    %llu,          %u),\n", offset + FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, MajorOperatingSystemVersion), sizeof(optionalHeader->MajorOperatingSystemVersion), optionalHeader->MajorOperatingSystemVersion);
    printf("    ('MajorImageVersion',           0x%05llX,    %llu,          %u),\n", offset + FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, MajorImageVersion), sizeof(optionalHeader->MajorImageVersion), optionalHeader->MajorImageVersion);
    printf("    ('MinorImageVersion',           0x%05llX,    %llu,          %u),\n", offset + FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, MinorImageVersion), sizeof(optionalHeader->MinorImageVersion), optionalHeader->MinorImageVersion);
    printf("    ('MajorSubsystemVersion',       0x%05llX,    %llu,          %u),\n", offset + FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, MajorSubsystemVersion), sizeof(optionalHeader->MajorSubsystemVersion), optionalHeader->MajorSubsystemVersion);
    printf("    ('MinorSubsystemVersion',       0x%05llX,    %llu,          %u),\n", offset + FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, MinorSubsystemVersion), sizeof(optionalHeader->MinorSubsystemVersion), optionalHeader->MinorSubsystemVersion);
    printf("    ('Win32VersionValue',           0x%05llX,    %llu,          %u),\n", offset + FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, Win32VersionValue), sizeof(optionalHeader->Win32VersionValue), optionalHeader->Win32VersionValue);
    printf("    ('SizeOfImage',                 0x%05llX,    %llu,          0x%08X),\n", offset + FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, SizeOfImage), sizeof(optionalHeader->SizeOfImage), optionalHeader->SizeOfImage);
    printf("    ('SizeOfHeaders',               0x%05llX,    %llu,          0x%08X),\n", offset + FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, SizeOfHeaders), sizeof(optionalHeader->SizeOfHeaders), optionalHeader->SizeOfHeaders);
    printf("    ('CheckSum',                    0x%05llX,    %llu,          0x%08X),\n", offset + FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, CheckSum), sizeof(optionalHeader->CheckSum), optionalHeader->CheckSum);
    printf("    ('Subsystem',                   0x%05llX,    %llu,          %u),\n", offset + FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, Subsystem), sizeof(optionalHeader->Subsystem), optionalHeader->Subsystem);
    printf("    ('SizeOfStackReserve',          0x%05llX,    %llu,          0x%08llX),\n", offset + FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, SizeOfStackReserve), sizeof(optionalHeader->SizeOfStackReserve), optionalHeader->SizeOfStackReserve);
    printf("    ('SizeOfStackCommit',           0x%05llX,    %llu,          0x%08llX),\n", offset + FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, SizeOfStackCommit), sizeof(optionalHeader->SizeOfStackCommit), optionalHeader->SizeOfStackCommit);
    printf("    ('SizeOfHeapReserve',           0x%05llX,    %llu,          0x%08llX),\n", offset + FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, SizeOfHeapReserve), sizeof(optionalHeader->SizeOfHeapReserve), optionalHeader->SizeOfHeapReserve);
    printf("    ('SizeOfHeapCommit',            0x%05llX,    %llu,          0x%08llX),\n", offset + FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, SizeOfHeapCommit), sizeof(optionalHeader->SizeOfHeapCommit), optionalHeader->SizeOfHeapCommit);
    printf("    ('NumberOfRvaAndSizes',         0x%05llX,    %llu,          %u),\n", offset + FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, NumberOfRvaAndSizes), sizeof(optionalHeader->NumberOfRvaAndSizes), optionalHeader->NumberOfRvaAndSizes);
}


static void printDataDirectories(PCIMAGE_NT_HEADERS64 NTHeaders) {
    PCIMAGE_OPTIONAL_HEADER64 optionalHeader = &(NTHeaders->OptionalHeader);
    size_t offset = (uint8_t *) optionalHeader - imageBase;
    printf("    ('DataDirectory',               0x%05llX,    %llu,        [\n", offset + FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, DataDirectory), sizeof(optionalHeader->DataDirectory));
    printf("        # offset  type   VirtualAddress    Size\n");
    PCIMAGE_DATA_DIRECTORY dataDir;
    // print each data directory's data up to amount specified in the optional header
    for (int idx = 0; idx < optionalHeader->NumberOfRvaAndSizes; idx++) {
        dataDir = &(optionalHeader->DataDirectory[idx]);
        offset = (uint8_t *) dataDir - imageBase;
        printf("        (0x%05llX, '%2u',     0x%06X,      0x%04X),\n", offset, idx, dataDir->VirtualAddress, dataDir->Size);
    }
    printf("    ]),\n");
}


static void printSectionHeaders(PCIMAGE_NT_HEADERS64 NTHeaders){
    PCIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(NTHeaders);
    size_t offset = (uint8_t *) section - imageBase;
    uint16_t numSections = NTHeaders->FileHeader.NumberOfSections;
    printf("    ('Section Headers',            0x%05llX,    %llu,         [\n", offset, sizeof(*section) * numSections);
    printf("        # Name        VirtualSize  VirtualAddress  SizeOfRawData  PointerToRawData\n");
    // print each section header's data up to amount specified in the file header 
    for (int idx = 0; idx < numSections; idx++) {
        printf("        ('%-8s',   0x%06X,      0x%06X,       0x%06X,      0x%06X),\n", section->Name, section->Misc.VirtualSize, section->VirtualAddress, section->SizeOfRawData, section->PointerToRawData);
        section = (PCIMAGE_SECTION_HEADER) ((uint8_t *) section + sizeof(*section));
    }
    printf("    ]),\n");
}


/**
 * @brief Parses the second command line argument as a filepath and opens the file to buffer in process memory
 * @remark Use free() to release buffer when no longer needed
 * 
 * @param[out] fileName Name and path of file read
 * @param[out] fileSize Size of the file read
 * @return Returns allocated buffer containing file (free() when no longer needed) | 0 = ERROR
 */
static uint8_t *loadArgFile(char **fileName, size_t *fileSize, int argc, char *argv[]) {

    // check number of arguments is 2, then take filename argument
    const int FILENAME_ARG = 1;
    if (argc != 2) {
        fprintf(stderr, "Invalid number of arguments given.\nUsage: pehdr <filename|filepath>\n");
        return 0;
    }
    *fileName = argv[FILENAME_ARG];

    // open a handle to the file
    FILE* fp;
    if (fopen_s(&fp, *fileName, "rb") != 0) {
        fprintf(stderr, "ERROR: Open input file for read failed. File: '%s',  Error: %d\n", *fileName, errno);
        return 0;
    }

    // find the size of the file
    size_t size = FileSize(fp);
    if ((int64_t)size == -1) {
        fprintf(stderr, "ERROR: Get input file size file failed. File: '%s',  Error: %d\n", *fileName, errno);
        fclose(fp);
        return 0;
    }
    *fileSize = size;

    // allocate buffer for file
    uint8_t *buffer = (uint8_t *) calloc(size, 1);
    if (buffer == NULL) {
        fprintf(stderr, "ERROR: Allocate read buffer failed.\n");
        goto cleanup;
    }

    // block to limit scope of fread() return value
    {
        // read file into the buffer
        size_t rv = fread(buffer, 1, size, fp);
        if (rv != size)
        {
            fprintf(stderr, "ERROR: Read input file failed. File: '%s',  Error: %d\n", *fileName, errno);
            goto cleanup;
        }
    }
    fclose(fp);
    return buffer;

cleanup:
    fclose(fp);
    if (buffer) {
        free(buffer);
    }
    *fileSize = 0;
    return 0;
}


/**
 * @brief Get length of an open file
 * @remark Limited to 2GiB
 *
 * @param[in] fp Open file pointer
 * @return Returns the length of the file, on error returns 0
 */
static uint32_t FileSize(FILE* fp) {
    int64_t start = ftell(fp);
    if (start == -1){
        return 0;
    }
    uint8_t rv = fseek(fp, 0, SEEK_END);
    if (rv != 0){
        return 0;
    }
    uint32_t size = ftell(fp);
    fseek(fp, start, SEEK_SET);
    return size;
}