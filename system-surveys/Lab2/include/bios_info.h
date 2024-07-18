//-------------------------------------------------------------------------------------------------
// bios_info.h
//
// BIOS data structures and definitions
//-------------------------------------------------------------------------------------------------
#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>


//-------------------------------------------------------------------------------------------------
// Definitions and types
//-------------------------------------------------------------------------------------------------

#define SMBIOS_FIRMWARE_PROVIDER    'RSMB'
#define SMBIOS_FIRMWARE_ID          0


#pragma pack(push)
#pragma pack(1)

///
/// @brief Raw SMBIOS data
///
typedef struct _RawSMBIOSData
{
    uint8_t     used_20_calling_method;
    uint8_t     sm_bios_major_version;
    uint8_t     sm_bios_minor_version;
    uint8_t     dmi_revision;
    uint32_t    length;                 // size, in bytes, of the SMBIOSDataTable[] contents
    uint8_t     SMBIOSTableData[1];     // list of variable sized SMBIOS Firmware records. Each starts with SMBIOSHeader, but has additional
                                        //  structure members based on the type id.
} RawSMBIOSData, *PRawSMBIOSData;

typedef const RawSMBIOSData *PCRawSMBIOSData;

///
/// @brief Base BIOS header
///
typedef struct _SMBIOSHeader
{
    uint8_t     type;                   // type id for this BIOS record
    uint8_t     length;                 // length of the fixed portion of this BIOS record, variable length null terminated string list follows
    uint16_t    handle;
} SMBIOSHeader, *PSMBIOSHeader;

typedef const SMBIOSHeader *PCSMBIOSHeader;

/**
 * @brief BIOS type values
 */
enum class BiosType {
    SystemInfo = 1,
    EndOfTable = 127
};


//
// System Management BIOS (SMBIOS) headers each begin with the SMBIOSHeader structure above, which provides the type and length of the
// header. For each type, additional information exists in the BIOS header. The length field indicates the size of that header. Following
// the header are a list of strings terminated with a double null (e.g. '\0\0'). If no strings, there is just the double null, else the
// list continues until a string has a double null termination (e.g. 'Manufacturer Name\0Serial Number\0\0')
//
// References:
//    General Overview: https://wiki.osdev.org/System_Management_BIOS
//    Specs (incl type definitions): https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.3.0.pdf
//
// Header type 1 is System Info (indicated by BiosType::SystemInfo above). So if currentHeader->type == (unsigned)BiosType::SystemInfo,
// typecast the header as const SystemInfo* to get access to the structure members specific to that type. See the specs link above for
// the definition of the system information (1) header type, and complete the structure definition below.
//
// START: //////////////////////////// LAB2: SystemInfo Structure (Part 3a) ////////////////////////////

///
/// @brief Type1 (SystemInfo) specific BIOS header
///
typedef struct _Type1
{
    SMBIOSHeader header;
    // type specific data follows base BIOS header
    uint8_t manufacturer;
    uint8_t productName;
    uint8_t version;
    uint8_t serialNumber;
    uint8_t uuid[16];
    uint8_t wakeupType;
    uint8_t skuNumber;
    uint8_t family;
} SystemInfo, *PSystemInfo;

typedef const SystemInfo* PCSystemInfo;

// END:   //////////////////////////// LAB2: SystemInfo Structure (Part 3a) ////////////////////////////

#pragma pack(pop)

//-------------------------------------------------------------------------------------------------
// Function Declarations
//-------------------------------------------------------------------------------------------------
/**
 * @brief Checks if BIOS system info is virtual environment info.
 *
 * @return True if BIOS system info is virtual; False otherwise
 */
bool IsBIOSSystemVirtual();
