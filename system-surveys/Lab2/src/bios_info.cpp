//-------------------------------------------------------------------------------------------------
// bios_info.cpp
//
// BIOS data structures and definitions
//-------------------------------------------------------------------------------------------------
#include "..\include\bios_info.h"
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * Gets a string from the structure's string list.
 *
 * @param str The structure's string list
 * @param index The index of the string to get
 *
 * @return The requested string
 */
const char* GetString(const char* str, unsigned index)
{
    if (index == 0)
    {
        return "nullptr";
    }

    while (--index)
    {
        str += strlen(str) + 1;
    }

    return str;
}


/* Checks if BIOS system info is virtual environment info */
bool IsBIOSSystemVirtual()
{
    bool ret_val = false;

    // Query size of SMBIOS data.
    unsigned sm_bios_data_size = GetSystemFirmwareTable(SMBIOS_FIRMWARE_PROVIDER, SMBIOS_FIRMWARE_ID, nullptr, 0);

    // Allocate memory for SMBIOS data
    auto pSMBIOSData = (RawSMBIOSData*)HeapAlloc(GetProcessHeap(), 0, sm_bios_data_size);
    if (!pSMBIOSData)
    {
        printf("Error allocating memory needed to call GetSystemFirmwareTable.\n");
        return ret_val;
    }

    //
    // pSMBIOSData points to a buffer that will hold the SMBIOS header list. You will query the headers, and then
    // iterate through them to find the SystemInfo header, typecast it as (SystemInfo*) and check that info for
    // signs that your process is running in a virtual environment
    //
    // 1) Make follow-up call to GetSystemFirmwareTable to retrieve the SMBIOS table
    //
    // 2) Loop through the structures in the table
    //    a) Only check the SystemInfo header
    //    b) SytemInfo structure in the header needs to be completed
    //    c) For each header that is not SystemInfo (type 1), you will need to calculate the pointer to the next
    //       header as current header + currHdr->length + skip string list. Remember how pointer math works.
    //       Warning: If you do this wrong, you will be walking through random memory, so if you start seeing
    //         headers and string lists that don't look right, recheck your logic for skipping a header.
    //
    // 3) Some of the data in the structure should show evidence of a virtual environment
    //      Tip: The members, such as 'manufacturer' are optional, 1-based string ids that can be looked
    //          up in the string list that follows the header (at the current header pointer plus currHdr->length).
    //          The GetString() utility function above will look the string up from the list pointer you
    //          calculate.
    //
    // 4) Print the product name of the virtual environment if running in virtual environment (Print the info on
    //      your laptop and a VM to see how they differ)
    //
    // NOTE: The SystemInfo struct isn't the only struct that can be checked for virtual environment info, but
    //  that's all we care about in this lab
    //
    // START: //////////////////////////// LAB2: SMBIOS List of Headers (Part 3b) ////////////////////////////

    sm_bios_data_size = GetSystemFirmwareTable(SMBIOS_FIRMWARE_PROVIDER, SMBIOS_FIRMWARE_ID, pSMBIOSData, sm_bios_data_size);
    PSystemInfo pSystemInfo = (PSystemInfo)(pSMBIOSData->SMBIOSTableData);
    uint8_t* endAddr = (uint8_t*)(pSMBIOSData->SMBIOSTableData) + pSMBIOSData->length;
    bool foundSystemInfo = false;
    // while the entry is not the EndOfTable entry (last entry) or havent exceeded table size
    while ((uint8_t*)pSystemInfo < endAddr && pSystemInfo->header.type != (int)BiosType::EndOfTable)
    {
        // if System Info header type found, break out with flag set
        if (pSystemInfo->header.type == (int)BiosType::SystemInfo)
        {
            foundSystemInfo = true;
            break;
        }
        // iterate to string
        pSystemInfo = (PSystemInfo)((uint8_t *)pSystemInfo + pSystemInfo->header.length);
        // iterate past all string characters until finding a double null (end of string list)
        while (*((char*)pSystemInfo) != '\0' || *(((char*)pSystemInfo)+1) != '\0')
        {
            pSystemInfo = (PSystemInfo)((uint8_t*)pSystemInfo + 1);
        }
        pSystemInfo = (PSystemInfo)((uint8_t*)pSystemInfo + 2);
    }

    if (foundSystemInfo)
    {
        const char* manufacturer = GetString((const char*)pSystemInfo + pSystemInfo->header.length, pSystemInfo->manufacturer);
        printf("BIOS Info, Manufacturer: %s\n", manufacturer);
        const char* productName = GetString((const char*)pSystemInfo + pSystemInfo->header.length, pSystemInfo->productName);
        printf("BIOS Info, Product Name: %s\n", productName);
        if (strstr(manufacturer, "VMware") || strstr(productName, "VMware"))
        {
            ret_val = true;
        }
    }
    else
    {
        printf("Unable to locate BIOS system info structure.\n");
    }
    //printf("BIOS Info, version: %s\n", GetString((const char*)pSystemInfo + pSystemInfo->header.length, pSystemInfo->version));
    //printf("BIOS Info, serialNumber: %s\n", GetString((const char*)pSystemInfo + pSystemInfo->header.length, pSystemInfo->serialNumber));
    //printf("BIOS Info, skuNumber: %s\n", GetString((const char*)pSystemInfo + pSystemInfo->header.length, pSystemInfo->skuNumber));

    // END:   //////////////////////////// LAB2: SMBIOS List of Headers (Part 3b) ////////////////////////////

    // cleanup
    if (pSMBIOSData)
    {
        HeapFree(GetProcessHeap(), 0, pSMBIOSData);
    }
    return ret_val;
}
