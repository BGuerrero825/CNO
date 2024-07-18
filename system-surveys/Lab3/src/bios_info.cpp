//-------------------------------------------------------------------------------------------------
// bios_info.cpp
//
// BIOS data structures and definitions
//-------------------------------------------------------------------------------------------------
#include "..\include\bios_info.h"

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

// Uncomment to display unknown structures
//#define DEBUG

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

/**
 * Prints a character based on hex value. If not a displayable character, prints "."
 *
 * @param c The character to print
 */
void PrintChar(char c)
{
    if (c >= 0x20 && c <= 0x7E || c >= 0xA0 && c <= 0xFF)
    {
        printf("%c", c);
    }
    else
    {
        printf(".");
    }
}

/**
 * Prints unknown structure data and strings.
 *
 * @param PUnknownInfo Pointer to unknown structure
 */
void PrintUnknownInfo(Hardware::PUnknownInfo pUnknownInfo)
{
    const uint8_t  LINE_LIMIT = 16;

    uint8_t* dataPtr = (uint8_t*)pUnknownInfo;
    uint8_t* endOfHeader = dataPtr + pUnknownInfo->header.length;

    printf("-----| Unknown Firmware Information |-----\n");
    printf("    Unknown Structure Type: %lu (len=%u)\n\t", pUnknownInfo->header.type, pUnknownInfo->header.length);

    uint8_t* startOfLine = dataPtr;
    unsigned nullTerminators = 2;
    while (nullTerminators)
    {
        // once we are past the header, start watching for the terminating double nulls
        if (dataPtr >= endOfHeader)
        {
            // if we're already processing the double null or we just reached it, decrement the null terminator counter
            if (nullTerminators < 2 || (*dataPtr == 0 && *(dataPtr + 1) == 0))
            {
                --nullTerminators;
            }
        }

        printf("%02X ", *dataPtr);

        // point to next character and see if we need to end the line
        dataPtr++;
        if (dataPtr - startOfLine == LINE_LIMIT)
        {
            while (startOfLine != dataPtr)
            {
                PrintChar(*startOfLine);
                ++startOfLine;
            }
            printf("\n\t");
        }
    }

    unsigned printedThisLine = (unsigned)(dataPtr - startOfLine);
    while (printedThisLine < LINE_LIMIT)
    {
        printf("   ");
        ++printedThisLine;
    }

    unsigned count = 0;
    while (startOfLine != dataPtr)
    {
        PrintChar(*startOfLine);
        ++startOfLine;
        ++count;
    }

    if (count)
    {
        printf("\n");
    }

    printf("\n");
}


//
// Add functions to dump details of the specific device types supported (similar to PrintUnknownInfo(),
//      but type specific (E.g. void PrintBIOSInfo(Hardware::PBIOSInfo pBIOSInfo))
//
// START: //////////////////////////// LAB3: BIOS Header Printers (Part 1b) ////////////////////////////

/**
 * @brief Iterates past the current BIOS header to the start of strings.
 *
 * @param pBIOSInfo pointer to current BIOS header to be iterated past
 * @return const char* at start of strings section
 */
inline const char* SkipBiosHeader(const void * pBIOSInfo)
{
    return (const char*)((uint8_t *)pBIOSInfo + ((Hardware::PUnknownInfo)pBIOSInfo)->header.length);
}


/**
 * @brief Iterates past the current BIOS structure in the firmware table.
 *
 * @param pBIOSInfo pointer to current BIOS structure to be iterated past
 * @return pointer to next BIOS structure
 */
Hardware::PUnknownInfo SkipBiosStruct(Hardware::PUnknownInfo pBIOSInfo)
{
    // skip BIOS header
    uint8_t* pData = (uint8_t *)pBIOSInfo;
    pData += pBIOSInfo->header.length;

    // skip BIOS strings
    // iterate past all string characters until finding a double null (end of string list)
    while (true)
    {
        if (*(pData) == 0 && *(pData + 1) == 0)
        {
            pData += 2;
            break;
        }
        pData++;
    }
    return (Hardware::PUnknownInfo)pData;
}


/**
 * Prints BIOS info structure data and strings.
 *
 * @param PBiosInfo Pointer to BIOS info structure.
 */
void PrintBiosInfo(Hardware::PCBIOSInfo pBIOSInfo)
{
    printf("-----| BIOS Information |-----\n");
    printf("Vendor: %s\n",
        GetString(SkipBiosHeader(pBIOSInfo), pBIOSInfo->vendorIdx));
    printf("Version: %s\n",
        GetString(SkipBiosHeader(pBIOSInfo), pBIOSInfo->biosVersionIdx));
    printf("Start Address Segment: 0x%04X\n", pBIOSInfo->biosStartAddressSegment);
    printf("Release Date: %s\n",
        GetString(SkipBiosHeader(pBIOSInfo), pBIOSInfo->biosReleaseDateIdx));
    printf("ROM Size: %uK\n", 64 * (pBIOSInfo->biosRomSize + 1));
    printf("Characteristics: 0x%016zX\n", pBIOSInfo->biosCharacteristics);
    printf("Characteristics (Extension): 0x%04X\n", pBIOSInfo->biosCharacteristicsEx);
    printf("Major Release: %u\n", pBIOSInfo->biosMajorRelease);
    printf("Minor Release: %u\n", pBIOSInfo->biosMinorRelease);
    printf("Embedded Controller Major Release: %u\n", pBIOSInfo->embedControllerMajorRelease);
    printf("Embedded Controller Minor Release: %u\n", pBIOSInfo->embedControllerMinorRelease);
    printf("ROM Size (Extension): 0x%04X\n", pBIOSInfo->biosRomSizeEx);
    printf("\n");
}


/**
 * Prints system info structure data and strings.
 *
 * @param PSystemInfo Pointer to system info structure.
 */
void PrintSystemInfo(Hardware::PCSystemInfo pSystemInfo)
{
    printf("-----| System Information |-----\n");
    printf("Manufacturer: %s\n",
        GetString(SkipBiosHeader(pSystemInfo), pSystemInfo->manufacturerIdx));
    printf("Product Name: %s\n",
        GetString(SkipBiosHeader(pSystemInfo), pSystemInfo->productNameIdx));
    printf("Version: %s\n",
        GetString(SkipBiosHeader(pSystemInfo), pSystemInfo->versionIdx));
    printf("Serial Number: %s\n",
        GetString(SkipBiosHeader(pSystemInfo), pSystemInfo->serialNumberIdx));
    printf("UUID: \n");
    for (unsigned idx = 0; idx < sizeof(pSystemInfo->uuid); idx++)
    {
        printf("%02X", pSystemInfo->uuid[idx]);
    }
    printf("\n");
    printf("Wakeup Type: %u\n", pSystemInfo->wakeupType);
    printf("SKU Number: %s\n",
        GetString(SkipBiosHeader(pSystemInfo), pSystemInfo->skuNumberIdx));
    printf("Family: %s\n",
        GetString(SkipBiosHeader(pSystemInfo), pSystemInfo->familyIdx));
    printf("\n");
}


/**
 * Prints baseboard info structure data and strings.
 *
 * @param PBaseboardInfo Pointer to baseboard info structure.
 */
void PrintBaseboardInfo(Hardware::PCBaseboardInfo pBaseboardInfo)
{
    printf("-----| Baseboard Information |-----\n");
    printf("Manufacturer: %s\n",
        GetString(SkipBiosHeader(pBaseboardInfo), pBaseboardInfo->manufacturerIdx));
    printf("Product Name: %s\n",
        GetString(SkipBiosHeader(pBaseboardInfo), pBaseboardInfo->productNameIdx));
    printf("Version: %s\n",
        GetString(SkipBiosHeader(pBaseboardInfo), pBaseboardInfo->versionIdx));
    printf("Serial Number: %s\n",
        GetString(SkipBiosHeader(pBaseboardInfo), pBaseboardInfo->serialNumberIdx));
    printf("Asset Tag: %s\n",
        GetString(SkipBiosHeader(pBaseboardInfo), pBaseboardInfo->assetTagIdx));
    printf("Feature Flags: 0x%02X\n", pBaseboardInfo->featureFlags);
    printf("Location In Chassis: %s",
        GetString(SkipBiosHeader(pBaseboardInfo), pBaseboardInfo->locationInChassisIdx));
    printf("Chassis Handle: 0x%04X\n", pBaseboardInfo->chassisHandle);
    printf("Board Type: %u\n", pBaseboardInfo->boardType);
    printf("Number Contained Object Handles: %u\n", pBaseboardInfo->numContainedObjHandles);
    for (int idx = 0; idx < pBaseboardInfo->numContainedObjHandles; idx++)
    {
        printf("Object Handle %u: 0x%04X\n", idx + 1, pBaseboardInfo->containedObjHandles[idx]);
    }
    printf("\n");
}

/**
 * Prints processor info structure data and strings.
 *
 * @param PCProcessorInfo Pointer to processor info structure.
 */
void PrintProcessorInfo(Hardware::PCProcessorInfo pProcessorInfo)
{
    printf("-----| Processor Information |-----\n");
    printf("Socket Designation: %s\n",
        GetString(SkipBiosHeader(pProcessorInfo), pProcessorInfo->socketDesignationIdx));
    printf("Processor Type: %u\n", pProcessorInfo->processorType);
    printf("Processor Family: %u\n", pProcessorInfo->processorFamily);
    printf("Processor Manufacturer: %s\n",
        GetString(SkipBiosHeader(pProcessorInfo), pProcessorInfo->processorManufacturerIdx));
    printf("Processor ID: 0x%016zX\n", pProcessorInfo->processorId);
    printf("Processor Version: %s\n",
        GetString(SkipBiosHeader(pProcessorInfo), pProcessorInfo->processorVersionIdx));
    printf("Voltage: %u\n", pProcessorInfo->voltage);
    printf("External Clock: %uMhz\n", pProcessorInfo->externalClock);
    printf("Max Speed: %u\n", pProcessorInfo->maxSpeed);
    printf("Current Speed: %u\n", pProcessorInfo->currentSpeed);
    printf("Status: 0x%02x\n", pProcessorInfo->status);
    printf("Processor Upgrade: %u\n", pProcessorInfo->processorUpgrade);
    printf("L1 Cache Handle: 0x%04X\n", pProcessorInfo->l1CacheHandle);
    printf("L2 Cache Handle: 0x%04X\n", pProcessorInfo->l2CacheHandle);
    printf("L3 Cache Handle: 0x%04X\n", pProcessorInfo->l3CacheHandle);
    printf("Serial Number: %s\n",
        GetString(SkipBiosHeader(pProcessorInfo), pProcessorInfo->serialNumberIdx));
    printf("Asset Tag: %s\n",
        GetString(SkipBiosHeader(pProcessorInfo), pProcessorInfo->assetTagIdx));
    printf("Part Number: %s\n",
        GetString(SkipBiosHeader(pProcessorInfo), pProcessorInfo->partNumberIdx));
    printf("Core Count: %u\n", pProcessorInfo->coreCount);
    printf("Core Enabled: %u\n", pProcessorInfo->coreEnabled);
    printf("Thread Count: %u\n", pProcessorInfo->threadCount);
    printf("Processor Characteristics: 0x%04X\n", pProcessorInfo->processorCharacteristics);
    printf("Processor Family 2: %u\n", pProcessorInfo->processorFamily2);
    printf("Core Count 2: %u\n", pProcessorInfo->coreCount2);
    printf("Core Enabled 2: %u\n", pProcessorInfo->coreEnabled2);
    printf("Thread Count 2: %u\n", pProcessorInfo->threadCount2);
    printf("\n");
}

/**
 * Prints memory device info structure data and strings.
 *
 * @param PCMemoryDeviceInfo Pointer to memory device info structure.
 */
void PrintMemoryDeviceInfo(Hardware::PCMemoryDeviceInfo pMemoryDeviceInfo)
{
    printf("-----| Memory Device Information |-----\n");
    printf("Physical Memory Array Handle: 0x%04X\n", pMemoryDeviceInfo->physicalMemoryArrayHandle);
    printf("Memory Error Information Handle: 0x%04X\n", pMemoryDeviceInfo->memoryErrorInfoHandle);
    printf("Total Width: %u\n", pMemoryDeviceInfo->totalWidth);
    printf("Data Width: %u\n", pMemoryDeviceInfo->dataWidth);
    printf("Size: %u\n", pMemoryDeviceInfo->size);
    printf("Form Factor: %u\n", pMemoryDeviceInfo->formFactor);
    printf("Device Set: %u\n", pMemoryDeviceInfo->deviceSet);
    printf("Device Locator: %s\n",
        GetString(SkipBiosHeader(pMemoryDeviceInfo), pMemoryDeviceInfo->deviceLocatorIdx));
    printf("Bank Locator: %s\n",
        GetString(SkipBiosHeader(pMemoryDeviceInfo), pMemoryDeviceInfo->bankLocatorIdx));
    printf("Memory Type: %u\n", pMemoryDeviceInfo->memoryType);
    printf("Type Detail: 0x%04X\n", pMemoryDeviceInfo->typeDetail);
    printf("Speed: %uMT/s\n", pMemoryDeviceInfo->speed);
    printf("Manufacturer: %s\n",
        GetString(SkipBiosHeader(pMemoryDeviceInfo), pMemoryDeviceInfo->manufacturerIdx));
    printf("Serial Number: %s\n",
        GetString(SkipBiosHeader(pMemoryDeviceInfo), pMemoryDeviceInfo->serialNumberIdx));
    printf("Asset Tag: %s\n",
        GetString(SkipBiosHeader(pMemoryDeviceInfo), pMemoryDeviceInfo->assetTagIdx));
    printf("Part Number: %s\n",
        GetString(SkipBiosHeader(pMemoryDeviceInfo), pMemoryDeviceInfo->partNumberIdx));
    printf("Attributes: 0x%02X\n", pMemoryDeviceInfo->attributes);
    printf("Extended Size: %lu\n", pMemoryDeviceInfo->extendedSize);
    printf("Configured Memory Speed: %uMT/s\n", pMemoryDeviceInfo->configuredMemorySpeed);
    printf("Minimum Voltage: %umV\n", pMemoryDeviceInfo->minVoltage);
    printf("Maximum Voltage: %umV\n", pMemoryDeviceInfo->maxVoltage);
    printf("Configured Voltage: %umV\n", pMemoryDeviceInfo->configuredVoltage);
    printf("Memory Technology: %u\n", pMemoryDeviceInfo->memoryTechnology);
    printf("Memory Operating Mode Capability: 0x%04X\n", pMemoryDeviceInfo->memoryOpModeCapability);
    printf("Firmware Version: %s\n",
        GetString(SkipBiosHeader(pMemoryDeviceInfo), pMemoryDeviceInfo->firmwareVersionIdx));
    printf("Module Manufacturer ID: 0x%04X\n", pMemoryDeviceInfo->moduleManufacturerId);
    printf("Module Product ID: 0x%04X\n", pMemoryDeviceInfo->moduleProductId);
    printf("Memory Subsystem Controller Manufacturer ID: 0x%04X\n", pMemoryDeviceInfo->memorySubControlManufacturerId);
    printf("Memory Subsystem Controller Product ID: 0x%04X\n", pMemoryDeviceInfo->memorySubControlProductId);
    printf("Non-Volatile Size: %zd\n", pMemoryDeviceInfo->nonVolatileSize);
    printf("Volatile Size: %zd\n", pMemoryDeviceInfo->volatileSize);
    printf("Cache Size: %zd\n", pMemoryDeviceInfo->cacheSize);
    printf("Logical Size: %zd\n", pMemoryDeviceInfo->logicalSize);
    printf("Extended Speed: %luMT/s\n", pMemoryDeviceInfo->extendedSpeed);
    printf("Extended Configured Memory Speed: %luMT/s\n", pMemoryDeviceInfo->extendedConfiguredMemorySpeed);
    printf("\n");
}

// END:   //////////////////////////// LAB3: BIOS Header Printers (Part 1b) ////////////////////////////


/**
 * Gets and prints BIOS information.
 *
 * @return Error code
 */
uint32_t Hardware::GetBIOSInfo()
{
    #define END_OF_TABLE 127
    unsigned ret_val = 0;

    // Query size of SMBIOS data.
    unsigned sm_bios_data_size = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);

    // Allocate memory for SMBIOS data
    PRawSMBIOSData pSMBIOSData = (RawSMBIOSData *)HeapAlloc(GetProcessHeap(), 0, sm_bios_data_size);
    if (!pSMBIOSData)
    {
        printf("Error allocating memory needed to call GetSystemFirmwareTable.\n");
        return ERROR_OUTOFMEMORY;
    }

    //
    // 1) Make follow-up call to GetSystemFirmwareTable to retrieve the SMBIOS table
    // 2) Loop through the structures in the table
    //    a) Identify supported header types, and call the appropriate printer
    //    b) For unsupported types, call PrintUnknownInfo()
    //    c) Skip to the next header
    //      Hint: You will be doing this a lot, so utilities to SkipBiosHeader() and SkipStrings() are
    //          recommended
    //
    // START: //////////////////////////// LAB3: BIOS Header Parser (Part 1c) ////////////////////////////

    // call to get firmware table with previously returned size allocated
    sm_bios_data_size = GetSystemFirmwareTable('RSMB', 0, pSMBIOSData, sm_bios_data_size);
    if (!sm_bios_data_size)
    {
        ret_val = GetLastError();
        fprintf(stderr, "Failed to retrieve firmware table. Error: %lu", ret_val);
        return ret_val;
    }

    uint8_t* endAddr = (uint8_t*)(pSMBIOSData->SMBIOSTableData) + pSMBIOSData->length;
    PUnknownInfo currentStruct = (PUnknownInfo) pSMBIOSData->SMBIOSTableData;
    // while the entry is not the EndOfTable entry (last entry) or havent exceeded table size
    while ((uint8_t*)currentStruct < endAddr && currentStruct->header.type != (int)BiosType::EndOfTable)
    {
        switch (currentStruct->header.type)
        {
        case (int)BiosType::BIOSInfo:
            PrintBiosInfo((PCBIOSInfo)currentStruct);
            break;
        case (int)BiosType::SystemInfo:
            PrintSystemInfo((PCSystemInfo)currentStruct);
            break;
        case (int)BiosType::BaseboardInfo:
            PrintBaseboardInfo((PCBaseboardInfo)currentStruct);
            break;
        case (int)BiosType::ProcessorInfo:
            PrintProcessorInfo((PCProcessorInfo)currentStruct);
            break;
        case (int)BiosType::MemoryDeviceInfo:
            PrintMemoryDeviceInfo((PCMemoryDeviceInfo)currentStruct);
            break;
        default:
            PrintUnknownInfo(currentStruct);
            break;
        }

        currentStruct = SkipBiosStruct(currentStruct);

    }

    // END:   //////////////////////////// LAB3: BIOS Header Parser (Part 1c) ////////////////////////////

    // cleanup
    if (pSMBIOSData)
    {
        HeapFree(GetProcessHeap(), 0, pSMBIOSData);
    }
    return ret_val;
}
