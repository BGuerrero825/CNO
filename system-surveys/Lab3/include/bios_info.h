//-------------------------------------------------------------------------------------------------
// bios_info.h
//
// BIOS data structures and definitions
//-------------------------------------------------------------------------------------------------
#pragma once
#include <windows.h>
#include <stdint.h>

namespace Hardware
{
    uint32_t GetBIOSInfo();

#pragma pack(push)
#pragma pack(1)

    typedef struct _RawSMBIOSData
    {
        uint8_t  used_20_calling_method;
        uint8_t  sm_bios_major_version;
        uint8_t  sm_bios_minor_version;
        uint8_t  dmi_revision;
        uint32_t length;
        uint8_t  SMBIOSTableData[1];
    } RawSMBIOSData, *PRawSMBIOSData;

    typedef struct _SMBIOSHeader
    {
        uint8_t type;
        uint8_t length;
        uint16_t handle;
    } SMBIOSHeader, *PSMBIOSHeader;

    //
    // Copy your SystemInfo definition and the header type enum from your work in Lab2. Then extend that work
    // to dump information about the devices identified by the SMBIOS.
    //
    // 1) Review Parts 1b and 1c in bios_info.cpp. Start with Part 1c, iterate through the headers, typecast each as
    //    UnknownInfo* and call PrintUnknownInfo() for it. You can use some of your code from Lab2 here as well.
    //
    // 2) Add support for each of the following header types by defining the structure for it (SystemInfo is done in
    //    your Lab2 solution), adding a PrintXyz() function for it, and identifying those types from the list and
    //    passing them to the appropriate printer.
    //
    //      BIOS Info
    //      System Info
    //      Baseboard Info
    //      Processor Info
    //      Memory Device Info
    //
    // START: //////////////////////////// LAB3: BIOS Header Structures (Part 1a) ////////////////////////////

    /**
    * @brief BIOS type values
    */
    enum class BiosType {
        BIOSInfo = 0,
        SystemInfo = 1,
        BaseboardInfo = 2,
        ProcessorInfo = 4,
        MemoryDeviceInfo = 17,
        EndOfTable = 127
    };

    /**
     * @brief Type0 (BIOSInfo) specific BIOS header
     */
    typedef struct _Type0
    {
        SMBIOSHeader header;
        // type specific data follows base BIOS header
        uint8_t vendorIdx;
        uint8_t biosVersionIdx;
        uint16_t biosStartAddressSegment;
        uint8_t biosReleaseDateIdx;
        uint8_t biosRomSize;
        uint64_t biosCharacteristics;
        uint16_t biosCharacteristicsEx;
        uint8_t biosMajorRelease;
        uint8_t biosMinorRelease;
        uint8_t embedControllerMajorRelease;
        uint8_t embedControllerMinorRelease;
        uint16_t biosRomSizeEx;
    } BIOSInfo, * PBIOSInfo;
    typedef const BIOSInfo* PCBIOSInfo;

    /**
     * @brief Type1 (SystemInfo) specific BIOS header
     */
    typedef struct _Type1
    {
        SMBIOSHeader header;
        uint8_t manufacturerIdx;
        uint8_t productNameIdx;
        uint8_t versionIdx;
        uint8_t serialNumberIdx;
        uint8_t uuid[16];
        uint8_t wakeupType;
        uint8_t skuNumberIdx;
        uint8_t familyIdx;
    } SystemInfo, * PSystemInfo;
    typedef const SystemInfo* PCSystemInfo;

    /**
     * @brief Type2 (BaseboardInfo) specific baseboard header
     */
    typedef struct _Type2
    {
        SMBIOSHeader header;
        uint8_t manufacturerIdx;
        uint8_t productNameIdx;
        uint8_t versionIdx;
        uint8_t serialNumberIdx;
        uint8_t assetTagIdx;
        uint8_t featureFlags;
        uint8_t locationInChassisIdx;
        uint16_t chassisHandle;
        uint8_t boardType;
        uint8_t numContainedObjHandles;
        uint8_t containedObjHandles[1];
    } BaseboardInfo, * PBaseboardInfo;
    typedef const BaseboardInfo * PCBaseboardInfo;

    /**
     * @brief Type4 (ProcessorInfo) specific processor header
     */
    typedef struct _Type4
    {
        SMBIOSHeader header;
        uint8_t socketDesignationIdx;
        uint8_t processorType;
        uint8_t processorFamily;
        uint8_t processorManufacturerIdx;
        uint64_t processorId;
        uint8_t processorVersionIdx;
        uint8_t voltage;
        uint16_t externalClock;
        uint16_t maxSpeed;
        uint16_t currentSpeed;
        uint8_t status;
        uint8_t processorUpgrade;
        uint16_t l1CacheHandle;
        uint16_t l2CacheHandle;
        uint16_t l3CacheHandle;
        uint8_t serialNumberIdx;
        uint8_t assetTagIdx;
        uint8_t partNumberIdx;
        uint8_t coreCount;
        uint8_t coreEnabled;
        uint8_t threadCount;
        uint16_t processorCharacteristics;
        uint16_t processorFamily2;
        uint16_t coreCount2;
        uint16_t coreEnabled2;
        uint16_t threadCount2;
    } ProcessorInfo, * PProcessorInfo;
    typedef const ProcessorInfo * PCProcessorInfo;

    /**
     * @brief Type17 (MemoryDeviceInfo) specific memory device header
     */
    typedef struct _Type17
    {
        SMBIOSHeader header;
        uint16_t physicalMemoryArrayHandle;
        uint16_t memoryErrorInfoHandle;
        uint16_t totalWidth;
        uint16_t dataWidth;
        uint16_t size;
        uint8_t formFactor;
        uint8_t deviceSet;
        uint8_t deviceLocatorIdx;
        uint8_t bankLocatorIdx;
        uint8_t memoryType;
        uint16_t typeDetail;
        uint16_t speed;
        uint8_t manufacturerIdx;
        uint8_t serialNumberIdx;
        uint8_t assetTagIdx;
        uint8_t partNumberIdx;
        uint8_t attributes;
        uint32_t extendedSize;
        uint16_t configuredMemorySpeed;
        uint16_t minVoltage;
        uint16_t maxVoltage;
        uint16_t configuredVoltage;
        uint8_t  memoryTechnology;
        uint16_t memoryOpModeCapability;
        uint8_t firmwareVersionIdx;
        uint16_t moduleManufacturerId;
        uint16_t moduleProductId;
        uint16_t memorySubControlManufacturerId;
        uint16_t memorySubControlProductId;
        uint64_t nonVolatileSize;
        uint64_t volatileSize;
        uint64_t cacheSize;
        uint64_t logicalSize;
        uint32_t extendedSpeed;
        uint32_t extendedConfiguredMemorySpeed;
    } MemoryDeviceInfo, * PMemoryDeviceInfo;
    typedef const MemoryDeviceInfo* PCMemoryDeviceInfo;


    // END:   //////////////////////////// LAB3: BIOS Header Structures (Part 1a) ////////////////////////////

    typedef struct _UnknownInfo
    {
        SMBIOSHeader header;
    } UnknownInfo, *PUnknownInfo;
#pragma pack(pop)
}

