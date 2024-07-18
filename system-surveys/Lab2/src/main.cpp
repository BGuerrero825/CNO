//-------------------------------------------------------------------------------------------------
// main.cpp
//
// Detecting Virtualization
//-------------------------------------------------------------------------------------------------
#include "..\include\bios_info.h"

#include <intrin.h>
#include <stdio.h>
//#include <cstdio>

extern "C" bool CheckHypervisorPort();

/**
 * Checks if CPUID hypervisor bit is set.
 *
 * @return True if CPUID hypervisor bit is set; False otherwise
 */
bool IsCPUIDHypervisorBitSet()
{
    //
    // As discussed in the slides, the CPUID opcode provides a bit that identifies a virtual processor, and
    //  if virtual, a hypervisor id query.
    //
    // 1) Reference slides for this section to figure out how to use __cpuid
    // 2) If you determine it's a virtual environment, print out the vendor id
    //      Note: For recent versions of Windows 10, this method may report Hyper-V due to Virtualization
    //      Based Security. Use all relavent methods to try to confirm.
    //
    // START: //////////////////////////// LAB2: CPUID Hypervisor Bit (Part 1) ////////////////////////////

#define EAX 0
#define EBX 1
#define ECX 2
#define EDX 3
#define MANUF_ID_LEAF 0x00
#define FEATURE_BITS_LEAF 0x01
#define HV_BITMASK 0x00000001
#define HV_ID_LEAF 0x40000000

    int regs[4] = { 0 };
    //__cpuid(regs, MANUF_ID_LEAF);
    //printf("Highest Function Parameter: 0x%X\n", regs[EAX]);
    //printf("Manufacturer ID: ");
    //printf("%.4s%.4s%.4s\n", (char*) & regs[EBX], (char*) &regs[EDX], (char*) &regs[ECX]);
    __cpuid(regs, FEATURE_BITS_LEAF);
    bool hypervisor = regs[ECX] & HV_BITMASK;
    printf("Hypervisor Present: %s\n", hypervisor ? "Yes" : "No");

    char hvId[64] = { 0 };
    __cpuid(regs, HV_ID_LEAF);
    sprintf_s(hvId, "%.4s%.4s%.4s\n", (char*)&regs[EBX], (char*)&regs[ECX], (char*)&regs[EDX]);
    //printf("Highest Function Parameter: 0x%X\n", regs[EAX]);
    printf("CPUID, Hypervisor ID: %s", hvId);
    if (hypervisor && !strstr(hvId, "VMware"))
    {
        return false;
    }


    return true;
    // END:   //////////////////////////// LAB2: CPUID Hypervisor Bit (Part 1) ////////////////////////////
}

/**
 * Checks if VMware hypervisor port is in use.
 *
 * @return True is VMware hypervisor port is in use; False otherwise
 */
bool IsHypervisorPortInUse()
{
    __try
    {
        // Edit hypervisor_port.asm
        if (CheckHypervisorPort())
        {
            printf("(Port Info) Running in virtual environment.\n");
            return true;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        printf("Error, exception thrown checking VMware virtual port.\n");
    }

    return false;
}

int __cdecl main()
{
    bool check1 = IsCPUIDHypervisorBitSet();
    bool check2 = IsBIOSSystemVirtual();
    // IsBIOSSystemVirtual must return true before checking hypervisor port
    // Otherwise, it could result in undefined behavior
    bool check3 = check2 ? IsHypervisorPortInUse() : false;

    if (!check1 && !(check2 && check3))
    {
        printf("Not running in virtual environment.\n");
    }
    //std::getchar();

    return 0;
}