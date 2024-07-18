//-------------------------------------------------------------------------------------------------
// adapter_info.cpp
//
// List attached adapters
//-------------------------------------------------------------------------------------------------
#include "..\include\adapter_info.h"

#include <iphlpapi.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#pragma comment(lib, "IPHLPAPI.lib")

/**
 * @brief Prints entries in a linked list of IP_ADDR_STRINGs.
 *
 * @param address the first node of the IP_ADDR_STRING list.
 */
void PrintIpAddrs(PIP_ADDR_STRING address)
{
    while (address)
    {
        printf("|-- IP Address: %s\n", address->IpAddress.String);
        printf("    IP Mask: %s\n", address->IpMask.String);
        printf("    Context: 0x%04lX\n", address->Context);
        address = address->Next;
    }
}


/**
 * Gets and prints adapter info.
 *
 * @return Error code
 */
uint32_t Hardware::GetAdapterInfo()
{
    unsigned ret_val = 0;

    // allocate initial adapter info buffer
    unsigned outBufLen = (unsigned)sizeof(IP_ADAPTER_INFO);
    PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO *)calloc(1, outBufLen);
    if (pAdapterInfo == nullptr)
    {
        printf("Error allocating memory needed to call GetAdaptersinfo.\n");
        return ERROR_OUTOFMEMORY;
    }

    // Make an initial call to GetAdaptersInfo to get the necessary size into the outBufLen variable
    if (GetAdaptersInfo(pAdapterInfo, (ULONG*)&outBufLen) == ERROR_BUFFER_OVERFLOW)
    {
        if (pAdapterInfo)
        {
            free(pAdapterInfo);
            pAdapterInfo = nullptr;
        }

        pAdapterInfo = (IP_ADAPTER_INFO*)calloc(1, outBufLen);
        if (pAdapterInfo == nullptr)
        {
            printf("Error allocating memory needed to call GetAdaptersinfo.\n");
            ret_val = ERROR_OUTOFMEMORY;
            goto cleanup;
        }
    }

    //
    // 1) Make a follow-up call to GetAdaptersInfo() to get adapter info
    // 2) Loop through adapters to get and print info about each
    //    a) Get Name, Description, MAC Address, Type, and Associated IPs
    //
    // START: //////////////////////////// LAB3: Print Adapter Info (Part 2) ////////////////////////////

    // follow-up call, if error received again, jump to cleanup with received error code
    ret_val = GetAdaptersInfo(pAdapterInfo, (ULONG*)&outBufLen);
    if (ret_val)
    {
        printf("Failed to get adapter information. Error %lu.\n", ret_val);
        goto cleanup;
    }


    if (outBufLen == 0)
    {
        ret_val = ERROR_SUCCESS;
        printf("No adapter information to display.\n");
        goto cleanup;
    }

    while (pAdapterInfo)
    {
        printf("-----| Network Adapter Information |-----\n");
        printf("Adapter Name: %s\n", pAdapterInfo->AdapterName);
        printf("Description: %s\n", pAdapterInfo->Description);
        printf("Address Length: %u\n", pAdapterInfo->AddressLength);
        printf("Address: 0x%0*X\n", MAX_ADAPTER_ADDRESS_LENGTH, (unsigned) pAdapterInfo->Address);
        printf("Index: %u\n", pAdapterInfo->Index);
        printf("Type: %u\n", pAdapterInfo->Type);
        printf("DHCP Enabled: %u\n", pAdapterInfo->DhcpEnabled);
        printf("IP Address List:\n");
        PrintIpAddrs(&(pAdapterInfo->IpAddressList));
        printf("Gateway List:\n");
        PrintIpAddrs(&(pAdapterInfo->GatewayList));
        printf("DHCP Server List: \n");
		PrintIpAddrs(&(pAdapterInfo->DhcpServer));
		printf("Uses Windows Internet Name Service: %s\n", pAdapterInfo->HaveWins ? "True" : "False");
        if (pAdapterInfo->HaveWins)
        {
            printf("Primary WINS Server: \n");
            PrintIpAddrs(&(pAdapterInfo->PrimaryWinsServer));
            printf("Secondary WINS Server: \n");
            PrintIpAddrs(&(pAdapterInfo->SecondaryWinsServer));
        }
        printf("Lease Obtained: %llu\n", pAdapterInfo->LeaseObtained);
        printf("Lease Lease Expires: %llu\n", pAdapterInfo->LeaseExpires);
        printf("\n");

        pAdapterInfo = pAdapterInfo->Next;
    }

    // END:   //////////////////////////// LAB3: Print Adapter Info (Part 2) ////////////////////////////

cleanup:
    // cleanup
    if (pAdapterInfo)
    {
        free(pAdapterInfo);
    }
    return ret_val;
}
