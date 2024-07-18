//
// Description:
//    This is a simple app that demonstrates the usage of the
//    IP_HDRINCL socket option. A raw socket is created of the
//    UDP protocol where we will build our own IP and UDP header
//    that we submit to sendto().
//
//    For IPv4 this is fairly simple. Create a raw socket, set the
//    IP_HDRINCL option, build the IPv4 and UDP headers, and do a
//    sendto. The IPv4 stack will fragment the data as necessary and
//    generally leaves the packet unmodified -- it performs fragmentation
//    and sets the IPv4 ID field.
//
//    For IPv6 its a bit more involved as it does not perform any
//    fragmentation, you have to do it and build the headers yourself.
//
//    The IP_HDRINCL option only works on Windows 2000 or greater.
//
// NOTE:
//    From Network Programming for Microsoft Windows, Second Edition
//    by Anthony Jones and James Ohlund.  Copyright 2002.
//    Reproduced by permission of Microsoft Press.  All rights reserved.
//
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#pragma warning(push)
#pragma warning(disable: 4127)

#include <winsock2.h>
#include <ws2tcpip.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "iphdr.h"
#include "resolve.h"
#include "dns.h"
#include "base32.h"

//---------------------------------------------------------------------------------------------------------------------
// Definitions and Structures
//---------------------------------------------------------------------------------------------------------------------
#define MAX_PACKET          (0xFFFF + sizeof(IPV4_HDR)) // maximum datagram size
#define RCV_TIMEOUT         4000                        // once receive begins, timeout after 4s without new data

#define EXIT_SUCCESS        0                           // process return code on success
#define EXIT_FAILURE        1                           // process return code on failure

//---------------------------------------------------------------------------------------------------------------------
// Global Variables
//---------------------------------------------------------------------------------------------------------------------
const char* gPort = "12345";

static uint8_t rcvBuffer[MAX_PACKET];                   // buffer for storing received data (used by ReceiveData() and PrintReceivedData())
static unsigned rcvIndex = 0;                           // current location in rcvBuffer
static uint32_t rcvChecksum = 0;                        // simple 32-bit checksum of received data
static unsigned rcvTotal = 0;                           // total bytes received

//---------------------------------------------------------------------------------------------------------------------
// Local Utility Function Declarations
//---------------------------------------------------------------------------------------------------------------------
//
// Function: validPort()
//
// Description:
//    Verify that a string has a valid port number in it (alldigits())
//
bool validPort(const char* str);

//
// Function: SetSocketTimeout()
//
// Description:
//    Set the receive timeout on a socket
//
void SetSocketTimeout(SOCKET socket, uint32_t ms);

//
// Function: ReceiveData()
//
// Description:
//    Accumulate decoded data for processing. For this lab, all this does is accumulate the data and keep a checksum
//    for final verification
//
static void ReceiveData(uint8_t* data, unsigned len);

//
// Function: PrintReceivedData
//
// Description:
//    Print any data accumulated to the console
//
static void PrintReceivedData();

//---------------------------------------------------------------------------------------------------------------------
// Begin Code
//---------------------------------------------------------------------------------------------------------------------
//
// Function: IsOurPacket
//
// Description:
//    Inspect a received packet to see if it is one of ours
//
static bool IsOurPacket(uint8_t* packet)
{
    IPV4_HDR* ip_hdr = (IPV4_HDR*)packet;

    // START: //////////////////////////// Filter - Only Want Our Packets ////////////////////////////
    //  Inspect a received packet to see if it is one of ours, such as:
    //      - Broadcast packets (IP header ip_destaddr is a broadcast address)
    //      - Inspection shows not IPv4 + UDP + DNS
    //      - Any flag you may have set on client side to identify your packet
    //

    // filter out broadcast packets / check if last octet is all set bits (255 decimal)
    if ((ntohs(ip_hdr->ip_destaddr) & 0x000000FF) == 0xFF)
    {
        return false;
    }

    // jump into qname to verify portions of the standard host name
    // + 1 on qname to account for first length byte
    uint8_t* qname = packet + sizeof(IPV4_HDR) + sizeof(UDP_HDR) + sizeof(DNS_HEADER);
    if (qname[BASEHOST_OFFSET + 1] != baseHost[BASEHOST_OFFSET] || qname[(BASEHOST_OFFSET + 1) + 1] != baseHost[BASEHOST_OFFSET + 1])
    {
        return false;
    }

    // END:   //////////////////////////// Filter - Only Want Our Packets ////////////////////////////
    return true;
}


//
// Function: ExtractDNSMessage()
//
// Description:
//    Extract and Decode DNS Request message
//
static bool ExtractDNSMessage(uint8_t* packet)
{
    DNS_HEADER* dns = (DNS_HEADER*)(packet + sizeof(UDP_HDR) + sizeof(IPV4_HDR));

    uint8_t host[MAX_HOST_SIZE];
    ReadName((uint8_t*)dns + sizeof(DNS_HEADER), (uint8_t*)dns, host, sizeof(host));
    if (!host[0])
    {
        fprintf(stderr, "Error, ReadName() failed\n");
        return false;
    }

    // START: //////////////////////////// Part 1 - Extract and Decode DNS Request Message /////////////////
    // place your code here to extract anything hidden in the DNS request and pass it to ReceiveData()

    // copy from predesignated offsets in the host name into a buffer to be decoded
    uint8_t encodedBuf[ENCODED_LEN] = { 0 };
    for (unsigned idx = 0; idx < sizeof(encodedBuf); idx++)
    {
        // break out if template name's placeholder char is found (no more data encoded)
        if (host[hostOffsets[idx]] == BASEHOST_PLACEHOLDER)
        {
            break;
        }
        encodedBuf[idx] = host[hostOffsets[idx]];
    }

    // decode the buffer and pass on the data for further processing
    uint8_t decodedBuf[ENCODED_BYTES] = { 0 };
    unsigned decodedLen = base32_decode(encodedBuf, decodedBuf, sizeof(decodedBuf));

    ReceiveData(decodedBuf, decodedLen);

    // END:   //////////////////////////// Part 1 - Extract and Decode DNS Request Message /////////////////

    return true;
}


//
// Function: ExtractHeaderMessage()
//
// Description:
//    Extract and decode message we hid in headers of an existing packet
//
static bool ExtractHeaderMessage(uint8_t* packet)
{
    const IPV4_HDR* ip_hdr = (const IPV4_HDR*)packet;
    const UDP_HDR* udphdr = (const UDP_HDR*)(packet + sizeof(IPV4_HDR));

    // START: //////////////////////////// Part 2 - Extract and Decode Message Hidden in Header ////////////////////////////
    // place your code here to extract anything hidden in the IP/UDP Headers and pass it to ReceiveData()

    // decode and receive a byte from the ip id header field
    uint8_t encodedBuf[ENCODED_LEN] = { 0 };
    if (ip_hdr->ip_id == MAX_16BIT)
    {
        return true;
    }
    memcpy_s(encodedBuf, sizeof(encodedBuf), &(ip_hdr->ip_id), 2);
    uint8_t decodedBuf[ENCODED_BYTES] = { 0 };
    unsigned decodedLen = base32_decode(encodedBuf, decodedBuf, sizeof(decodedBuf));
    ReceiveData(decodedBuf, decodedLen);

    // decode and receive a byte from the udp source port header field
    if (udphdr->src_portno == 0)
    {
        return true;
    }
    memcpy_s(encodedBuf, sizeof(encodedBuf), &(udphdr->src_portno), 2);
    // decode the buffer and pass on the data for further processing
    decodedLen = base32_decode(encodedBuf, decodedBuf, sizeof(decodedBuf));
    ReceiveData(decodedBuf, decodedLen);

    // END:   //////////////////////////// Part 2 - Extract and Decode Message Hidden in Header ////////////////////////////
    return true;
}


//---------------------------------------------------------------------------------------------------------------------
// Main Program Code
//---------------------------------------------------------------------------------------------------------------------
//
// Function: PrintUsage()
//
// Description:
//    Print usage information and exit.
//
void PrintUsage()
{
    printf("Usage: CovertCommsServer [port]\n"
           "    port - The port to bind to (default = 12345)\n");
}


//
// Function: ValidateArgs
//
// Description:
//    Parse the command line arguments and set some global flags to
//    indicate what actions to perform.
//
bool ValidateArgs(int argc, char **argv)
{
    bool portSet = false;

    // step through args, make sure port is given
    for (unsigned idx = 1; idx < (unsigned)argc; idx++)
    {
        if (!portSet && validPort(argv[idx]))
        {
            portSet = true;
            gPort = argv[idx];
            continue;
        }
        PrintUsage();
        return false;
    }
    return true;
}


//
// Function: main()
//
// Description:
//    Program main entry point
//
int _cdecl main(int argc, char** argv)
{
    int ret_val = EXIT_FAILURE;

    // Parse command line arguments and print them out
    if (!ValidateArgs(argc, argv))
    {
        return EXIT_FAILURE;
    }

    #pragma warning(disable: 28159) // disable GetTickCount() rollover warning
    srand(GetTickCount());
    #pragma warning(pop)
    printf("Listening on localhost:%s....\n", gPort);

    int wsa_rc;
    WSADATA wsd;
    if ((wsa_rc = WSAStartup(MAKEWORD(2, 2), &wsd)) != 0)
    {
        fprintf(stderr, "Error, WSAStartup() failed: %d\n", wsa_rc);
        return EXIT_FAILURE;
    }

    SOCKET sock = INVALID_SOCKET;
    uint8_t* buffer = NULL;
    struct addrinfo *ressrc = ResolveAddress("", gPort, AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (ressrc == NULL)
    {
        fprintf(stderr, "ResolveAddress('', '%s') failed\n", gPort);
        goto cleanup;
    }

    sock = socket(ressrc->ai_family, SOCK_RAW, ressrc->ai_protocol);

    if (sock == INVALID_SOCKET)
    {
        fprintf(stderr, "socket failed: %d\n", WSAGetLastError());
        goto cleanup;
    }

    // Bind the socket to the receiving address
    int rc = bind(sock, ressrc->ai_addr, (int)ressrc->ai_addrlen);
    if (rc == SOCKET_ERROR)
    {
        fprintf(stderr, "bind failed: %d\n", WSAGetLastError());
        goto cleanup;
    }

    PrintAddress("Binding to: ", ressrc->ai_addr, ressrc->ai_addrlen);

    // Allocate a buffer for computing the pseudo header checksum
    buffer = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, MAX_PACKET);
    if (buffer == NULL)
    {
        fprintf(stderr, "HeapAlloc failed: %d\n", GetLastError());
        goto cleanup;
    }

    // Receive the raw IP level packets off the wire
    while (true)
    {
        SOCKADDR_STORAGE    safrom = { 0 };
        int fromlen = sizeof(safrom);
        unsigned msglen = recvfrom(sock, (char*)buffer, MAX_PACKET, 0, (SOCKADDR*)&safrom, &fromlen);
        if ((int)msglen <= 0)
        {
            // exit successful on receive timeout
            if (WSAGetLastError() == WSAETIMEDOUT)
            {
                break;
            }
            fprintf(stderr, "recvfrom failed: %d\n", WSAGetLastError());
            goto cleanup;
        }

        // skip anything that is not our packet
        if (!IsOurPacket(buffer))
        {
            continue;
        }

        // once receive begins, set socket to timeout quickly
        {
            static bool receive_in_progress = false;
            if (!receive_in_progress)
            {
                receive_in_progress = true;
                SetSocketTimeout(sock, RCV_TIMEOUT);
            }
        }

        // extract and decode message we hid in spoofed DNS packet
        if (!ExtractDNSMessage(buffer))
        {
            goto cleanup;
        }

        // extract and decode message we hid in headers of an existing packet
        if (!ExtractHeaderMessage(buffer))
        {
            goto cleanup;
        }

        // print everything decoded from this packet
        PrintReceivedData();
    }
    // Expected results:
    //    Message CRC: 0C6D8EED (size: 100095)
    #define MACBETH_CHECKSUM 0x0C6D8EED
    if (rcvChecksum == MACBETH_CHECKSUM)
    {
        printf("\nSecret message received correctly!\nMessage CRC: %08X (size: %u)\n", rcvChecksum, rcvTotal);
        ret_val = EXIT_SUCCESS;
    }
    else
    {
        printf("\nErrors in message received\nMessage CRC: %08X (size: %u)\n", rcvChecksum, rcvTotal);
    }

cleanup:
    //
    // Cleanup allocations and sockets
    //
    if (ressrc)
    {
        freeaddrinfo(ressrc);
    }

    if (buffer)
    {
        HeapFree(GetProcessHeap(), 0, buffer);
    }

    if (sock != INVALID_SOCKET)
    {
        closesocket(sock);
    }

    WSACleanup();
    return ret_val;
}


//---------------------------------------------------------------------------------------------------------------------
// Local Utility Functions
//---------------------------------------------------------------------------------------------------------------------
/** Verify that a string has a valid port number in it (alldigits()) */
bool validPort(const char* str)
{
    if (str == NULL || !isdigit(*str))
    {
        return false;
    }
    while (*++str)
    {
        if (!isdigit(*str))
        {
            return false;
        }
    }
    return true;
}


/** Set the receive timeout on a socket */
void SetSocketTimeout(SOCKET socket, uint32_t ms)
{
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&ms, sizeof(ms));
}


/** Accumulate decoded data for processing. For this lab, all this does is accumulate the data and keep a checksum for
    final verification */
static void ReceiveData(uint8_t* data, unsigned len)
{
    for (unsigned idx = 0; idx < len; idx++)
    {
        // just stop receiving if the buffer ever fills up, but the buffer is 64K, and the most encoded in a packet will
        //  only be a dozen or so bytes.
        if (rcvIndex + 5 > sizeof(rcvBuffer))
        {
            break;
        }
        uint8_t chr = *data++;
        // accumulate crude checksum
        rcvChecksum = (((rcvChecksum&0x80000000)?1:0) | (rcvChecksum << 1)) + chr;
        rcvTotal++;
        if (!isprint(chr) && !isspace(chr))
        {
            sprintf_s((char*)rcvBuffer + rcvIndex, 5, "\\x%02X", chr);
            rcvIndex += 4;
        }
        else
        {
            rcvBuffer[rcvIndex++] = chr;
        }
    }
}

/** Print any data accumulated to the console */
static void PrintReceivedData()
{
    rcvBuffer[rcvIndex] = 0;
    printf((char*)rcvBuffer);
    rcvIndex = 0;
}
