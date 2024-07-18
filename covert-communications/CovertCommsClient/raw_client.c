//
// Sample: Raw IPv4/IPv6 UDP with IP_HDRINCL option
//
// Files:
//      rawudp.c      - this file
//      iphdr.h       - IPv4, IPv6, and UDP structure definitions
//      resolve.c     - common name resolution routines
//      resolve.h     - header file for common name resolution routines
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
#define IPv4_VERSION        4                           // Version number for IPv4 header
#define DEFAULT_TTL         8                           // default TTL value
#define DNS_PKT_BUFFER_SIZE 2048                        // size of DNS staging buffer
#define DEFAULT_PKTBUF_SIZE 4096                        // initial size of packet staging buffer

#define EXIT_SUCCESS        0                           // process return code on success
#define EXIT_FAILURE        1                           // process return code on failure

#define mk_verlen(ver, size) (uint8_t)(((ver) << 4) | (size / sizeof(uint32_t))) // ip_verlen is 4-bit IP version | 4-bit header length in DWORDs


// structure for holding packet buffer, size, and length
typedef struct _PKTBUF
{
    uint8_t *packet;            // packet staging buffer
    unsigned length;            // length of current packet
    unsigned max_size;          // size of actual buffer
} PKTBUF, *PPKTBUF;


// context structure for communications
typedef struct _LAB_CONTEXT
{
    SOCKET socket;              // open socket for communications with server
    struct addrinfo* src_addr;  // resolved source address
    struct addrinfo* dst_addr;  // resolved destination address
    PKTBUF packetBuf;           // allocated buffer and length for staging packets
    unsigned msgSize;           // length of message to transmit
    unsigned msgIdx;            // current index into message (transmit location)
    uint8_t *msgData;           // data of message to transmit
} LAB_CONTEXT, *PLAB_CONTEXT;

typedef const LAB_CONTEXT* PCLAB_CONTEXT;

inline unsigned MsgRemaining(PCLAB_CONTEXT ctx)
    {
        return ctx->msgSize - ctx->msgIdx;
    }

inline unsigned MsgReadBytes(PLAB_CONTEXT ctx, void *dst, unsigned cnt)
    {
        if (MsgRemaining(ctx) < cnt)
        {
            return 0;
        }
        memcpy(dst, ctx->msgData + ctx->msgIdx, cnt);
        ctx->msgIdx += cnt;
        return cnt;
    }

inline uint8_t MsgReadByte(PLAB_CONTEXT ctx)
    {
        if (MsgRemaining(ctx) < sizeof(uint8_t))
        {
            return 0;
        }
        return ctx->msgData[ctx->msgIdx++];
    }

inline uint16_t MsgReadWord(PLAB_CONTEXT ctx)
    {
        uint16_t tmp = 0;
        if (MsgRemaining(ctx) >= sizeof(uint16_t))
        {
            tmp = *(uint16_t*)&ctx->msgData[ctx->msgIdx];
            ctx->msgIdx += sizeof(uint16_t);
        }
        else if (MsgRemaining(ctx))
        {
            tmp = ctx->msgData[ctx->msgIdx];
            ctx->msgIdx += 1;
        }
        return tmp;
    }

inline uint32_t MsgReadDWord(PLAB_CONTEXT ctx)
    {
        if (MsgRemaining(ctx) < sizeof(uint32_t))
        {
            return 0;
        }
        uint32_t tmp = *(uint32_t*)&ctx->msgData[ctx->msgIdx];
        ctx->msgIdx += sizeof(uint32_t);
        return tmp;
    }

//---------------------------------------------------------------------------------------------------------------------
// Global Variables
//---------------------------------------------------------------------------------------------------------------------
// Note: Was using -sp 0 -sa 127.0.0.1 -dp 12345 -da 127.0.0.1 -f macbeth.txt
const char*                 gSrcAddress = "";           // IP address to send from
const char*                 gDestAddress = "";          // IP address to send to
const char*                 gSrcPort = "";              // port to send from
const char*                 gDestPort = "12345";        // port to send to
const char*                 gFilename = "Macbeth.txt";  // file containing our secret message to send


//---------------------------------------------------------------------------------------------------------------------
// Local Function Declarations
//---------------------------------------------------------------------------------------------------------------------
//
// Function: chksum32()
//
// Description:
//    Calculate a crude checksum of a block of data (catches correct letters in wrong order)
//
uint32_t chksum32(const uint8_t *data, unsigned size);

//
// Function: PrintUsage()
//
// Description:
//    Print usage information and exit.
//
static void PrintUsage();

//
// Function: getFileSize()
//
// Description:
//    Determines size of file from open handle with read access
//
// @param[in] file Open handle to file to get size of
//
static unsigned getFileSize(FILE *file);

//
// Function: Initialize()
//
// Description:
//    Initialize configuration and communications
//
static bool Initialize(LAB_CONTEXT *ctx);

//
// Function: Cleanup()
//
// Description:
//    Cleanup, shutdown, release resources
//
static void Cleanup(LAB_CONTEXT *ctx);

//
// Function: Communicate()
//
// Description:
//    Communicate with server
//
static bool Communicate(LAB_CONTEXT *ctx);

//
// Function: ValidateArgs
//
// Description:
//    Parse the command line arguments and set some global flags to
//    indicate what actions to perform.
//
// @param[in] argc Count of arguments on command line, including argv[0], this exe
// @param[in] argv Command line arguments, including argv[0], this exe
// @return Returns true if arguments parse successfully, else false
//
static bool ValidateArgs(int argc, char **argv);

//
// Function: crc16_accumulate()
//
// Description:
//    Accumulate CRC16 checksum as a 32-bit sum (does not finalize)
//    Note: If more data will be accumulated, make sure no odd number of bytes
//      are sent.
//
// @param[in] data Data to calculate checksum of
// @param[in] size Size of data in bytes
// @return Returns accumulated checksum as 32-bit value
//
static uint32_t crc16_accumulate(const void* data, unsigned size);

//
// Function: crc16_finalize()
//
// Description:
//    Finalize a 16-bit checksum by folding carry bits back in, and taking 1's complement of result
//
// @param[in] sum Accumulated checksum as 32-bit value
// @return Finalized checksum: 1's complement of sum with carry bits folded in
//
static uint16_t crc16_finalize(uint32_t sum);

//
// Function: checksum16
//
// Description:
//    This function calculates the 16-bit one's complement sum
//    for the supplied buffer. This is the checksum used in IPv4
//    headers.
//
// @param[in] data Data to calculate checksum for
// @param[in] size Data size in bytes
// @return Returns CRC16 for the data given
//
static uint16_t checksum16(void* data, int size);

//
// Function: InitIpv4Header
//
// Description:
//    Initialize the IPv4 header with the version, header length,
//    total length, ttl, protocol value, and source and destination
//    addresses, and then calculates the header checksum
//
// @param[out] buf Buffer to build header in
// @param[in] src Source address
// @param[in] dest Destination address
// @param[in] ttl TTL value to initialize header with
// @param[in] proto Protocol value for header
// @param[in] payloadLen Length of packet payload
// @return Returns size of header added (signed in case of need to return error code)
//
static int InitIpv4Header(
    void* buf,
    SOCKADDR* src,
    SOCKADDR* dest,
    uint8_t ttl,
    uint8_t proto,
    unsigned payloadLen
    );

//
// Function: InitUdpHeader
//
// Description:
//    Setup the UDP header which is fairly simple. Grab the ports and
//    stick in the total payload length.
//
// @param[out] buf Buffer to build header in
// @param[in] src Source address
// @param[in] dest Destination address
// @param[in] payloadLen Length of packet payload
// @return Returns size of header added (signed in case of need to return error code)
//
static int InitUdpHeader(
    void* buf,
    SOCKADDR* src,
    SOCKADDR* dest,
    unsigned  payloadLen
    );

//
// Function: ComputeUdpHeaderChecksum
//
// Description:
//    Compute the UDP header checksum.
//
// @param[in] iphdr Pointer to actual packet being calculated
// @param[in] udphdr UDP header to update
// @param[in] payload Packet payload
// @param[in] payloadLen Length of packet payload
//
static uint16_t ComputeUdpHeaderChecksum(
    const IPV4_HDR *iphdr,
    const UDP_HDR* udphdr,
    const void* payload,
    unsigned payloadLen
    );

//
// Function: PacketizeIpv4
//
// Description:
//    This routine takes the data buffer and packetizes it for IPv4/UDP transmission. The completed packet
//    is returned in the packetBuf parameter, including the total length of the packet in packetBuf.length
//
// @param[out] packetBuf Packet buffer to build the packet in
// @param[in] src Source address
// @param[in] dest Destination address
// @param[in] payload Packet payload
// @param[in] payloadLen Length of packet payload
// @return Returns 0 (ERROR_SUCCESS) on success, else an error code
//
static int PacketizeIpv4(
    PKTBUF* packetBuf,
    struct addrinfo* src,
    struct addrinfo* dest,
    uint8_t* payload,
    unsigned payloadLen
    );

//---------------------------------------------------------------------------------------------------------------------
// Begin Code
//---------------------------------------------------------------------------------------------------------------------
//
// Function: CreateSpoofDNSPacket
//
// Description:
//    Create a spoof DNS packet in ctx->packetBuf to encode data to be communicated covertly
//
static bool CreateSpoofDNSPacket(LAB_CONTEXT *ctx)
{
    //
    // Initialize a realistic DNS packet that can be sent as a spoof to hide our communications
    //
    //Set the DNS structure to standard queries
    uint8_t dnsPacketBuffer[512] = { 0 };
    DNS_HEADER* dns = (DNS_HEADER*)dnsPacketBuffer;
    dns->id = htons((uint16_t)GetCurrentProcessId());
    dns->qr = 0; //This is a query
    dns->opcode = 0; //This is a standard query
    dns->aa = 0; //Not Authoritative
    dns->tc = 0; //This message is not truncated
    dns->rd = 1; //Recursion Desired
    dns->ra = 0; //Recursion not available! hey we dont have it (lol)
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1); //we have only 1 question
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;

    // START: ///////////////////// Part 1 - Create a spoof DNS request to encode some data ///////////
    //  For Part 1, hide some of the data in spoof DNS packets.
    //      - the DNS packet must look legit, so don't just slap chunks of payload in as the name
    //        being queried; "Whence camest thou, worthy thane?.com" would be more than a little suspicious
    //        as an Internet url, let alone with line feeds, or possibly non-text payload bytes. Likewise,
    //        "www.megacorp.Whence" would be a poor choice.
    //
    //  Hint: A method has been provided to deal with spaces, linefeeds, and other unwanted bytes by
    //      encoding them.
    //

    // sleep so that client doesn't outpace the host
    Sleep(1);

    char host[MAX_HOST_SIZE] = { 0 };                  // setup the url for your host

    // read and encode the next n bytes, up to ENCODED_BYTES, from the message and store into the hostname
    char readBuf[ENCODED_BYTES] = { 0 };
    unsigned readCount = MsgRemaining(ctx);
    if (readCount > ENCODED_BYTES)
    {
        readCount = ENCODED_BYTES;
    }
    unsigned read = MsgReadBytes(ctx, readBuf, readCount);
    char encodedBuf[ENCODED_LEN] = { 0 };
    unsigned encodedLen = base32_encode((const uint8_t *) readBuf, read, (uint8_t *) encodedBuf, sizeof(encodedBuf));

    strcpy_s(host, sizeof(host), baseHost);

    // replace X's in host name to the encoded characters
    for (unsigned idx = 0; idx < encodedLen; idx++)
    {
        host[hostOffsets[idx]] = encodedBuf[idx];
    }

    // END:   ///////////////////// Part 1 - Create a spoof DNS request to encode some data ///////////

    //
    // add the host name to be queried to the DNS packet
    //
    uint8_t* qname = dnsPacketBuffer + sizeof(DNS_HEADER);
    if (!ChangetoDnsNameFormat(host, qname))
    {
        fprintf(stderr, "Error: ChangetoDnsNameFormat(%s) failed\n", host);
        return false;
    }

    QUESTION* qinfo = (QUESTION*)&dnsPacketBuffer[sizeof(DNS_HEADER) + (strlen((const char*)qname) + 1)];
    qinfo->qtype = htons(1); //we are requesting the ipv4 address
    qinfo->qclass = htons(1); //its internet
    unsigned payloadSize = (unsigned)(sizeof(DNS_HEADER) + (strlen((const char*)qname) + 1) + sizeof(QUESTION));

    //
    // Create an IPv4/UDP packet to allow our DNS query to be sent
    //
    int rc = PacketizeIpv4(&ctx->packetBuf, ctx->src_addr, ctx->dst_addr, dnsPacketBuffer, payloadSize);
    if (rc != ERROR_SUCCESS)
    {
        fprintf(stderr, "Packetizing failed (%d)\n", rc);
        return false;
    }
    return true;
}


//
// Function: ModifyPacketInline
//
// Description:
//    Modify a packet inline to hide data in its headers as from a man-in-the-middle attack
//
static bool ModifyPacketInline(LAB_CONTEXT *ctx)
{
    // get pointer to IPv4 header
    IPV4_HDR* v4hdr = (IPV4_HDR*)ctx->packetBuf.packet;
    // get pointer to UDP header inside IPv4 packet
    UDP_HDR* udphdr = (UDP_HDR*)(ctx->packetBuf.packet + sizeof(IPV4_HDR));
    // get pointer to payload to use when updating the packet checksum
    uint8_t* payload = (ctx->packetBuf.packet + sizeof(IPV4_HDR) + sizeof(UDP_HDR));
    unsigned payloadSize = ntohs(udphdr->udp_length) - sizeof(UDP_HDR);


    // START: //////////////////////////// Part 2 - Hide Data in Packet Header ////////////////////////////
    // We have now intercepted the IPv4 + UDP packet in ctx->packetBuf.packet. Use what you have learned
    // to encode your secret message in pieces across these packets. Don't forget to reset any checksums
    // that were affected

    // encode a byte into the ip identification header field
    /**/
    uint8_t msgByte = MsgReadByte(ctx);
    // if no message byte, fill with 0xFFFF (0 cant be used, IP stack will autofill it)
    if (msgByte == 0)
    {
        unsigned endVal = MAX_16BIT;
        memcpy_s(&(v4hdr->ip_id), 2, &(endVal), 2);
        return true;
    }
    char encodedBuf[ENCODED_LEN] = { 0 };
    unsigned encodedLen = base32_encode(&msgByte, 1, encodedBuf, sizeof(encodedBuf));
    memcpy_s(&(v4hdr->ip_id), 2, encodedBuf, encodedLen);

    // encode a byte into the udp source port header field
    msgByte = MsgReadByte(ctx);
    if (msgByte == 0)
    {
        return true;
    }
    encodedLen = base32_encode(&msgByte, 1, encodedBuf, sizeof(encodedBuf));
    memcpy_s(&(udphdr->src_portno), 2, encodedBuf, encodedLen);
    //v4hdr->ip_id |= htons(0x00BB); // fits 1 more byte of data

    // recalculate checksums
    udphdr->udp_checksum = ComputeUdpHeaderChecksum(v4hdr, udphdr, payload, payloadSize);
    v4hdr->ip_checksum = checksum16(v4hdr, sizeof(IPV4_HDR));


    // END:  //////////////////////////// Part 2 - Hide Data in Packet Header ////////////////////////////

    return true;
}


//---------------------------------------------------------------------------------------------------------------------
// Main Program Code
//---------------------------------------------------------------------------------------------------------------------
//
// Function: main()
//
// Description:
//    First, parse command line arguments and load Winsock. Then
//    create the raw socket and then set the IP_HDRINCL option.
//    Following this assemble the IP and UDP packet headers by
//    assigning the correct values and calculating the checksums.
//    Then fill in the data and send to its destination.
//
int _cdecl main(int argc, char** argv)
{
    LAB_CONTEXT ctx = { 0 };

    // parse command line arguments, sets global config values
    if (!ValidateArgs(argc, argv))
    {
        return EXIT_FAILURE;
    }

    // initialize communications
    if (!Initialize(&ctx))
    {
        Cleanup(&ctx);
        return EXIT_FAILURE;
    }

    int ret_val = EXIT_SUCCESS;
    if (!Communicate(&ctx))
    {
        ret_val = EXIT_FAILURE;
    }

    Cleanup(&ctx);
    return ret_val;
}


/** Initialize configuration and communications */
static bool Initialize(LAB_CONTEXT *ctx)
{
    memset(ctx, 0, sizeof(*ctx));

    // seed random number generator
    #pragma warning(disable: 28159) // disable GetTickCount() rollover warning
    srand(GetTickCount());
    #pragma warning(pop)

    //
    // initialize configuration
    //
    int wsa_rc;
    WSADATA wsd;
    if ((wsa_rc = WSAStartup(MAKEWORD(2, 2), &wsd)) != 0)
    {
        fprintf(stderr, "Error, WSAStartup() failed: %d\n", wsa_rc);
        return false;
    }

    // resolve the source address
    ctx->src_addr = ResolveAddress(gSrcAddress, gSrcPort, AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (ctx->src_addr == NULL)
    {
        fprintf(stderr, "Unable to resolve address '%s' and port '%s'\n", gSrcAddress?gSrcAddress:"<local>", gSrcPort?gSrcPort:"<ephemeral>");
        return false;
    }

    // resolve destination address
    ctx->dst_addr = ResolveAddress(gDestAddress, gDestPort, AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (ctx->dst_addr == NULL)
    {
        fprintf(stderr, "Unable to resolve address '%s' and port '%s'\n", gDestAddress?gDestAddress:"<local>", gDestPort);
        return false;
    }

    PrintAddress("Source Address     : " , ctx->src_addr->ai_addr, ctx->src_addr->ai_addrlen);
    PrintAddress("Destination Address: " , ctx->dst_addr->ai_addr, ctx->dst_addr->ai_addrlen);

    // create socket
    SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock == INVALID_SOCKET)
    {
        fprintf(stderr, "socket failed: %d\n", WSAGetLastError());
        return false;
    }

    // Enable the IP header include option to allow us to build raw packets
    {
        // code block necessary to allow this initialization after goto's
        uint32_t optval = 1;
        int rc = setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char*)&optval, sizeof(optval));
        if (rc == SOCKET_ERROR)
        {
            fprintf(stderr, "setsockopt: IP_HDRINCL failed: %d\n", WSAGetLastError());
            return false;
        }
        ctx->socket = sock;
    }

    //
    // load payload file
    //
    // open the payload text file
    FILE *fp = NULL;
    fopen_s(&fp, gFilename, "r");
    if (fp == NULL) {
        fprintf(stderr, "Error: Could not open file to read (%s) (%lu)\n", gFilename, GetLastError());
        return false;
    }
    unsigned size = getFileSize(fp);
    ctx->msgData = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    if (ctx->msgData == NULL)
    {
        fprintf(stderr, "Error: Memory allocation failed (%lu)\n", GetLastError());
        return false;
    }
    size_t nbytes = fread_s(ctx->msgData, size, 1, size, fp);
    ctx->msgIdx = 0;
    ctx->msgSize = (unsigned)nbytes;
    fclose(fp);

    printf("Message CRC: %08X (size: %u)\n", chksum32(ctx->msgData, ctx->msgSize), ctx->msgSize);
    return true;
}


/** Cleanup, shutdown, release resources */
static void Cleanup(LAB_CONTEXT *ctx)
{
    if (ctx->src_addr)
    {
        freeaddrinfo(ctx->src_addr);
        ctx->src_addr = NULL;
    }

    if (ctx->dst_addr)
    {
        freeaddrinfo(ctx->dst_addr);
        ctx->dst_addr = NULL;
    }
    // free the packet buffer
    if (ctx->packetBuf.packet != NULL)
    {
        HeapFree(GetProcessHeap(), 0, ctx->packetBuf.packet);
        ctx->packetBuf.packet = NULL;
    }

    if (ctx->socket)
    {
        closesocket(ctx->socket);
        ctx->socket = 0;
    }

    if (ctx->msgData)
    {
        HeapFree(GetProcessHeap(), 0, ctx->msgData);
        ctx->msgData = NULL;
        ctx->msgIdx = 0;
        ctx->msgSize = 0;
    }

    WSACleanup();
}


/** Communicate with server */
static bool Communicate(LAB_CONTEXT *ctx)
{
    while (MsgRemaining(ctx))
    {
        // Create a spoof DNS packet in ctx->packetBuf to encode data to be communicated covertly
        if (!CreateSpoofDNSPacket(ctx))
        {
            return false;
        }

        // Modify a packet inline to hide data in its headers as from a man-in-the-middle attack
        if (!ModifyPacketInline(ctx))
        {
            return false;
        }

        // Send the packet to the server
        int rc = sendto(ctx->socket, (const char*)ctx->packetBuf.packet, ctx->packetBuf.length, 0, ctx->dst_addr->ai_addr, (int)ctx->dst_addr->ai_addrlen);
        if (rc == SOCKET_ERROR)
        {
            fprintf(stderr, "Error, sendto() failed: %d\n", WSAGetLastError());
            return false;
        }

        // Print when we start sending
        static bool logged = false;
        if (!logged)
        {
            logged = true;
            printf("Sending %s...\n", gFilename);
        }
    }
    printf("All data sent successfully\n");
    return true;
}


//---------------------------------------------------------------------------------------------------------------------
// Utility Functions
//---------------------------------------------------------------------------------------------------------------------
/** Calculate a crude checksum of a block of data (catches correct letters in wrong order) */
uint32_t chksum32(const uint8_t *data, unsigned size)
{
    uint32_t chksum = 0;
    // for each byte, roll the current checksum 2 left then add value
    for (unsigned idx = 0; idx < size; idx++)
    {
        chksum = (((chksum&0x80000000)?1:0) | (chksum << 1)) + *data++;
    }
    return chksum;
}

/** Print usage information and exit. */
static void PrintUsage()
{
    printf("Usage: CovertCommsClient [-sp int] [-sa str] [-dp int] [-da str]\n"
            "    -sa addr   From (sender) IP address (default: local)\n"
            "    -sp int    From (sender) port number (default: any)\n"
            "    -da addr   To (recipient) IP address (default: local)\n"
            "    -dp int    To (recipient) port number (default: %s)\n"
            "    -f  str    File containing our secret message to send (default: %s)\n",
            gDestPort, gFilename);
}


/** Determines size of file from open handle with read access */
static unsigned getFileSize(FILE *file)
{
    long original_loc = ftell(file);
    if (original_loc == -1)
    {
        fprintf(stderr, "getFileSize: ftell() failed (%d)\n", errno);
        return 0;
    }
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    if (size == -1)
    {
        fprintf(stderr, "getFileSize: ftell(b) failed (%d)\n", errno);
        size = 0;
    }
    fseek(file, original_loc, SEEK_SET);
    return size;
}



/** Parse the command line arguments and set some global flags to indicate what actions to perform. */
static bool ValidateArgs(int argc, char **argv)
{
    for (unsigned idx = 1; idx < (unsigned)argc; idx++)
    {
        if ((argv[idx][0] != '-') && (argv[idx][0] != '/'))
        {
            fprintf(stderr, "Unexpected argument %u: %s\n", idx, argv[idx]);
            PrintUsage();
            return false;
        }
        switch (argv[idx][1])
        {
        case '?': // for -? or -h, just show usage string and exit
        case 'h':
        case 'H':
            PrintUsage();
            return false;
        }
        if (idx + 1 >= (unsigned)argc)
        {
            fprintf(stderr, "Error: '%s' requires a value\n", argv[idx]);
            PrintUsage();
            return false;
        }
        switch (tolower(argv[idx][1]))
        {
        case 's': // source address
            if (tolower(argv[idx][2]) == 'a')
            {
                gSrcAddress = argv[++idx];
            }
            else if (tolower(argv[idx][2]) == 'p')
            {
                gSrcPort = argv[++idx];
            }
            else
            {
                fprintf(stderr, "Error, unknown argument %u: %s\n", idx, argv[idx]);
                PrintUsage();
                return false;
            }
            break;
        case 'd': // destination address
            if (tolower(argv[idx][2]) == 'a')
            {
                gDestAddress = argv[++idx];
            }
            else if (tolower(argv[idx][2]) == 'p')
            {
                gDestPort = argv[++idx];
            }
            else
            {
                fprintf(stderr, "Error, unknown argument %u: %s\n", idx, argv[idx]);
                PrintUsage();
                return false;
            }
            break;
        case 'f':
            ++idx;
            gFilename = argv[idx];
            break;
        default:
            PrintUsage();
            return false;
        }
    }
    return true;
}


/** Accumulate CRC16 checksum as a 32-bit sum (does not finalize) */
static uint32_t crc16_accumulate(const void* data_in, unsigned size)
{
    uint32_t cksum = 0;
    const uint8_t* data = (const uint8_t*)data_in;

    while (size >= sizeof(uint16_t))
    {
        cksum += *(uint16_t*)data;
        data += sizeof(uint16_t);
        size -= sizeof(uint16_t);
    }
    // if the buffer was not a multiple of 16-bits, add the last byte
    if (size)
    {
        cksum += *(uint8_t*)data;
    }
    return cksum;
}

/** Finalize a 16-bit checksum by folding carry bits back in, and taking 1's complement of result */
static uint16_t crc16_finalize(uint32_t sum)
{
    // fold carryover back in until none exists
    while ((sum >> 16) > 0)
    {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }

    // take the 1's complement of the result
    return (uint16_t)(~sum);
}


/** This function calculates the 16-bit one's complement sum for the supplied buffer. This is the checksum used in IPv4 headers. */
static uint16_t checksum16(void* data, int size)
{
    return crc16_finalize(crc16_accumulate(data, size));
}


/** Initialize the IPv4 header with the version, header length, total length, ttl, protocol value, and source and destination addresses, and then calculates the header checksum */
static int InitIpv4Header(
    void* buf,
    SOCKADDR* src,
    SOCKADDR* dest,
    uint8_t ttl,
    uint8_t proto,
    unsigned payloadLen
    )
{
    IPV4_HDR* v4hdr = (IPV4_HDR*)buf;

    v4hdr->ip_verlen = mk_verlen(IPv4_VERSION, sizeof(IPV4_HDR));   // 4-bit IPv4 version | 4-bit header length (in 32-bit words)
    v4hdr->ip_tos = 0;                                              // IP type of service
    v4hdr->ip_totallength = htons(sizeof(IPV4_HDR) + (uint16_t)payloadLen); // total length of packet, in nbo (BE)
    v4hdr->ip_id = 0;
    v4hdr->ip_offset = 0;
    v4hdr->ip_ttl = ttl;
    v4hdr->ip_protocol = proto;
    v4hdr->ip_checksum = 0;
    v4hdr->ip_srcaddr = ((SOCKADDR_IN*)src)->sin_addr.s_addr;
    v4hdr->ip_destaddr = ((SOCKADDR_IN*)dest)->sin_addr.s_addr;
    v4hdr->ip_checksum = checksum16(v4hdr, sizeof(IPV4_HDR));
    return sizeof(IPV4_HDR);
}


/** Setup the UDP header which is fairly simple. Grab the ports and stick in the total payload length. */
static int InitUdpHeader(
    void* buf,
    SOCKADDR* src,
    SOCKADDR* dest,
    unsigned  payloadLen
    )
{
    UDP_HDR* udphdr = (UDP_HDR*)buf;

    // Port numbers are already in network byte order

    udphdr->src_portno = ((SOCKADDR_IN*)src)->sin_port;
    udphdr->dst_portno = ((SOCKADDR_IN*)dest)->sin_port;
    udphdr->udp_length = htons(sizeof(UDP_HDR) + (uint16_t)payloadLen);
    return sizeof(UDP_HDR);
}


/** Compute the UDP header checksum. */
static uint16_t ComputeUdpHeaderChecksum(
    const IPV4_HDR* iphdr,
    const UDP_HDR* udphdr,
    const void* payload,
    unsigned payloadLen
    )
{
    uint32_t checksum = 0;

    // The UDP checksum is based on the following fields:
    //       o source IP address
    checksum += crc16_accumulate(&iphdr->ip_srcaddr, sizeof(iphdr->ip_srcaddr));
    //       o destination IP address
    checksum += crc16_accumulate(&iphdr->ip_destaddr, sizeof(iphdr->ip_destaddr));
    //       o 8-bit zero field and 8-bit protocol field
    uint8_t buf[] = { 0, iphdr->ip_protocol };
    checksum += crc16_accumulate(buf, sizeof(buf));
    //       o 16-bit UDP length
    checksum += crc16_accumulate(&udphdr->udp_length, sizeof(udphdr->udp_length));
    //       o 16-bit source port
    checksum += crc16_accumulate(&udphdr->src_portno, sizeof(udphdr->src_portno));
    //       o 16-bit destination port
    checksum += crc16_accumulate(&udphdr->dst_portno, sizeof(udphdr->dst_portno));
    //       o 16-bit UDP packet length
    checksum += crc16_accumulate(&udphdr->udp_length, sizeof(udphdr->udp_length));
    //       o 16-bit UDP checksum (zero)
    uint16_t udp_checksum = 0;
    checksum += crc16_accumulate(&udp_checksum, sizeof(udp_checksum));
    //       o UDP payload (padded to the next 16-bit boundary)
    checksum += crc16_accumulate(payload, payloadLen);
    return crc16_finalize(checksum);
}


/** This routine takes the data buffer and packetizes it for IPv4/UDP transmission. */
static int PacketizeIpv4(
    PKTBUF* packetBuf,
    struct addrinfo* src,
    struct addrinfo* dest,
    uint8_t* payload,
    unsigned payloadLen
    )
{
    // Check the parameters
    if ((packetBuf == NULL) || (src == NULL) ||
        (dest == NULL) || (payload == NULL))
    {
        return WSAEINVAL;
    }

    // Allocate memory for the packet
    packetBuf->length = sizeof(IPV4_HDR) + sizeof(UDP_HDR) + payloadLen;
    if (packetBuf->packet && packetBuf->length > packetBuf->max_size)
    {
        HeapFree(GetProcessHeap(), 0, packetBuf->packet);
        packetBuf->packet = NULL;
    }
    if (packetBuf->packet == NULL)
    {
        if (packetBuf->length <= DEFAULT_PKTBUF_SIZE)
        {
            packetBuf->max_size = DEFAULT_PKTBUF_SIZE;
        }
        else
        {
            packetBuf->max_size = (packetBuf->length * 15) / 10;
        }
        packetBuf->packet = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, packetBuf->max_size);
        if (packetBuf->packet == NULL)
        {
            fprintf(stderr, "PacketizeIpv4: HeapAlloc(%u) failed: %lu\n", packetBuf->max_size, GetLastError());
            return GetLastError();
        }
    }

    IPV4_HDR* iphdr = (IPV4_HDR *)packetBuf->packet;
    UDP_HDR* udphdr = (UDP_HDR*)(packetBuf->packet + sizeof(IPV4_HDR));

    // Initialize the v4 header
    int iphdrlen = InitIpv4Header(
        iphdr,
        src->ai_addr,
        dest->ai_addr,
        DEFAULT_TTL,
        IPPROTO_UDP,
        sizeof(UDP_HDR) + payloadLen
        );

    // Initialize the UDP header
    int udphdrlen = InitUdpHeader(
        udphdr,
        src->ai_addr,
        dest->ai_addr,
        payloadLen
        );

    // copy the payload to the end of the header
    memcpy(&packetBuf->packet[iphdrlen + udphdrlen], payload, payloadLen);

    // Compute the UDP checksum
    udphdr->udp_checksum = ComputeUdpHeaderChecksum(iphdr, udphdr, payload, payloadLen);
    return NO_ERROR;
}
