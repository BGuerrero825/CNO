//-------------------------------------------------------------------------------------------------
// SystemScanRaw.cpp
//
// Port scan logic for System Surveys
//-------------------------------------------------------------------------------------------------
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>

#include <stdio.h>
#include <stdlib.h>
#include <iphlpapi.h>
#include <pcap.h>
#include <memory.h>
#include <stdint.h>
#include <stdbool.h>

#include <set>
#include <vector>
#include <string>

#include "iphdr.h"
#include "resolve.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#pragma warning(push)
#pragma warning(disable: 28159)     // don't warn on calls to GetTickCount()
#pragma warning(disable: 4505)      // don't warn that static function GetDefaultGateway() is unused

using namespace std;

//
// Adjust any of the following values to control the operation of your labs (e.g. min/max port). Change PART1 to false when you
//  begin working on Part2.
//
// START: //////////////////////////// SETTINGS  ////////////////////////////
#define PART1 false                     // working on Part1 (else part2)
#define PART2 (!PART1)

#define PART1_TARGET_IP LOOPBACK_NBO        // Target IP for Part1 (port scan local system). Loopback is fine, but feel free to experiment
//#define PART1_TARGET_IP 0x2B56A8C0           // "192.168.86.43" in hex NBO

#define SOURCE_PORT 34567                   // arbitrary source port for scan
#define MIN_PORT    1                       // port range to scan
#define MAX_PORT    1024                    // 1024 is generally high enough to see this work, but full scan would use 65535

#define CLOSED_FILTERED_DISPLAY_MAX 10      // number of closed or filtered ports to display per device before squelching notifications

// END:   //////////////////////////// SETTINGS ////////////////////////////


//-------------------------------------------------------------------------------------------------
// Definitions and defaults
//-------------------------------------------------------------------------------------------------
#define DEFAULT_TTL         54                          // default TTL value
#define MAX_PACKET          (0xFFFF + sizeof(IPV4_HDR)) // maximum datagram size
#define PACKET_SIZE         2048                        // size of our packet staging buffer
#define MAC_SIZE            8                           // size of a mac address
#define NETMASK_24_NBO      0x00FFFFFF                  // netmask for 24 bits in NBO (i.e. 255.255.255.0)
#define LOOPBACK_NBO        0x0100007F                  // loopback address (127.0.0.1) in hex network byte order (BE)
#define LOOPBACK_SUBNET     0x0000007F                  // loopback network address (127.0.0.0) in hex network byte order (BE)
#define LOOPBACK_NETMASK    0x000000FF                  // netmask for loopback (8 bits)
#define LOOPBACK_DOTTED_IP  "127.0.0.1"                 // dotted IP string for loopback
#define MULTICAST_SUBNET    0x000000E0                  // multicast subnet (224.0.0.0 - 239.255.255.255) in hex network byte order (BE)
#define MULTICAST_NETMASK   0x000000F0                  // multicast subnet netmask
#define GLOBAL_BROADCAST    0xFFFFFFFF                  // global broadcast address
#define LOOPBACK_DOTTED_IP  "127.0.0.1"                 // dotted IP string for loopback

#define IPV4_ADDR_STR_SIZE  16                          // size of buffer needed for dotted IPv4 string (e.g. "10.10.10.1")

#define NPCAP_PATH          L"\\Npcap"                  // name of npcap folder under System32
#define NPCAP_PATH_LEN      6                           // length of npcap folder name

#define BSD_LOOPBACK_IPV4   2                           // value for loopback header indicating IPv4 traffic (https://www.tcpdump.org/linktypes.html)
#define ETHER_TYPE_IPV4     0x0800                      // ethernet frame (ETHER_HDR) type indicating IPv4 packet (https://en.wikipedia.org/wiki/EtherType)

#define ON_SUBNET(ip, subnet, netmask)  ((uint32_t)((ip) & (netmask)) == (uint32_t)(subnet))        // network portion of address matches subnet address
#define IS_BROADCAST(ip, netmask)       ((uint32_t)((ip) & ~(netmask)) == (uint32_t)~(netmask))     // all address bits are on (~netmask == address bits mask)
#define IS_LOOPBACK(ip)                 ON_SUBNET((ip), LOOPBACK_SUBNET, LOOPBACK_NETMASK)

//-------------------------------------------------------------------------------------------------
// Global Variables
//-------------------------------------------------------------------------------------------------
char pcap_errbuf[PCAP_ERRBUF_SIZE];     // buffer to pass to various pcap calls for error messages

uint32_t deviceToScan = 0;              // specific device to scan, if selected from command line


//-------------------------------------------------------------------------------------------------
// Local Function Declarations
//-------------------------------------------------------------------------------------------------
/**
 * @brief Extend system DLL path to include npcap folder (System32\Npcap)
 *
 * @return Returns true on success, false on failure
 */
bool LoadNpcapDlls();


/**
 * @brief Queries the MAC address for a destination IP
 *
 * @param[in] ip IP to get mac address for
 * @param[out] mac Buffer to return MAC in (should be MAC_SIZE bytes)
 *
 * @return Returns true on success, false on failure
*/
bool GetMacAddress(uint32_t ip, uint8_t* mac);


/**
 * @brief Query and return information defining the IP gateway (IPv4) for the current system (UNUSED)
 *
 * @remark This is unused, but left for informational purposes
 *
 * @param[out] ip Variable to return the IPv4 address of the interface (NBO)
 * @param[out] gatewayip Variable to return the interface's gateway's IPv4 address (NBO)
 * @param[out] subnetmask Variable to return the subnet mask in (NBO)
 *
 * @return Returns true if it successfully retrieves gateway info
*/
static bool GetDefaultGateway(uint32_t& ip, uint32_t& gatewayip, uint32_t& subnetmask);


/**
 * @brief Select the interface to use for sending our packets
 *
 * @param[in] devList List of all devices on system
 * @param[in] loopback Automatically select the loopback adapter
 *
 * @return Returns a pointer to the selected interface's device structure, or null on failure
 */
const pcap_if_t* SelectInterface(const pcap_if_t* devList, bool loopback);


/**
 * @brief Calculate an IPv4 header for the buffer given
 *
 * @param[in] buffer Data to calculate CRC for
 * @param[in] size Data size, in bytes
 */
uint16_t checksum(const void* buffer, unsigned size);


/**
 * @brief Increment a network byte order value (e.g. tcp_seq_num)
 *
 * @param value NBO value to increment
 * @param inc   Optional amount to increment by (default 1)
 *
 * @return Returns incremented NBO value
*/
uint32_t inc_nbo32(uint32_t value, uint8_t inc = 1);


/**
 * @brief Returns true if device is the loopback device (cannot be determined via dev->addresses)
 */
bool isLoopbackDevice(const pcap_if_t* dev);


/**
 * @brief Convert IPv4 address in NBO to dotted string (can be used inline for quick string conversion)
 *
 * @param ip NBO IPv4 address to convert (e.g. 0x0100007F => "127.0.0.1")
 * @param buffer Buffer to place dotted string in. Must be at least 16 bytes (IPV4_ADDR_STR_SIZE)
 *
 * @return Returns the dotted format string for ip
 */
const char* iptostr(uint32_t ip, char* buffer);


/**
 * @brief Parse an IPv4 dotted format string, and return the NBO IP address (or 0 on failure)
 */
unsigned parse_ip(const char* ipstr);


/**
 * @brief Find IPv4 address info, if any, in pcap address list
 *
 * @param addresses PCAP address list
 *
 * @return Returns pointer to IPv4 address info, or null if none found
 */
const pcap_addr* pcap_findipv4(const pcap_addr* addresses);


/**
 * @brief Extract the IPv4 address and other values from a pcap address list
 *
 * @param[in] addresses PCAP address list
 * @param[out] ip Return of IPv4 address (of device)
 * @param[out] netmask Optional return of IPv4 netmask
 * @param[out] broadcast Optional return of IPv4 broadcast address
 * @param[out] dest Optional return of IPv4 destination address
 *
 * @return Returns true if some information was found, false if no IPv4 info was found
 */
bool GetIPv4Info(const pcap_addr* addresses, uint32_t& ip, uint32_t* netmask = nullptr, uint32_t* broadcast = nullptr, uint32_t* dest = nullptr);


/**
 * @brief Create the link layer header for ethernet or loopback
 *
 * @param[out] packet Packet staging buffer
 * @param[in] useEtherHdr Build ethernet header, else build loopback header
 * @param[in] src_mac Local MAC address (only needed for ethernet headers)
 * @param[in] dst_mac Target MAC address (only needed for ethernet headers)
 *
 * @return Returns size of link header in bytes. Additional headers should follow this.
 */
unsigned CreateLinkHeader(void* packet, bool useEtherHdr, uint8_t* src_mac, uint8_t* dst_mac);


/**
 * @brief Initialize an IPv4 packet header
 *
 * @param[out] buf Buffer to create headers in (Note: should follow link header)
 * @param[in] src Source address (IP & port)
 * @param[in] dest Destination address (IP & port)
 * @param[in] ttl TTL value to use
 * @param[in] proto Protocol value
 * @param[in] payloadlen Packet payload size
 *
 * @return Returns size of header added to buf
 */
unsigned InitIpv4Header(const uint8_t* buf, const SOCKADDR_IN* src, const SOCKADDR_IN* dest, unsigned ttl, unsigned proto, unsigned payloadlen);


/**
 * @brief Initialize an TCP packet header
 *
 * @param[out] buf Buffer to create headers in (Note: should follow link header)
 * @param[in] src Source address (IP & port)
 * @param[in] dest Destination address (IP & port)
 * @param[in] ack_seq Optional NBO 32-bit sequence number to ACK (should be rcvd pkt's tcp_seq_num + 1)
 * @param[in] reset Optional, True to create an RST packet (default: SYN packet)
 *
 * @return Returns size of headers added to buf
 */
unsigned InitTcpHeader(const uint8_t* buf, const SOCKADDR_IN* src, const SOCKADDR_IN* dest, unsigned ack_seq = false, bool reset = false);


/**
 * @brief Initialize an IP and TCP packet headers and sets header checksum
 *
 * @param[out] packet Buffer to create headers in (Note: should follow link header)
 * @param[in] src Source address (IP & port)
 * @param[in] dest Destination address (IP & port)
 * @param[in] ack_seq Optional NBO 32-bit sequence number to ACK (should be rcvd pkt's tcp_seq_num + 1)
 * @param[in] reset Optional, True to create an RST packet (default: SYN packet)
 *
 * @return Returns size of headers added to buf, or SOCKET_ERROR on error
 */
int PacketizeIpv4(uint8_t* packet, const SOCKADDR_IN* src, const SOCKADDR_IN* dest, unsigned ack_seq = 0, bool reset = false);


//-------------------------------------------------------------------------------------------------
// Begin Code
//-------------------------------------------------------------------------------------------------
/**
 * @brief Query ARP cache, returns list of entries found
 *
 * @return Returns allocated MIB_IPNETTABLE structure with list of ARP entries. Pass to HeapFree() when no longer needed.
 * @return Returns null on failure
 */
MIB_IPNETTABLE* GetArpTable()
{
    MIB_IPNETTABLE* ipNetTable = nullptr;


#if PART2
    //
    // Use GetIpNetTable() to query a list of devices in the ARP cache. Do a web search to
    //  get usage instructions. Use HeapAlloc() to allocate the buffer.
    //
    // START: //////////////////////////// GET ARP TABLE - PART2 ////////////////////////////
    unsigned long sizePointer = 0;
    int rv = 0;
    rv = GetIpNetTable(ipNetTable, &sizePointer, false);
    if (rv != ERROR_INSUFFICIENT_BUFFER)
    {
        fprintf(stderr, "Failed to get IPv4 ARP table. Error: %lu", rv);
        return nullptr;
    }
    ipNetTable = (MIB_IPNETTABLE *) HeapAlloc(GetProcessHeap(), 0, sizePointer);
    rv = GetIpNetTable(ipNetTable, &sizePointer, false);
    if (rv)
    {
        fprintf(stderr, "Failed to get IPv4 ARP table. Error: %lu", rv);
        HeapFree(GetProcessHeap(), 0, ipNetTable);
        return nullptr;
    }
    // END:   //////////////////////////// GET ARP TABLE - PART2 ////////////////////////////
#endif

    return ipNetTable;
}

/**
 * @brief Set up the npcap driver to filter for only the return packets we want
 *
 * @param[in] devName Name of device being configured
 * @param[in] hPcap Open handle to an npcap session/file
 */
bool SetupFilter(const char* devName, pcap_t* hPcap)
{
    const unsigned FILTER_BUF_SIZE = 128;
    char filterExpression[FILTER_BUF_SIZE] = { 0 };

    //
    // Extra Credit: Improve the packet sniffer filter rule
    //  o To help reduce the amount of traffic being seen by the pcap_next() function, a filter is been placed
    //    on the npcap driver below for packets received to only include tcp packets destined for whichever
    //    port was set in #define SOURCE_PORT.
    //  o To further decrease the traffic, explore the filtering scheme provided to the pcap_filter() function
    //    to only receive the packets desired.
    //
    // Documentation on the filter syntax can be found at https ://www.tcpdump.org/manpages/pcap-filter.7.html.
    //
    // START: //////////////////////////// FILTER RULE BONUS ////////////////////////////

    char portExpression[] = "tcp dst port ";

    size_t portExprLen = strlen(portExpression);

    strncpy_s(filterExpression, portExpression, portExprLen);
    _itoa_s(SOURCE_PORT, filterExpression + portExprLen, FILTER_BUF_SIZE - portExprLen, 10);

    // END:   //////////////////////////// FILTER RULE BONUS ////////////////////////////

    bpf_u_int32 mask;		/* The netmask of our sniffing device */
    bpf_u_int32 net;		/* The IP of our sniffing device */

    if (pcap_lookupnet(devName, &net, &mask, pcap_errbuf) == -1)
    {
        fprintf(stderr, "Error, Can't get netmask for device %s (%s)\n", devName, pcap_errbuf);
        net = 0;
        mask = 0;
    }

    struct bpf_program filterExpressionCompiled;
    if (pcap_compile(hPcap, &filterExpressionCompiled, filterExpression, 1, net))
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filterExpression, pcap_geterr(hPcap));
        return false;
    }

    if (pcap_setfilter(hPcap, &filterExpressionCompiled) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filterExpression, pcap_geterr(hPcap));
        return false;
    }
    return true;
}


/**
 * @brief Get a list of devices in the ARP cache that are on the selected subnet (PART1 just adds loopback and returns)
 *
 * @param[in] subnet Subnet being scanned
 * @param[in] netmask Netmask of the subnet being scanned
 * @param]out] devicesToScan List to fill with IPv4 addresses of devices found
 *
 * @return Returns true on success, false on fatal errors
*/
bool GetDeviceList(uint32_t subnet, uint32_t netmask, vector<uint32_t>& devicesToScan)
{
    //
    // For PART1 (or if a specific device is given), we simply add the single target address, nominally loopback, to the
    //  list of devices to scan
    //
    if (deviceToScan)
    {
        devicesToScan.push_back(deviceToScan);
        return true;
    }

    //
    // PART2
    // 1. Use GetArpTable() from above to query the contents of the ARP cache.
    //      Print status messages so the app shows its processing (e.g. "Scanning ## entries on subnet ###.###.###.###"
    //          and "Adding ###.###.###.### to devicesToScan" or "Skipping ###.###.###.### because ...")
    //
    // 2. Scan all entries in the table:
    //      - Skip any that aren't suitable (e.g. broadcast, multicast, not on the subnet supported by the selected interface)
    //      - Add relevant device addresses to devicesToScan
    //      You can use iptostr() and a temp buffer to convert addresses to readable format
    //
    // START: //////////////////////////// ADD SUBNET ENTRIES - PART2 ////////////////////////////

    MIB_IPNETTABLE* ipNetTable = GetArpTable();
    if (!ipNetTable)
    {
        return false;
    }

    #define BROADCAST_MASK 0xFF
    #define SUBNET_MASK 0xFFFFFF00

    for (unsigned idx = 0; idx < ipNetTable->dwNumEntries; idx++)
    {
        char tempIp[64];
        unsigned ipAddr = ipNetTable->table[idx].dwAddr;
        iptostr(ipAddr, tempIp);
        // if multicast, broadcast, or not in subnet, skip it
        if ((ipAddr & MULTICAST_NETMASK) == MULTICAST_SUBNET || IS_BROADCAST(ipAddr, netmask) || !ON_SUBNET(ipAddr, subnet, netmask))
        {
            continue;
        }

        devicesToScan.push_back(ipNetTable->table[idx].dwAddr);
    }

    HeapFree(GetProcessHeap(), 0, ipNetTable);

    // END:   //////////////////////////// ADD SUBNET ENTRIES - PART2 ////////////////////////////
    return true;
}


/**
 * @brief Perform a port scan on a specific device
 *
 * @param hPcap Open handle to a live npcap session
 * @param src_ip Interface IP address
 * @param targetIp IPv4 address of the device to scan
 * @param useEtherHdr Use ethernet headers
 *
 * @return Returns true on success, false on failure
*/
bool ScanDevice(pcap_t* hPcap, uint32_t src_ip, uint32_t targetIp, bool useEtherHdr)
{
    uint32_t start = GetTickCount();    // for timing loop
    char address[IPV4_ADDR_STR_SIZE];   // general purpose IP address buffer
    std::set<int> knownOpenPorts;       // track known open ports

    printf("\n\nSCANNING %s:%u-%u\n", iptostr(targetIp, address), MIN_PORT, MAX_PORT);

    // setup source address structure, it will remain constant
    struct sockaddr_in src_addr = { 0 };
    src_addr.sin_family = AF_INET;
    src_addr.sin_addr.s_addr = src_ip;
    src_addr.sin_port = htons(SOURCE_PORT);

    // set known info for destination. Port will vary.
    struct sockaddr_in dst_addr = { 0 };
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_addr.s_addr = targetIp;

    // if we will be using ethernet headers, lookup src and dst mac addresses
    uint8_t src_mac[MAC_SIZE] = { 0 };
    uint8_t dst_mac[MAC_SIZE] = { 0 };
    if (useEtherHdr)
    {
        // if we can't get MAC for interface, fail entire scan (return false)
        if (!GetMacAddress(src_ip, src_mac))
        {
            fprintf(stderr, "    Error, failed to get interface MAC (%s)\n", iptostr(src_ip, address));
            return false;
        }
        //printf("    Local Device MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
        //    src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);

        if (!GetMacAddress(targetIp, dst_mac))
        {
            fprintf(stderr, "    Error, failed to get device MAC (%s)\n", iptostr(targetIp, address));
            return true;
        }
        //printf("    Destination MAC : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
        //    dest_mac[0], dest_mac[1], dest_mac[2], dest_mac[3], dest_mac[4], dest_mac[5]);
    }


    // only report first CLOSED_FILTERED_DISPLAY_MAX each of closed/filtered ports to limiting noise
    unsigned closedCount = 0;
    unsigned filteredCount = 0;

    for (unsigned currentPort = MIN_PORT; currentPort < MAX_PORT; currentPort++)
    {
        #define RESPONSE_TIMEOUT 200    // wait 200ms for a response
        uint8_t packet[PACKET_SIZE] = { 0 };

        dst_addr.sin_port = htons((uint16_t)currentPort);

        // create the link layer header at the start of the packet staging buffer
        unsigned linkHdrSize = CreateLinkHeader(packet, useEtherHdr, src_mac, dst_mac);

        //
        // Analyze the ports of the target to determine whether they are Open, Closed, or appear to be Filtered
        //
        // STEP 1: Create the packet to be sent
        //   o Use the PacketizeIpv4() function to create the TCP packet that will be sent to each port.
        //   o The link layer portion of the packet (Ethernet / loopback) header has been generated for you
        //     already and placed in the packet buffer.
        //
        // STEP 2: Send the packet to the given port
        //   o Use the pcap_sendpacket() function to send the packet you have generated on the chosen network
        //     interface (for part1 this should be the loopback interface).
        //
        // STEP 3: Receive the response
        //   o For up to 300ms (RESPONSE_TIMEOUT), watch for a response to the packet that was sent.
        //   o Use the pcap_next() function to receive the next packet, if any, that has been captured.
        //   o This function will return a pointer to the start of the link layer header (Ethernet / loopback).
        //   o If it returns NULL, no packets have been captured, so continue waiting unless a timeout occurs.
        //
        // STEP 4: Analyze the packet
        //   o Verify that the source of the packet is the target and port currently being scanned. If not, ignore it and keep
        //     waiting.
        //   o Check the response to determine what TCP flags were set in order to determine the status of the port scanned.
        //     - SYN / ACK – Your connection request was accepted (Port OPEN)
        //     - RST / ACK – Acknowledges your SYN, but refuses the connection (Port CLOSED)
        //     - Other packets will generally not occur, but if they do, you can ignore them. If your code doesn't work,
        //       debug any of these to see if you're misreading them.
        //   o If a timeout occurs without having received a response, the port is likely filtered.
        //      Hint: You can use GetTickCount64() to get a rolling counnt of milliseconds to use for timing the response to
        //          your requests.
        //   o Print the port number and the results for that port.
        //      IMPORTANT: The open ports are what is important. Pages of “123 CLOSED” or “123 FILTERED” will keep you from
        //          seeing the ports that mean something, so only print the first 10 closed and first 10
        //          filtered, to let you know they are happening, but keep them from flooding your report.
        //   o Run your port scanner multiple times and compare the results. If they are not consistent, something is wrong
        //     with your code. If you are getting more Filtered than you think you should, try increasing RECEIVE_TIMEOUT. But
        //     be aware that this will slow your scanner. A professional scanner would likely send many requests at once and
        //     analyze the results as they came in.
        //
        // STEP 5: Terminate the handshake for OPEN/CLOSED ports
        //   o If you don't send a RST / ACK in response to SYN / ACK packets received, the target will think the packet
        //     got lost and will resend for a period of time. To keep this from happening, build and send a RST packet to
        //     the port once a response has been received, acknowledging receipt of the packet, and terminating the
        //     handshake.
        //   o PacketizeIpv4() can be used to build this packet over the top of the packet buffer used for step 2.
        //     The reset parameter should be true, and ack_seq should be set based on the received packet’s TCP sequence
        //     number.
        //   o Reminder: The link header still exists at the start of the staging buffer, and the source and dest addresses
        //     are still correct.
        //
        // START: //////////////////////////// PORT ANALYSIS - PART1 ////////////////////////////

        // STEP 1: Create the packet to be sent
        unsigned ipTcpHdrSize = PacketizeIpv4(packet + linkHdrSize, &src_addr, &dst_addr);

        PIPV4_HDR synIpHdr = (PIPV4_HDR) (packet + linkHdrSize);
        PTCP_HDR synTcpHdr = (PTCP_HDR)(packet + linkHdrSize + sizeof(IPV4_HDR));
        // STEP 2: Send the packet to the given port
        if (pcap_sendpacket(hPcap, packet, linkHdrSize + ipTcpHdrSize))
        {
            fprintf(stderr, "%5u Failed to send packet. Pcap Error: \"%s\"\n", currentPort, pcap_geterr(hPcap));
            continue;
        }

        // STEP 3: Receive the response
        pcap_pkthdr packetInfo;

        unsigned portStart = GetTickCount();
        const u_char * responsePacket = NULL;

        // while still within the response timeout window, get next pcap packet
        while (GetTickCount() - portStart < RESPONSE_TIMEOUT)
        {
            responsePacket = pcap_next(hPcap, &packetInfo);

            // if no next pcap packet, sleep and continue
            if (!responsePacket)
            {
                // printf("No packet.\n");
                continue;
            }

        // STEP 4: Analyze the packet
            // if not the IP being queried, continue
            PIPV4_HDR responseIpHdr = (PIPV4_HDR)(responsePacket + linkHdrSize);
            if (responseIpHdr->ip_srcaddr != targetIp)
            {
                continue;
            }

            // if not the port being queried, continue
            PTCP_HDR responseTcpHdr = (PTCP_HDR)(responsePacket + sizeof(linkHdrSize) + sizeof(IPV4_HDR));
            if (ntohs(responseTcpHdr->tcp_src) != currentPort)
            {
                continue;
            }

            // check SYN / ACK, port open
            if (responseTcpHdr->tcp_syn && responseTcpHdr->tcp_ack)
            {
                printf("%5u OPEN\n", currentPort);
            }
            // check RST / ACK, port closed
            else if (responseTcpHdr->tcp_rst && responseTcpHdr->tcp_ack)
            {
                closedCount++;
                if (closedCount <= CLOSED_FILTERED_DISPLAY_MAX)
                {
                    printf("%5u CLOSED\n", currentPort);
                }
            }
            else
            {
                printf("%5u INVALID\n", currentPort);
            }
            // STEP 5: Terminate the handshake for OPEN/CLOSED ports
            ipTcpHdrSize = PacketizeIpv4(packet + linkHdrSize, &src_addr, &dst_addr, inc_nbo32(responseTcpHdr->tcp_seq_num), true);
            PTCP_HDR resetTcpHdr = (PTCP_HDR)(packet + linkHdrSize + sizeof(IPV4_HDR));
            pcap_sendpacket(hPcap, packet, linkHdrSize+ipTcpHdrSize);
            break;
        }

        // if the response timed out, assume the port is filtered
        if (GetTickCount() - portStart >= RESPONSE_TIMEOUT)
        {
            filteredCount++;
            if (filteredCount <= CLOSED_FILTERED_DISPLAY_MAX)
            {
                printf("%5u FILTERED\n", currentPort);
            }
        }

        // END:   //////////////////////////// PORT ANALYSIS - PART1 ////////////////////////////
    }
    printf("Scan took: %ums (closed=%u, filtered=%u)\n", GetTickCount() - start, closedCount, filteredCount);
    return true;
}

/**
 * @brief Main code
 */
bool RunPortScan(const pcap_if_t* devList)
{
    // select the device to use for sending our packets (for PART1, use the defined address unless IP given on command line)
#if PART1
    if (!deviceToScan)
    {
        deviceToScan = PART1_TARGET_IP;
    }
#endif
    const pcap_if_t* ifc = SelectInterface(devList, IS_LOOPBACK(deviceToScan));
    if (nullptr == ifc)
    {
        return false;
    }

    // open an npcap live session to this device
    pcap_t* hPcap;
    if ((hPcap = pcap_open_live(ifc->name,	    // name of the device to use as interface
                                65536,			// portion of the packet to capture.
                                                // 65536 grants that the whole packet will be captured on all the MACs.
                                1,			    // promiscuous mode (nonzero means promiscuous)
                                1,			    // read timeout
                                pcap_errbuf			// error buffer
                            )) == nullptr
        )
    {
        fprintf(stderr, "\nUnable to open the adapter. '%s' is not supported by Npcap (%s)\n", ifc->name, pcap_errbuf);
        return false;
    }

    // Set up the npcap driver to filter for only the return packets we want
    if (!SetupFilter(ifc->name, hPcap))
    {
        return false;
    }

    // setup subnet info and determine what kind of link header to use
    uint32_t ifc_ip;    // source IP for our packets (interface selected)
    uint32_t subnet;    // subnet for selected interface
    uint32_t netmask;   // netmask for selected interface
    bool useEtherHdr = true;
    if (isLoopbackDevice(ifc))
    {
        ifc_ip = LOOPBACK_NBO;
        netmask = NETMASK_24_NBO;
        useEtherHdr = false;
    }
    else if (!GetIPv4Info(ifc->addresses, ifc_ip, &netmask))
    {
        fprintf(stderr, "No IPv4 support on selected interface\n");
        return false;
    }
    subnet = ifc_ip & netmask;

    // build a list of devices to scan
    vector<uint32_t> devicesToScan; // list of devices found to scan
    if (!GetDeviceList(subnet, netmask, devicesToScan))
    {
        return false;
    }

    if (devicesToScan.size() == 0)
    {
        fprintf(stderr, "\n\nNo suitable devices found on selected interface\n");
        return false;
    }

    for (uint32_t deviceIp : devicesToScan)
    {
        ScanDevice(hPcap, ifc_ip, deviceIp, useEtherHdr);
    }

    return true;
}

int _cdecl main(int argc, char** argv)
{
    #define EXIT_FAILURE    1
    #define EXIT_SUCCESS    0

    if (argc == 2)
    {
        deviceToScan = parse_ip(argv[1]);
        if (!deviceToScan)
        {
            fprintf(stderr, "Usage: SystemScanRaw [interface_ip]\n");
            return EXIT_FAILURE;
        }
    }

    /* Load Npcap and its functions. */
    if (!LoadNpcapDlls())
    {
        fprintf(stderr, "Couldn't load Npcap\n");
        return EXIT_FAILURE;
    }

    /* Retrieve the device list */
    pcap_if_t* alldevs;
    if (pcap_findalldevs(&alldevs, pcap_errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", pcap_errbuf);
        return EXIT_FAILURE;
    }

    bool success = RunPortScan(alldevs);

    /* Free the device list */
    pcap_freealldevs(alldevs);

    return success ? EXIT_SUCCESS : EXIT_FAILURE;
}


//-------------------------------------------------------------------------------------------------
// Local Functions
//-------------------------------------------------------------------------------------------------
bool LoadNpcapDlls()
{
    wchar_t npcap_dir[MAX_PATH];
    unsigned len = GetSystemDirectoryW(npcap_dir, MAX_PATH);
    if (!len)
    {
        fprintf(stderr, "LoadNpcapDlls() Error, GetSystemDirectory() failed (%u)\n", GetLastError());
        return false;
    }
    if (len > MAX_PATH - NPCAP_PATH_LEN)
    {
        fprintf(stderr, "LoadNpcapDlls() Error, GetSystemDirectory() failed, insufficient room in local buffer for path (%u)\n", len);
        return false;
    }
    unsigned rv = wcscat_s(npcap_dir, MAX_PATH, NPCAP_PATH);
    if (rv != ERROR_SUCCESS)
    {
        fprintf(stderr, "LoadNpcapDlls() Error, wcscat_s() failed (%u)\n", rv);
        return false;
    }
    if (!SetDllDirectoryW(npcap_dir))
    {
        fprintf(stderr, "LoadNpcapDlls() Error, SetDllDirectoryW() failed (%u)\n", GetLastError());
        return false;
    }
    return true;
}


bool GetMacAddress(uint32_t ip, uint8_t* mac)
{
    uint32_t MacAddr[2];
    unsigned PhyAddrLen = sizeof(MacAddr);
    unsigned rv = SendARP(ip, 0, MacAddr, (ULONG*)&PhyAddrLen);
    if (rv != ERROR_SUCCESS)
    {
        fprintf(stderr, "Error, SendARP() failed (%u)\n", rv);
        return false;
    }
    memcpy(mac, MacAddr, PhyAddrLen);
    return true;
}


/**
 * @brief Query adapter info into buffer allocated by this function
 *
 * @return Adapter info list (must be passed to HeapFree()), or null on failure
 */
static IP_ADAPTER_INFO* _GetAdaptersInfo()
{
    IP_ADAPTER_INFO* buffer = nullptr;
    unsigned buflen = 0;

    while (true)
    {
        unsigned rv = GetAdaptersInfo(buffer, (ULONG*)&buflen);
        if (rv == ERROR_SUCCESS)
        {
            if (nullptr == buffer)
            {
                fprintf(stderr, "GetAdaptersInfo() unexpected error, buffer is null\n");
            }
            return buffer;
        }
        if (nullptr != buffer)
        {
            HeapFree(GetProcessHeap(), 0, buffer);
            buffer = nullptr;
        }
        if (rv == ERROR_BUFFER_OVERFLOW)
        {
            buffer = (IP_ADAPTER_INFO*)HeapAlloc(GetProcessHeap(), 0, buflen);
            if (nullptr == buffer)
            {
                fprintf(stderr, "Allocation failed '%u'\n", GetLastError());
            }
            continue;
        }
        fprintf(stderr, "GetAdaptersInfo() failed '%u'\n", rv);
        return nullptr;
    }
}


static bool GetDefaultGateway(uint32_t& ip, uint32_t& gatewayip, uint32_t& subnetmask)
{
    IP_ADAPTER_INFO* adapterList = _GetAdaptersInfo();
    if (nullptr == adapterList)
    {
        return false;
    }

    unsigned homed = 0;
    PIP_ADAPTER_INFO GatewayAdapter = nullptr;
    printf("\nGetGateway: Adapter List\n");
    for (IP_ADAPTER_INFO* adapter = adapterList; adapter != nullptr; adapter = adapter->Next)
    {
        //unsigned nicip, gwyip;
        //int rv1 = InetPtonA(AF_INET, AdapterInfo->IpAddressList.IpAddress.String, &nicip);
        //int rv2 = InetPtonA(AF_INET, AdapterInfo->GatewayList.IpAddress.String, &gwyip);
        printf("    %-50s ADDRESS: %-16s\tGATEWAY: %-16s\tMASK: %-16s\n",
            adapter->Description,
            adapter->IpAddressList.IpAddress.String,
            adapter->GatewayList.IpAddress.String,
            adapter->IpAddressList.IpMask.String);
        // skip any adapters with no gateway address
        if (strcmp(adapter->GatewayList.IpAddress.String, "0.0.0.0") == 0)
        {
            continue;
        }
        // and any with invalid or missing address strings
        uint32_t junk;
        if ((InetPtonA(AF_INET, adapter->IpAddressList.IpAddress.String, &junk) != 1)
            || (InetPtonA(AF_INET, adapter->GatewayList.IpAddress.String, &junk) != 1))
        {
            continue;
        }
        if (GatewayAdapter == nullptr)
        {
            GatewayAdapter = adapter;
        }
        homed++;
    }

    // if no gateways found, fail the search
    if (!homed || (GatewayAdapter == nullptr))
    {
        printf("No gateway found\n");
        return false;
    }

    if (homed > 1)
    {
        printf("WARNING: Multi-homed machine detected, selected first gateway interface\n");
    }

    // conversions already checked for validity above
    InetPtonA(AF_INET, GatewayAdapter->IpAddressList.IpAddress.String, &ip);
    InetPtonA(AF_INET, GatewayAdapter->GatewayList.IpAddress.String, &gatewayip);
    InetPtonA(AF_INET, GatewayAdapter->IpAddressList.IpMask.String, &subnetmask);
    printf("\nGateway Interface:\n%-50s ADDRESS: %-16s\tGATEWAY: %-16s\tMASK: %-16s\n",
        GatewayAdapter->Description,
        GatewayAdapter->IpAddressList.IpAddress.String,
        GatewayAdapter->GatewayList.IpAddress.String,
        GatewayAdapter->IpAddressList.IpMask.String);
    HeapFree(GetProcessHeap(), 0, adapterList);
    return true;
}


/**
 * @brief Find and return a pointer to the loopback adapter
 *
 * @param[in] devList List of all devices on system
 */
static const pcap_if_t* findLoopbackAdapter(const pcap_if_t* devList)
{
    for (const pcap_if_t* dev = devList; dev; dev = dev->next)
    {
        if (isLoopbackDevice(dev))
        {
            return dev;
        }
    }
    fprintf(stderr, "Error, loopback adapter not found\n");
    return nullptr;
}


/**
 * @brief Print a numbered list of network devices, returns count of devices listed
 */
static unsigned printDeviceSelectionList(const pcap_if_t* devList)
{
    unsigned deviceCount = 0;
    for (const pcap_if_t* dev = devList; dev; dev = dev->next)
    {
        printf("%2u. %-50s", ++deviceCount, dev->name);
        uint32_t ip, netmask;
        if (isLoopbackDevice(dev))
        {
            printf(" %-34s", "(LOOPBACK)");
        }
        else if (nullptr == dev->addresses)
        {
            printf(" %-34s", "(INACTIVE)");
        }
        else if (!GetIPv4Info(dev->addresses, ip, &netmask))
        {
            printf(" %-34s", "(NO IPv4)");
        }
        else
        {
            char ip_s[IPV4_ADDR_STR_SIZE];
            char netmask_s[IPV4_ADDR_STR_SIZE];

            printf(" (%-15s/ %-15s)",
                InetNtopA(AF_INET, &ip, ip_s, sizeof(ip_s)),
                InetNtopA(AF_INET, &netmask, netmask_s, sizeof(netmask_s))
            );
        }
        if (dev->description)
        {
            printf(" (%s)\n", dev->description);
        }
        else
        {
            printf(" (No description available)\n");
        }
    }
    return deviceCount;
}


/**
 * @brief Search for an interface by IP address
 */
const pcap_if_t* findInterface(const pcap_if_t* devList, uint32_t targetIp)
{
    for (const pcap_if_t* dev = devList; dev; dev = dev->next)
    {
        if (isLoopbackDevice(dev))
        {
            continue;
        }
        if (dev->addresses == nullptr)
        {
            continue;
        }
        uint32_t deviceIp, netmask;
        if (!GetIPv4Info(dev->addresses, deviceIp, &netmask))
        {
            printf(" %-34s", "(NO IPv4)");
            continue;
        }
        if (targetIp == deviceIp)
        {
            return dev;
        }
    }
    return nullptr;
}


const pcap_if_t* SelectInterface(const pcap_if_t* devList, bool loopback)
{
    if (loopback)
    {
        return findLoopbackAdapter(devList);
    }

    if (deviceToScan)
    {
        return findInterface(devList, deviceToScan);
    }

    // print list of adapters for selection
    unsigned adapterCount = printDeviceSelectionList(devList);
    if (adapterCount == 0)
    {
        printf("\nNo interfaces found! Make sure Npcap is installed.\n");
        return nullptr;
    }

    //
    // allow user to select from device list
    //
    unsigned deviceIndex;
    do
    {
        printf("\nEnter the interface number (1-%u): ", adapterCount);
        scanf_s("%u", &deviceIndex);
        // adapter numbers are 1 based, but we want a 0-based value for accessing the list
        deviceIndex--;
        if (deviceIndex < adapterCount)
        {
            break;
        }
        printf("\nInterface number out of range.");
    } while (true);

    // locate the selected adapter
    const pcap_if_t* ifc = devList;
    for (unsigned idx = 0; ifc && idx < deviceIndex; ifc = ifc->next, idx++)
    {
        // intentionally empty
    }
    if (nullptr == ifc)
    {
        fprintf(stderr, "\nUnexpected error: interface is null\n");
    }
    return ifc;
}


uint16_t checksum(const void* buffer, unsigned size)
{
    uint32_t result = 0;
    const uint16_t* ptr = (const uint16_t*)buffer;

    // calculate value for full 16-bit values in data
    while (size > 1)
    {
        result += *ptr++;
        size -= sizeof(uint16_t);
    }
    // if the buffer was not a multiple of 16-bits, add the last byte
    if (size)
    {
        result += *(const uint8_t*)ptr;
    }

    // add the low order 16-bits to the high order 16-bits
    result = (result >> 16) + (result & 0xffff);

    // return the 1's complement
    return (uint16_t)(~result);
}


uint32_t inc_nbo32(uint32_t value, uint8_t inc)
{
    uint32_t result = ntohl(value) + inc;
    return htonl(result);
}


bool isLoopbackDevice(const pcap_if_t* dev)
{
    // dev->addresses should be null, name "\\Device\\NPF_Loopback", description "Adapter for loopback traffic capture"
    return strstr(dev->name, "Loopback") != nullptr;
}


const char* iptostr(uint32_t ip, char* buffer)
{
    inet_ntop(AF_INET, &ip, buffer, IPV4_ADDR_STR_SIZE);
    return buffer;
}


unsigned parse_ip(const char* ipstr)
{
    uint32_t addr = 0; // pAddrBuf should point to an IN_ADDR, which is just a union that wraps a 32-bit unsigned integer
    int rv = inet_pton(AF_INET, ipstr, &addr);
    if (rv == SOCKET_ERROR)
    {
        fprintf(stderr, "Unexpected error parsing scan interface IP (%s) (errno=%u)\n", ipstr, errno);
        return 0;
    }
    if (rv != 1)
    {
        fprintf(stderr, "Error, '%s' is not a valid IPv4 address\n", ipstr);
        return 0;
    }
    return addr;
}


const pcap_addr* pcap_findipv4(const pcap_addr* addresses)
{
    while (nullptr != addresses)
    {
        if ((addresses->addr != nullptr) && (addresses->addr->sa_family == AF_INET))
        {
            return addresses;
        }
        addresses = addresses->next;
    }
    return nullptr;
}


bool GetIPv4Info(const pcap_addr* addresses, uint32_t& ip, uint32_t* netmask, uint32_t* broadcast, uint32_t* dest)
{
    // initialize all return values to zero
    ip = 0;
    if (nullptr != netmask)
    {
        *netmask = 0;
    }
    if (nullptr != broadcast)
    {
        *broadcast = 0;
    }
    if (nullptr != dest)
    {
        *dest = 0;
    }
    if (nullptr == addresses)
    {
        //printf("getIPv4Info() error, null pcap address\n");
        return false;
    }
    // find IPv4 addresses info, if any
    addresses = pcap_findipv4(addresses);
    if (nullptr == addresses)
    {
        //printf("getIPv4Info() no IPv4 address info\n");
        return false;
    }
    const sockaddr_in* sa = (const sockaddr_in*)addresses->addr;
    ip = sa->sin_addr.s_addr;

    if ((nullptr != netmask) && (nullptr != addresses->netmask))
    {
        sa = (const sockaddr_in*)addresses->netmask;
        *netmask = sa->sin_addr.s_addr;
    }

    if ((nullptr != broadcast) && (nullptr != addresses->broadaddr))
    {
        sa = (const sockaddr_in*)addresses->broadaddr;
        *broadcast = sa->sin_addr.s_addr;
    }

    if ((nullptr != dest) && (nullptr != addresses->dstaddr))
    {
        sa = (const sockaddr_in*)addresses->dstaddr;
        *dest = sa->sin_addr.s_addr;
    }
    return true;
}


unsigned CreateLinkHeader(void* packet, bool useEtherHdr, uint8_t* src_mac, uint8_t* dst_mac)
{
    if (useEtherHdr)
    {
        // LINKTYPE_ETHERNET is used for all other local traffic, including wi-fi. Link header is ETHER_HDR.
        ETHER_HDR* ethHdr = (ETHER_HDR*)packet;
        memcpy(ethHdr->source, src_mac, sizeof(ethHdr->source)); //Source Mac address
        memcpy(ethHdr->dest, dst_mac, sizeof(ethHdr->dest)); //Destination MAC address
        ethHdr->type = htons(ETHER_TYPE_IPV4); //IP Frames
        return sizeof(ETHER_HDR);
    }
    else {
        // LINKTYPE_NULL (BSD Loopback Encapsulation) uses a 32-bit link header with a host byte order value indicating the
        //      packet type.
        uint32_t* loopbackHdr = (uint32_t*)packet;
        *loopbackHdr = BSD_LOOPBACK_IPV4;
        return sizeof(uint32_t);
    }
}


unsigned InitIpv4Header(const uint8_t* buf, const SOCKADDR_IN* src, const SOCKADDR_IN* dest, unsigned ttl, unsigned proto, unsigned payloadlen)
{
    IPV4_HDR* v4hdr = nullptr;

    v4hdr = (IPV4_HDR*)buf;

    v4hdr->ip_verlen = (4 << 4) | (sizeof(IPV4_HDR) / sizeof(uint32_t));
    v4hdr->ip_tos = 0;
    v4hdr->ip_totallength = htons(sizeof(IPV4_HDR) + (uint16_t)payloadlen);
    v4hdr->ip_id = htons(54321);
    v4hdr->ip_offset = 0;
    v4hdr->ip_ttl = (uint8_t)ttl;
    v4hdr->ip_protocol = (uint8_t)proto;
    v4hdr->ip_checksum = 0;
    v4hdr->ip_srcaddr = src->sin_addr.s_addr;
    v4hdr->ip_destaddr = dest->sin_addr.s_addr;

    v4hdr->ip_checksum = checksum(v4hdr, sizeof(IPV4_HDR));

    return sizeof(IPV4_HDR);
}


unsigned InitTcpHeader(const uint8_t* buf, const SOCKADDR_IN* src, const SOCKADDR_IN* dest, unsigned ack_seq, bool reset)
{
    TCP_HDR* tcphdr = (TCP_HDR*)buf;

    tcphdr->tcp_src = src->sin_port;
    tcphdr->tcp_dst = dest->sin_port;
    tcphdr->tcp_hdr_len = 6;
    tcphdr->tcp_res1 = 0;
    tcphdr->tcp_fin = 0;
    // setup either TCP/SYN or TCP/RST depending on reset flag
    tcphdr->tcp_syn = reset ? 0 : 1;
    tcphdr->tcp_rst = reset ? 1 : 0;
    tcphdr->tcp_psh = 0;
    // if an ACK sequence number is given, make this an ACK of the remote packet
    if (ack_seq)
    {
        tcphdr->tcp_ack = 1;
        tcphdr->tcp_ack_num = ack_seq;
        tcphdr->tcp_seq_num = inc_nbo32(tcphdr->tcp_seq_num);
    }
    else
    {
        tcphdr->tcp_ack = 0;
        tcphdr->tcp_ack_num = 0;
        tcphdr->tcp_seq_num = 0;
    }
    tcphdr->tcp_urg = 0;
    tcphdr->tcp_res2 = 0;
    tcphdr->tcp_win_size = htons(1024);
    tcphdr->tcp_chk = 0;
    tcphdr->tcp_urg_ptr = 0;
    uint8_t options[4] = { 0x02, 0x04, 0x05, 0xb4 };
    memcpy(((char*)tcphdr) + sizeof(TCP_HDR), options, sizeof(options));

    return (sizeof(TCP_HDR) + sizeof(options));
}


int PacketizeIpv4(uint8_t* packet, const SOCKADDR_IN* src, const SOCKADDR_IN* dest, unsigned ack_seq, bool reset)
{
    // Check the parameters
    if ((packet == nullptr) || (src == nullptr) || (dest == nullptr))
    {
        WSASetLastError(WSAEINVAL);
        return SOCKET_ERROR;
    }

    // Initialize the v4 header
    unsigned iphdrlen = InitIpv4Header(packet, src, dest, DEFAULT_TTL, IPPROTO_TCP, sizeof(TCP_HDR) + 4);

    unsigned tcphdrlen = InitTcpHeader(&(packet[iphdrlen]), src, dest, ack_seq, reset);

    PSUEDO_TCP_HDR ptcph;
    //Pseudo TCP Header + TCP Header + data
    uint8_t* pseudo_packet;
    TCP_HDR* tcpHdr = (TCP_HDR*)&(packet[iphdrlen]);

    ptcph.srcAddr = src->sin_addr.s_addr;
    ptcph.dstAddr = dest->sin_addr.s_addr;
    ptcph.zero = 0;
    ptcph.protocol = IPPROTO_TCP;
    ptcph.TCP_len = htons((uint16_t)tcphdrlen);

    #pragma warning(disable : 6386)        // possible buffer overflow (due to inadequate markup)
    //Populate the pseudo packet
    pseudo_packet = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (unsigned)sizeof(PSUEDO_TCP_HDR) + tcphdrlen);
    if (nullptr == pseudo_packet)
    {
        WSASetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return SOCKET_ERROR;
    }
    memset(pseudo_packet, 0, (int)sizeof(PSUEDO_TCP_HDR) + tcphdrlen);

    // Copy pseudo header
    memcpy(pseudo_packet, &ptcph, sizeof(PSUEDO_TCP_HDR));

    //Copy tcp header + data to fake TCP header for checksum
    memcpy(pseudo_packet + sizeof(PSUEDO_TCP_HDR), tcpHdr, tcphdrlen);

    //Set the TCP header's check field
    tcpHdr->tcp_chk = (checksum((uint16_t*)pseudo_packet, (int)sizeof(PSUEDO_TCP_HDR) + tcphdrlen));

    HeapFree(GetProcessHeap(), 0, pseudo_packet);

    return iphdrlen + tcphdrlen;
}
