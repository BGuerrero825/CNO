#pragma once
//
// IP Header Definitions
//
// Description:
//    This file contains protocol header definitions.
//
// NOTE:
//    From Network Programming for Microsoft Windows, Second Edition
//    by Anthony Jones and James Ohlund.  Copyright 2002.
//    Reproduced by permission of Microsoft Press.  All rights reserved.
//
#include <pshpack1.h>

//
//Ethernet Header
//
typedef struct ethernet_header
{
    uint8_t     dest[6];        // Total 48 bits
    uint8_t     source[6];      // Total 48 bits
    uint16_t    type;           // 16 bits
}   ETHER_HDR, * PETHER_HDR, FAR* LPETHER_HDR, ETHERHeader;

//
// IPv4 Header (without any IP options)
//
typedef struct ip_hdr
{
    uint8_t     ip_verlen;      // 4-bit IPv4 version
                                // 4-bit header length (in 32-bit words)
    uint8_t     ip_tos;         // IP type of service
    uint16_t    ip_totallength; // Total length
    uint16_t    ip_id;          // Unique identifier
    uint16_t    ip_offset;      // Fragment offset field
    uint8_t     ip_ttl;         // Time to live
    uint8_t     ip_protocol;    // Protocol(TCP,UDP etc)
    uint16_t    ip_checksum;    // IP checksum
    uint32_t    ip_srcaddr;     // Source address
    uint32_t    ip_destaddr;    // Source address
} IPV4_HDR, * PIPV4_HDR, * LPIPV4_HDR;

//
// Define the UDP header
//
typedef struct udp_hdr
{
    uint16_t    src_portno;     // Source port no.
    uint16_t    dst_portno;     // Dest. port no.
    uint16_t    udp_length;     // Udp packet length
    uint16_t    udp_checksum;   // Udp checksum
} UDP_HDR, * PUDP_HDR;

//
// TCP packet structure.
//
typedef struct tcp
{
    uint16_t    tcp_src;        // Source port.
    uint16_t    tcp_dst;        // Destination port.
    uint32_t    tcp_seq_num;    // Sequence number.
    uint32_t    tcp_ack_num;    // sequence number being ack'd
    uint8_t     tcp_res1 : 4,   // Reserved (bit 0..3).
                tcp_hdr_len : 4;// Header length.
    uint8_t     tcp_fin : 1,    // FIN flag.
                tcp_syn : 1,    // SYN flag.
                tcp_rst : 1,    // RST flag.
                tcp_psh : 1,    // PSH flag.
                tcp_ack : 1,    // ACK flag.
                tcp_urg : 1,    // URG flag.
                tcp_res2 : 2;   // Reserved (bit 4..6).
    uint16_t    tcp_win_size;   // Window size.
    uint16_t    tcp_chk;        // TCP checksum.
    uint16_t    tcp_urg_ptr;    // Urgent pointer.
} TCP_HDR, * PTCP_HDR;

//Pseudo header needed for calculating the TCP header checksum
typedef struct pseudoTCPPacket {
    uint32_t    srcAddr;
    uint32_t    dstAddr;
    uint8_t     zero;
    uint8_t     protocol;
    uint16_t    TCP_len;
} PSUEDO_TCP_HDR, *PPSUEDO_TCP_HDR;

#include <poppack.h>