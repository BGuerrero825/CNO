//-------------------------------------------------------------------------------------------------
// dns.h
//
// DNS definitions and utilities
//
// Based on source code published without license header at
// https://www.binarytides.com/dns-query-code-in-c-with-winsock/
//-------------------------------------------------------------------------------------------------
#include "pch.h"
#include "dns.h"
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>

extern const char* baseHost = "www.XXXX-megamicro.XXX.com";
extern const unsigned hostOffsets[8] = {4, 5, 6, 7, 19, 20, 21};

/** @brief Read the host name from a DNS name query */
void ReadName(const uint8_t* qname, const uint8_t* dns_pkt, uint8_t* name, unsigned nameSize)
{
    // start with an empty string
    name[0] = 0;

    // gather the qname format string (e.g. "\3www\6google\3com" into name buffer (may be distributed)
    unsigned nameLen = 0;    // index of end of name buffer
    while (*qname)
    {
        if (nameLen + 1 >= nameSize)
        {
            break;
        }
        // until we reach the end of string indicator, just copy everything to name[]
        if (*qname <= MAX_QNAME_SEGMENT_LEN)
        {
            name[nameLen++] = *qname++;
            continue;
        }
        // a value greater than MAX_QNAME_SEGMENT_LEN signals an encoded 16-bit packet offset
        //      - extract the 16-bit value, big endian, and then subtracts the flag value to get the packet
        //        offset of the next segment of the string
        unsigned offset = (((unsigned)(qname[0]) << 8) + qname[1]) - DNS_QNAME_OFFSET_INC;
        qname = dns_pkt + offset;
    }
    name[nameLen] = 0; //string complete

    // check for empty string and fail
    if (nameLen == 0)
    {
        return;
    }

    // now convert "\3www\6google\3com" format to "www.google.com"
    // grab first segment length, and then memcpy() the rest down 1
    unsigned segLen = name[0];
    memmove(name, name + 1, nameLen);
    nameLen--;

    // now replace segment lengths with dots
    while (segLen < nameLen)
    {
        unsigned nextSegLen = name[segLen];
        name[segLen++] = '.';
        segLen += nextSegLen;
    }
}


/* Converts dotted format name string to DNS qname format string (e.g. "www.google.com" => "\3www\6google\3com") */
bool ChangetoDnsNameFormat(const char* host, uint8_t* dns)
{
    if ((NULL == host) || !host[0])
    {
        return false;
    }

    do
    {
        // find the end of the next section of the host name
        const char* end = strchr(host, '.');
        // if no dot, set end to end of string
        if (NULL == end)
        {
            end = host + strlen(host);
        }
        unsigned seglen = (unsigned)(end - host);
        if (seglen > MAX_QNAME_SEGMENT_LEN)
        {
            // decoding can't handle values greater than 191
            return false;
        }
        // set the length
        *dns++ = (uint8_t)seglen;
        // copy this segment
        while (host < end)
        {
            *dns++ = *host++;
        }
        // if we ended at a dot, increment host to point to next segment
        if (*host == '.')
        {
            host++;
        }
    } while (*host);
    // terminate dns qname string
    *dns = 0;
    return true;
}
