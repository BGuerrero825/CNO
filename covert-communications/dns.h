//-------------------------------------------------------------------------------------------------
// dns.h
//
// DNS definitions and utilities
//
// Based on source code published without license header at
// https://www.binarytides.com/dns-query-code-in-c-with-winsock/
//-------------------------------------------------------------------------------------------------
#pragma once
#include <stdint.h>
#include <stdbool.h>

#define DNS_QNAME_OFFSET_INC    0xC000                      // this value is added to an offset that is stored BE to indicate that it is not a character of the string
#define MAX_QNAME_SEGMENT_LEN ((DNS_QNAME_OFFSET_INC >> 8) - 1) // a QNAME name segment may not exceed 191 characters (e.g. www)
//#define MAX_HOST_SIZE (3 * (MAX_QNAME_SEGMENT_LEN + 1))     // allow for 3 full length name segments, including null terminator

#define MAX_HOST_SIZE 256                                    // arbitrary max length of a url string for our labs
#define ENCODED_BYTES 4
#define ENCODED_LEN 7
#define MAX_16BIT 0xFFFF

#define BASEHOST_OFFSET 8
#define BASEHOST_PLACEHOLDER 'X'
extern const char* baseHost;
extern const unsigned hostOffsets[];

//DNS header structure
typedef struct _DNS_HEADER
{
    uint16_t id; // identification number

    uint8_t rd : 1; // recursion desired
    uint8_t tc : 1; // truncated message
    uint8_t aa : 1; // authoritive answer
    uint8_t opcode : 4; // purpose of message
    uint8_t qr : 1; // query/response flag

    uint8_t rcode : 4; // response code
    uint8_t cd : 1; // checking disabled
    uint8_t ad : 1; // authenticated data
    uint8_t z : 1; // its z! reserved
    uint8_t ra : 1; // recursion available

    uint16_t q_count; // number of question entries
    uint16_t ans_count; // number of answer entries
    uint16_t auth_count; // number of authority entries
    uint16_t add_count; // number of resource entries
} DNS_HEADER, *PDNS_HEADER;

typedef const DNS_HEADER* PCDNS_HEADER;

//Constant sized fields of query structure
typedef struct _QUESTION
{
    uint16_t qtype;
    uint16_t qclass;
} QUESTION, *PQUESTION;

typedef const QUESTION* PCQUESTION;

//Constant sized fields of the resource record structure
#pragma pack(push, 1)
typedef struct _R_DATA
{
    uint16_t type;
    uint16_t _class;
    uint32_t ttl;
    uint16_t data_len;
} R_DATA, *PR_DATA;

typedef const R_DATA* PCR_DATA;
#pragma pack(pop)

//Pointers to resource record contents
typedef struct _RES_RECORD
{
    uint8_t* name;
    R_DATA* resource;
    uint8_t* rdata;
} RES_RECORD, *PRES_RECORD;

typedef const RES_RECORD* PCRES_RECORD;

//Structure of a Query
typedef struct _QUERY
{
    uint8_t* name;
    QUESTION* ques;
} QUERY, *PQUERY;

typedef const QUERY* PCQUERY;



/**
 * @brief Read the host name from a DNS name query
 *
 * @param[in] qname Pointer to data in DNS packet, presumed to be a qname string (e.g. "\3www\6google\3com")
 * @param[in] dns_pkt Pointer to top of DNS packet for offset calculations
 * @param[out] name Buffer to place the url from the name query in (e.g. "www.google.com")
 * @param[in] nameSize Size of the name buffer
 */
void ReadName(const uint8_t* reader, const uint8_t* buffer, uint8_t* name, unsigned nameSize);

/**
 * @brief Converts dotted format name string to DNS qname format string (e.g. "www.google.com" => "\3www\6google\3com")
 *
 * @param[in] host Host format string to convert
 * @param[out] dns Buffer to create DNS QNAME format string in
 *
 * @return Returns true on success, else false
*/
bool ChangetoDnsNameFormat(const char* host, uint8_t* dns);
