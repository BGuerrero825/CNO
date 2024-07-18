/**
 * @file iobuffer.c
 * @author Brian Guerrero
 * @brief structures and constants for the shared memory region
 * @date 2024-05-08
 */

#include <stdint.h>

#define BUFFER_SIZE 1024

const char *mapName = "ProjectC_SharedMem";
const char *serverEventName = "ProjectC_Server";
const char *clientEventName = "ProjectC_Client";

/**
 * @brief Memory layout for IPC messages via file mappings
 */
typedef struct _IOBuffer{
    uint32_t length;
    uint8_t data[BUFFER_SIZE - sizeof(uint32_t)];
} IOBuffer, *pIOBuffer;
