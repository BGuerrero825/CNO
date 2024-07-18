//-------------------------------------------------------------------------------------------------
// bmp_lsb.h
// 
// Provides LSB embed and extract logic for BMP file format
//-------------------------------------------------------------------------------------------------
#pragma once

#include <stdint.h>

//-------------------------------------------------------------------------------------------------
// Function Declarations
//-------------------------------------------------------------------------------------------------
/**
 * @brief Embed a payload into a BMP image using LSB steganography
 * 
 * @param image The BMP image to modify
 * @param payload Payload to embed
 * @param payloadSize Size of payload in bytes
 * @return Returns true if process succeeds
 */
bool BMPWriteLSB(uint8_t *image, const uint8_t *payload, unsigned payloadSize);

/**
 * @brief Read data that has been LSB stego'd into a BMP image into an allocated buffer
 * 
 * @param image BMP image to process
 * @param payload Pointer to a buffer to allocate for payload (Note: pass to HeapFree() when no longer needed)
 * @param payloadSize Pointer to variable to receive the payload size
 * @return Returns true if action succeeds
 */
bool BMPReadLSB(const uint8_t *image, uint8_t *&payload, unsigned &payloadSize);