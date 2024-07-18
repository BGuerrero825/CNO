//-------------------------------------------------------------------------------------------------
// LSB.h
// 
// Class containing functionality for encoding and decoding LSB payloads, file type agnostic
//-------------------------------------------------------------------------------------------------
#pragma once

#include <stdint.h>
#include <string>


//-------------------------------------------------------------------------------------------------
// Class Declarations
//-------------------------------------------------------------------------------------------------
/**
 * @brief Constructs an object containing a pointer to LSB data and the size of that data.
 * Includes functionality to encode and decode a payload to/from that LSB data.
 * 
 */
class LSB {
public:
    const uint8_t SIZE_BITS = 32;
    uint8_t *data;
    size_t size;

    /**
     * @brief Construct a new LSB object from a data pointer and size
     * 
     * @param inData 
     * @param inSize 
     */
    LSB(uint8_t *inData, size_t inSize);
    
    /**
     * @brief Encodes the payload size with LSB into the first 32 object data bytes
     * 
     * @param payloadSize
     * @return true 
     */
    bool encodeSize(uint32_t payloadSize);

    /**
     * @brief Reads the least significant bit of the first 32 bytes in the image to extract the encoded payload's size
     * @return size_t 
     */
    size_t decodeSize();

    /**
     * @brief Encodes the payload bytes with LSB into the object's data bytes (following the size bytes)
     * 
     * @param payload 
     * @param payloadSize 
     * @return bool
     */
    bool encodeData(const uint8_t * payload, uint32_t payloadSize);

    /**
     * @brief Decodes the data bytes (following the size bytes) of an LSB encoded payload into an allocated buffer
     * 
     * @param payloadSize 
     * @return uint8_t* Pointer to the payload decoded from image (release with free() when done)
     */
    uint8_t * decodeData(size_t payloadSize);

private:
    /**
     * @brief Takes a single byte and returns the value of the least significant bit (0 or 1)
     */
    bool readLSB(uint8_t byte);
};