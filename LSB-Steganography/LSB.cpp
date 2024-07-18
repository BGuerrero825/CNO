//-------------------------------------------------------------------------------------------------
// LSB.cpp
// 
// Class containing functionality for encoding and decoding LSB payloads, file type agnostic
//-------------------------------------------------------------------------------------------------

#include "LSB.h"


/**
 * @brief Construct a new LSB object from a data pointer and size
 * 
 * @param inData 
 * @param inSize 
 */
LSB::LSB(uint8_t *inData, size_t inSize){
    data = inData;
    size = inSize; 
}


/**
 * @brief Encodes the payload size with LSB into the first 32 object data bytes
 * 
 * @param payloadSize
 * @return true 
 */
bool LSB::encodeSize(uint32_t payloadSize){
    uint32_t bitMask = 0x80000000;
    if (size < SIZE_BITS){
        fprintf(stderr, "ERROR: Could not encode payload size, target file must have at least %u bytes of data.\n", SIZE_BITS);
        return false;
    }
    for (uint8_t idx = 0; idx < SIZE_BITS; idx++){
        // mask away the last bit of data[idx], add it back in if the corresponsing masked bit of payloadSize is set
        data[idx] = (data[idx] & 0xFE) | (bool)(payloadSize & bitMask);
        bitMask = bitMask >> 1;
    }
    return true;


}
/**
 * @brief Reads the least significant bit of the first 32 bytes in the image to extract the encoded payload's size
 * @return size_t 
 */
size_t LSB::decodeSize(){
    size_t payloadSize = 0;
    if (size < SIZE_BITS){
        fprintf(stderr, "ERROR: Could not decode payload size, target file must have at least %u bytes of data.\n", SIZE_BITS);
        return 0;
    }
    for(uint8_t idx = 0; idx < SIZE_BITS; idx++){
        // add to the size value the least significant bit, shifted left by # of size bits - 1 - current index. (index 0, shift left 31 bits)
        payloadSize += readLSB(data[idx]) << ((SIZE_BITS - 1) - idx);
    }
    return payloadSize;


}
/**
 * @brief Encodes the payload bytes with LSB into the object's data bytes (following the size bytes)
 * 
 * @param payload 
 * @param payloadSize 
 * @return bool
 */
bool LSB::encodeData(const uint8_t * payload, uint32_t payloadSize){
    uint8_t bitMask = 0x80;
    uint32_t idx = 0;
    // check that the number of bits to encode does not exceed the number of bytes available
    if (payloadSize * 8 > (size - SIZE_BITS)){
        fprintf(stderr, "Error: Could not encode payload data, target file data (%u bytes) must be larger than payload data in bits (%u bits).\n", size - SIZE_BITS, payloadSize * 8);
        return false;
    }
    while(idx < payloadSize * 8 && idx < (size - SIZE_BITS)){
        // mask away the last bit of data[idx], add it back in if the corresponsing masked bit of the payload bit is set
        data[idx + SIZE_BITS] = (data[idx + SIZE_BITS] & 0xFE) | (bool)(bitMask & payload[idx/8]);
        bitMask = bitMask >> 1; 
        // reset mask if shifted to 0
        if (bitMask == 0){
            bitMask = 0x80;
        }
        idx++;
    }
    return true;


}
/**
 * @brief Decodes the data bytes (following the size bytes) of an LSB encoded payload into an allocated buffer
 * 
 * @param payloadSize 
 * @return uint8_t* Pointer to the payload decoded from image (release with free() when done)
 */
uint8_t * LSB::decodeData(size_t payloadSize){
    // check that the number of bits to encode does not exceed the number of bytes available
    if (payloadSize * 8 > (size - SIZE_BITS)){
        fprintf(stderr, "ERROR: Could not decode payload data, target file data (%u bytes) must be larger than payload data in bits (%u bits).\n", size - SIZE_BITS, payloadSize * 8);
        return nullptr;
    }
    //create a buffer to hold the decoded payload, intialized to 0
    uint8_t * payloadBuffer = (uint8_t *)calloc(payloadSize, sizeof(uint8_t));
    size_t idx = 0;
    // while payload size (in bits) and image size (in bytes) have not been exceeded
    while (idx < payloadSize * 8 && idx < (size - SIZE_BITS)){
        // to the payload buffer byte (index / 8), add the smallest bit from the image's indexed pixel data, bit shifted left by the index mod 8
        payloadBuffer[idx/8] += readLSB(data[idx + SIZE_BITS]) << (7 - (idx % 8));
        idx++;
    }
    return payloadBuffer;
}


/**
 * @brief Takes a single byte and returns the value of the least significant bit (0 or 1)
 */
bool LSB::readLSB(uint8_t byte){
    return byte & 0x01;
}