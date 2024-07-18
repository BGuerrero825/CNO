//-------------------------------------------------------------------------------------------------
// bmp_lsb.cpp
// 
// Provides embed and extract logic for BMP file format
//-------------------------------------------------------------------------------------------------
#include "bmp_lsb.h"
#include "bmp.h"
#include "LSB.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>


/**
 * @brief Embed a payload into a BMP image using LSB steganography
 * 
 * @param[in,out] image Pointer to the image where the payload will be encoded with LSB
 * @param[in] payload Pointer to the payload to be encoded into the image
 * @param[in] payloadSize Size of payload to encode
 * 
 */
bool BMPWriteLSB(uint8_t *image, const uint8_t *payload, unsigned payloadSize)
{
    // create a struct from the file's BMP header
    PBMPHEADER header = (PBMPHEADER)image;
    // check file type is BMP, starts with chars "BM" 
    if (!(header->FileType == 0x4D42)){
        fprintf(stderr, "ERROR: The image given is not a BMP file, first 2 bytes must be \"BM\".\n");
        return false;
    }

    LSB lsbData(header->PixelData, header->ImageSize);

    
    if(!lsbData.encodeSize(payloadSize)){
        return false;
    }
    if(!lsbData.encodeData(payload, payloadSize)){
        return false;
    }
    return true;
}

/**
 * @brief Read data that has been LSB stego'd into a BMP image into an allocated buffer
 * 
 * @param[in] image Pointer to the image containing an LSB encoded payload
 * @param[out] payload Pointer to the payload decoded from image (release with free() when done)
 * @param[out] payloadSize Size of the decoded payload
 * 
 */
bool BMPReadLSB(const uint8_t *image, uint8_t *&payload, unsigned &payloadSize)
{
    payloadSize = 0;
    payload = nullptr;
    // create a struct from the file's BMP header
    PBMPHEADER header = (PBMPHEADER)image;
    // check file type is BMP, starts with chars "BM" 
    if (!(header->FileType == 0x4D42)){
        fprintf(stderr, "ERROR: The image given is not a BMP file, first 2 bytes must be \"BM\".\n");
        return false;
    }

    LSB lsbData(header->PixelData, header->ImageSize);

    payloadSize = lsbData.decodeSize();
    if (!payloadSize){
        return false;
    }
    
    payload = lsbData.decodeData(payloadSize);
    if (payload == nullptr){
        return false;
    }

    return true;
}