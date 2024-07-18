//-------------------------------------------------------------------------------------------------
// bmp.h
// 
// BMP related definitions
//-------------------------------------------------------------------------------------------------
#pragma once

#include <stdint.h>

//-------------------------------------------------------------------------------------------------
// Definitions and types
//-------------------------------------------------------------------------------------------------
/**
 * Structure of a BMP file header
 */
const uint16_t BMP_TYPE = 0x4D42;   // BMP file type field ("BM")

#pragma warning(disable :4200)
#pragma pack(push, 1) // keep compiler from adding alignment bytes
typedef struct _BMPHEADER
{
    uint16_t FileType;              // for BMP, this is 42 4D ("BM")
    uint32_t FileSize;              // file size, in bytes
    uint16_t reserved1;
    uint16_t reserved2;
    uint32_t PixelDataOffset;       // file offset of start of pixel data (should be sizeof(BMPHEADER), 54 bytes)
    uint32_t HeaderSize;            // size of remaining header, including this member (40 bytes for standard BMP)
    uint32_t ImageWidth;            // image width in pixels
    uint32_t ImageHeight;           // image height in pixels
    uint16_t Planes;                // number of planes in image (normally 1, but not important)
    uint16_t BitsPerPixel;          // bits per pixel (24 for standard BMP (R,G,B))
    uint32_t Compression;           // compression type (should be None (0))
    uint32_t ImageSize;             // size of image data in bytes (should be FileSize - PixelDataOffset)
    uint32_t XPixelsPerMeter;
    uint32_t YPixelsPerMeter;
    uint32_t TotalColors;
    uint32_t ImportantColors;

    // Present only if BitsPerPixel is less than 8
    // char Red;
    // char Green;
    // char Blue;
    // char Reserved3;

    // Note: If your compiler warns that this is unsupported, you are welcome to put a 1 as the array size, but then don't use
    //      sizeof(BMPHEADER) as the size of the base header and offset of PixelData.
    uint8_t PixelData[];            // pixel data as a byte array (actual pixels are BitsPerPixel/8 bytes long)

} BMPHEADER, *PBMPHEADER;

typedef const BMPHEADER* PCBMPHEADER;

#pragma pack(pop)
