//---------------------------------------------------------------------------------------------------------------------
//  EventLogAccess.h
//
//  Utilities for programmatically accessing Windows eventlogs files
//---------------------------------------------------------------------------------------------------------------------
#pragma once
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>


//---------------------------------------------------------------------------------------------------------------------
// Definitions and structures
//---------------------------------------------------------------------------------------------------------------------
/**
 * @brief Windows EventLog Service name and related definitions
 */
#define EVENTLOG_SERVICE_NAME   L"EventLog"     // service name of Windows EventLog Service
#define EVENTLOG_SERVICE_DLL    L"wevtsvc.dll"  // dll name of Windows EventLog Service
#define SERVICE_HOST_EXE        L"svchost.exe"  // service host executable name
#define EVTX_PATH               L"\\Windows\\System32\\winevt\\Logs\\System.evtx" // logs location


 /**
 * @brief EVTX File Header structure
 *
 * @remark Items marked with (*) need to be updated if the file contents are modified
 * @remark LastChunkNumber, NextRecordId, and NumberOfChunks, and sometimes FirstChunkNumber, are not always representative of the data in the file.  As records are added,
 *      and the current chunk changes, these three values are not kept up to date (in the file) and therefore the checksum is not recalculated.  They appear to be accurate
 *      after a reboot.  It appears that the header is maintained in memory for performance reasons, and is only occasionally written to disk, primarily at shutdown.
 * @remark Rotating Overwrites - when a file is configured to overwrite when full, it does so but rotating through the buffers.  So when the last chunk in the file is full,
 *      FirstChunkNumber will be changed from 0 to 1, LastChunkNumber will be set to 0, and the first chunk will be initialized to all free space.  When it is full,
 *      FirstChunkNumber will change to 2, LastChunkNumber to 1, and the process continues in a loop
 */
#define EVTX_FILE_HEADER_SIZE        128                    // used header size - see EVTX_FILE_FIRST_CHUNK_OFFSET for additional details
#define EVTX_FILE_HDR_SIGNATURE      "ElfFile"              // signature from first 8 bytes of EVTX header as an ASCII string (including the null terminator character)
#define EVTX_FILE_HDR_SIGNATURE_BIN  0x00656C6946666C45llu  // signature from first 8 bytes of EVTX header as a 64-bit unsigned integer
#define EVTX_FILE_HDR_SIGNATURE_SIZE 8                      // size of the file header signature in bytes
#define EVTX_HEADER_CRC_SIZE         120                    // size of area prior to checksum that is covered in the CRC
#define EVTX_FILE_HEADER_BLOCK_SIZE  4096                   // size of header block, including 3968 bytes of unused space
 //      Note: The remaining 3968 bytes to first chunk are unused and zero filled (but are not checked by CRC and may be freely modified)
#define EVTX_FILE_FIRST_CHUNK_OFFSET  EVTX_FILE_HEADER_BLOCK_SIZE // athough the used header is only 128 bytes, 4K is reserved at the start of the file before the first chunk
#define EVTX_FILE_MAJOR_VERSION      3                      // major version number for EVTX files
#define EVTX_FILE_MINOR_VERSION      2                      // minor version number for EVTX files (3.1 existed up to about Win11, then 3.2)
#define EVTX_FILE_HEADER_SIGNATURE(pH)  *((uint64_t*)((pH)->Signature))

typedef struct _EVTX_FILE_HEADER {
    uint8_t Signature[EVTX_FILE_HDR_SIGNATURE_SIZE];        // signature value (see above)
    uint64_t FirstChunkNumber;                              // 0-based index of the first (oldest) chunk in use (initially 0) (Note: If this value is non-zero, it should be one
                                                            //   greater than LastChunkNumber (see Rotating Overwrites above)
    uint64_t LastChunkNumber;                               // 0-based index of the last (newest) chunk in the file (initially 0) - this is the chunk that is currently being written to
    uint64_t NextRecordId;                                  // 1-based identity value to provide unique ids to each event record in the file (initially 1, incremented on add) (*)
    uint32_t HeaderSize;                                    // size of the file header (128)
    uint16_t MinorVersion;                                  // minor version number (3)
    uint16_t MajorVersion;                                  // major version number (1 or 2)
    uint16_t FirstChunkOffset;                              // first chunk offset / size of header block (4096)
    uint16_t NumberOfChunks;                                // number of 64K chunks in the file (initially 1)
    uint8_t Unused[76];                                     // unused section of header (zero filled, included in header checksum)
    uint32_t Flags;                                         // file level flags (see EVTX_FILE_FLAGS) (initially 0)
    uint32_t Checksum;                                      // CRC32 of the first 120 bytes of the file header (*)
    // uint8_t Unused2[3968];                               // unused space before first chunk in file (Note: Not included in checksum, can be freely modified)
} EVTX_FILE_HEADER, * PEVTX_FILE_HEADER;

typedef const EVTX_FILE_HEADER* PCEVTX_FILE_HEADER;


/**
 * @brief EVTX Chunk Header structure
 *
 * @remark Items marked with (*) need to be updated if the file contents are modified
 * @remark All offsets in chunk are relative to the start of the 64K chunk
 */
#define EVTX_CHUNK_HEADER_SIZE        128                   // formal chunk header size
#define EVTX_CHUNK_FULL_HEADER_SIZE   512                   // size of header and pointer data sections (everything prior to the variable sized event record data area)
#define EVTX_CHUNK_SIZE               (64<<10)              // size of full chunk
#define EVTX_CHUNK_HDR_SIGNATURE      "ElfChnk"             // signature from first 8 bytes of EVTX chunk header as an ASCII string (including the null terminator character)
#define EVTX_CHUNK_HDR_SIGNATURE_BIN  0x006B6E6843666C45llu // signature from first 8 bytes of EVTX chunk header as a 64-bit unsigned integer
#define EVTX_CHUNK_HDR_SIGNATURE_SIZE 8                     // size of the chunk header signature in bytes
#define EVTX_CHUNK_EVENT_DATA_OFFSET  512                   // offset of the event data within an EVTX chunk
#define EVTX_CHUNK_STRING_PTR_COUNT   64                    // number of common string pointers/offsets in the pointer data section of the chunk
#define EVTX_CHUNK_TEMPLATE_PTR_COUNT 32                    // number of Template pointers/offsets in the pointer data section of the chunk

#define EVTX_CHUNK_SIGNATURE(pC)            *((const uint64_t*)((pC)->Signature))
#define EVTX_CHUNK_AT_OFFSET(pC, offs)      ((const uint8_t*)(pC) + offs)
#define EVTX_CHUNK_POINTER_DATA(pC)         EVTX_CHUNK_AT_OFFSET(pC, EVTX_CHUNK_HEADER_SIZE)
#define EVTX_CHUNK_POINTER_DATA_SIZE(pC)    (EVTX_CHUNK_FULL_HEADER_SIZE - EVTX_CHUNK_HEADER_SIZE)
#define EVTX_CHUNK_EVENT_DATA(pC)           EVTX_CHUNK_AT_OFFSET(pC, EVTX_CHUNK_EVENT_DATA_OFFSET)
#define EVTX_CHUNK_EVENT_DATA_SIZE(pC)      (((pC)->FreeSpaceOffset >= EVTX_CHUNK_EVENT_DATA_OFFSET) ? ((pC)->FreeSpaceOffset - EVTX_CHUNK_EVENT_DATA_OFFSET) : 0)
#define EVTX_CHUNK_FREE_SPACE(pC)           EVTX_CHUNK_AT_OFFSET(pC, (pC)->FreeSpaceOffset)
#define EVTX_CHUNK_FREE_SPACE_SIZE(pC)      (((pC)->FreeSpaceOffset >= EVTX_CHUNK_EVENT_DATA_OFFSET) ? (EVTX_CHUNK_SIZE - (pC)->FreeSpaceOffset) : 0)
#define EVTX_CHUNK_FILE_OFFSET(chunkIndex)  (EVTX_FILE_FIRST_CHUNK_OFFSET + ((uint64_t)(chunkIndex) * EVTX_CHUNK_SIZE)) // chunkIndex is 0-based

typedef struct _EVTX_CHUNK_HEADER {
    uint8_t  Signature[EVTX_FILE_HDR_SIGNATURE_SIZE];       // signature value (see above)
    uint64_t FirstEventRecordNumber;                        // number of the first event record (initally 1) (Note: Except for empty records, this value generally matches FirstEventRecordId)
    uint64_t LastEventRecordNumber;                         // number of the last event record (initally -1) (*) (Note: This value generally matches LastEventRecordId)
    uint64_t FirstEventRecordId;                            // identifier of the first event record (initally -1)
    uint64_t LastEventRecordId;                             // identifier of the last event record (initally -1) (*)
    uint32_t PointerDataOffset;                             // offset into the chunk of the pointer data / base header size (128)
    uint32_t LastEventRecordOffset;                         // offset from start of chunk of last event record in this chunk (initially 0) (*)
    uint32_t FreeSpaceOffset;                               // offset from start of chunk of the unused portion at the end of the chunk (initially 512) (*)
    uint32_t EventRecordsChecksum;                          // CRC32 of the event records in this chunk (initially 0) (*)
    uint8_t Unused[64];                                     // unused section of header (zero filled, included in header checksum)
    uint32_t InUseFlag;                                     // appears to be a boolean value that is 1 if the chunk is initialized and in use
    uint32_t Checksum;                                      // CRC32 of the first 120 bytes of the chunk header and pointer data section (*)
    // ---------------- end of formal header --------------------
    uint32_t CommonStrings[EVTX_CHUNK_STRING_PTR_COUNT];    // array of offsets of common strings that can be shared within the chunk
    uint32_t Templates[EVTX_CHUNK_TEMPLATE_PTR_COUNT];      // array of offsets of event templates (?)
    // ---------------- begin event data, remaining chunk space totals 65024 bytes ----------------------------------
    // uint8_t EventRecordData[];                           // variable sized event records from 512 to FreeSpaceOffset (EventRecordsChecksum covers this region)
    // uint8_t FreeSpace[];                                 // begins at FreeSpaceOffset (Note: It is common to find fragments of old event records here, this is not included in any CRC)
} EVTX_CHUNK_HEADER, * PEVTX_CHUNK_HEADER;

typedef const EVTX_CHUNK_HEADER* PCEVTX_CHUNK_HEADER;

#define EVTX_EVENT_RECORD_SIGNATURE   "**\0"                // signature from first 4 bytes of Event Record as an ASCII string (including double null terminator characters)
#define EVTX_EVENT_RECORD_SIGNATURE_BIN  0x00002A2Alu       // signature from first 4 bytes of Event Record as a 32-bit unsigned integer
#define EVTX_EVENT_RECORD_DATA_OFFSET    24                 // size of event record prior to variable length BinXml data

/**
 * @brief EVTX Event Record Layout
 */
typedef struct _EVTX_EVENT_RECORD {
    uint32_t Signature;                                     // signature value (see above)N
    uint32_t Size;                                          // event record size (1st copy)
    uint64_t Id;                                            // standard event identifier for this event
    uint64_t CreateTime;                                    // date/time event record was written to the log (Windows FILETIME format, UTC)
    // BinXml RecordData;                                   // variable sized record data in BinXml format
    // uint32_t SizeCopy;                                   // copy of record size (must match Size)
} EVTX_EVENT_RECORD, * PEVTX_EVENT_RECORD;

/**
 * @brief Finds the PID of a process matching a given name and having a loaded module of given name. Returns PID if found, 0 if not found.
 * @param processName, name of desired process as a wide string
 * @param moduleName, name of desired loaded module as a wide string
 * @return DWORD, PID of found process | 0 = ERROR
 */
unsigned FindProcessWithModule(const wchar_t* processName, const wchar_t* moduleName);

/**
 * @brief Searches loaded modules in the given process PID for the given module name. Returns true if found, false if not found.
 * @param processPID, PID of the process to search modules in
 * @param moduleName, name of desired loaded module as a wide string
 * @return bool, true = module found | false = module not found.
 */
bool FindLoadedModule(unsigned processPID, const wchar_t* moduleName);

/**
 * @brief DuplicateHandle() wrapper requesting the same privileges and duplicating to the current process
 * @param processPID, the process to copy from
 * @param desiredHandle, handle to copy from the process
 * @return HANDLE, copied handle value in the current process
 */
HANDLE DuplicateHandleFromProcess(HANDLE processPID, HANDLE desiredHandle);

/**
 * @brief Duplicates file handles in the given process, retrieves the file name, then returns any that match the requested file name.
 * @param processPID, the process ID to search for files handles.
 * @param requestedFileName, the name the file handle name should match.
 * @return HANDLE, file handle with name matching requested file name. Must be freed with CloseHandle()
 */
HANDLE FindFileHandleByName(unsigned processPID, const wchar_t* requestedFileName);

/**
 * @brief Maps a view into the given file handle if an evtx and prints the file header
 * @param fileHandle, a handle to the evtx file to print
 * @return bool, 0 = SUCCESS | 1 = FAILURE
 */
bool DumpEvtxFileHeader(HANDLE fileHandle);

/**
 * @brief Maps a view into the given file handle if an evtx and prints the file header
 * @param fileHandle, a handle to the evtx file to print
 * @return bool, 0 = SUCCESS | 1 = FAILURE
 */
bool DumpEvtxFirstChunkHeader(HANDLE fileHandle);




