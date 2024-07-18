//-----------------------------------------------------------------------------------------------------------
// WindowsQueries.h
//
// Utility code for calling Windows Queries such as NtQuerySystemInformation(), NtQueryInformationFile(),
//  and related functions, and supporting structures and definitions
//-----------------------------------------------------------------------------------------------------------
#pragma once
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>



/**
 * @brief Needed NTSTATUS codes - including ntstatus.h causes several redefinition conflicts
 *
 * @remark These are normally defined by the DDK, but since we are writing user mode code, define the ones
 *      we need here
 */
#define STATUS_BUFFER_OVERFLOW          ((NTSTATUS)0x80000005L)
#define STATUS_INFO_LENGTH_MISMATCH     ((NTSTATUS)0xC0000004L)
#define STATUS_BUFFER_TOO_SMALL         ((NTSTATUS)0xC0000023L)
#define STATUS_NOT_SUPPORTED            ((NTSTATUS)0xC00000BBL)


//-----------------------------------------------------------------------------------------------------------
// NtQuerySystemInformation() related definitions and functions
//-----------------------------------------------------------------------------------------------------------
/**
 * @brief Partial list of the SYSTEM_INFORMATION_CLASS enumeration for NtQuerySystemInformation
 *
 * @remark This gives Windows version availability of each: https://www.geoffchappell.com/studies/windows/km/ntoskrnl/history/names310.htm
 * @remark Windows Internal Query System Information: http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FSystem%20Information%2FSYSTEM_INFORMATION_CLASS.html
 *
 * @remark These are normally defined by the DDK, but since we are writing user mode code, define the ones
 *      we need here
 */
typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemHandleInformation = 16,                                   // returns SYSTEM_HANDLE_INFORMATION[]
    SystemExtendedHandleInformation = 64,                           // returns SYSTEM_HANDLE_INFORMATION_EX[]
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;


/**
 * @brief Values for _SYSTEM_HANDLE_TABLE_ENTRY_INFO.HandleAttributes
 */
typedef enum _SYSTEM_HANDLE_FLAGS
{
    PROTECT_FROM_CLOSE = 1,
    INHERIT = 2
} SYSTEM_HANDLE_FLAGS;


/**
 * @brief System per handle information
 */
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO                      // size     = 16 (x86), 24 (x64)
{
    uint16_t UniqueProcessId;                                       // offset   =  0 (x86),  0 (x64), size = 2
    uint16_t CreatorBackTraceIndex;                                 // offset   =  2 (x86),  2 (x64), size = 2
    uint8_t ObjectTypeIndex;                                        // offset   =  4 (x86),  4 (x64), size = 1
    uint8_t HandleAttributes; /*SYSTEM_HANDLE_FLAGS*/               // offset   =  5 (x86),  5 (x64), size = 1
    uint16_t HandleValue;                                           // offset   =  6 (x86),  6 (x64), size = 2
    void* Object;                                                   // offset   =  8 (x86),  8 (x64), size = 4/8
    uint32_t GrantedAccess;                                         // offset   = 12 (x86), 16 (x64), size = 4
    // uint32_t _align (x64)                                        // offset   =           20 (x64), size = 0/4
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

/**
 * @brief Array of system handles
 */
typedef struct _SYSTEM_HANDLE_INFORMATION                           // size     = 20 (x86), 32 (x64)
{
    uint32_t NumberOfHandles;                                       // offset   =  0 (x86),  0 (x64), size = 4
    // uint32_t _align (x64)                                        // offset   =            4 (x64), size = 0/4
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];                      // offset   =  4 (x86),  8 (x64)
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;


/**
 * @remark there are more but these are the only potentially relevant ones
 */
typedef enum _FILE_INFORMATION_CLASS {
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation = 2,
    FileBothDirectoryInformation = 3,
    FileBasicInformation = 4,
    FileStandardInformation = 5,
    FileInternalInformation = 6,
    FileEaInformation = 7,
    FileAccessInformation = 8,
    FileNameInformation = 9,
    FileRenameInformation = 10,
    FileNamesInformation = 12,
} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;

//-----------------------------------------------------------------------------------------------------------
// Function Declarations
//-----------------------------------------------------------------------------------------------------------

EXTERN_C_START

/**
 * @brief Query and return the requested type of information (XP+)
 *
 * @param[in] SystemInformationClass The type of system information to query
 *
 * @return Returns the requested information that must be passed to HeapFree() when no longer needed
 * @return Returns NULL on failure
 */
_Success_(return != NULL) void* GetSystemInformation(_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass);


/**
 * @brief Query and return information on all system handles (XP+)
 *
 * @remark May need to use the Ex form to assure compatability with larger handles, process ids, etc.  However, at the
 *      end of 2019, was non-EX structure is still adequate.
 * @remark This function does not require elevation or any special privileges
 * @remark The info class used for this has been available since NT 3.1, but the usermode API has only existed since XP
 *
 * @return Returns allocated list that should be released with HeapFree(GetProcessHeap(), ...), or null if the action fails
 */
_Success_(return != NULL) PSYSTEM_HANDLE_INFORMATION GetSystemHandleInformation();

/**
 * @brief Wraps two calls to NtQueryInformationFile. Once to retrieve the size of the handle's file name
 * @brief and a second time to copy the file name into a supplied buffer.
 * @return wchar_t*, file name of the provided file handle, free with HeapFree()
 */
bool GetFileNameFromHandle(HANDLE fileHandle, wchar_t* fileName, unsigned fileNameSize);










EXTERN_C_END
