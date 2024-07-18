//-----------------------------------------------------------------------------------------------------------
// WindowsQueries.c
//
// Utility code for calling Windows Queries such as NtQuerySystemInformation(), NtQueryInformationFile(),
//  and related functions, and supporting structures and definitions
//-----------------------------------------------------------------------------------------------------------
#include "WindowsQueries.h"
#include <stdio.h>


//-----------------------------------------------------------------------------------------------------------
// General Definitions
//-----------------------------------------------------------------------------------------------------------
#define MODULE_NTDLL "ntdll"

//-----------------------------------------------------------------------------------------------------------
// NtQuerySystemInformation() related definitions and functions
//-----------------------------------------------------------------------------------------------------------
/**
 * @brief Dynamically link and call NtQuerySystemInformation() - Queries various system information, based on SYSTEM_INFORMATION_CLASS
 *
 * @remark This is a mostly undocumented but very powerful Windows API call.
 * @remark This API function has been available since the original XP, but the functions and their returns have changed over time, primarily through extension
 *
 * @param[in] SystemInformationClass Information class to query
 * @param[out] SystemInformation Pointer to a structure specific to the information class being queried
 * @param[in] SystemInformationLength Size of buffer passed for SystemInformation
 * @param[out] ReturnLength (Optional) Pointer to a value where the actual/needed SystemInformation buffer size is returned
 *
 * @return Returns STATUS_SUCCESS on success, or an error code on failure.
 */
static
_Success_(SUCCEEDED(return))
NTSTATUS
NtQuerySystemInformation(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_writes_bytes_to_opt_(SystemInformationLength, *ReturnLength) void* SystemInformation,
    _In_ uint32_t SystemInformationLength,
    _Out_opt_ uint32_t* ReturnLength)
{
    /**
     * @brief Function type for NtQuerySystemInformation from ntdll.dll
     */
    typedef NTSTATUS (WINAPI * FN_NtQuerySystemInformation)(
                                                    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
                                                    _Out_writes_bytes_to_opt_(SystemInformationLength, *ReturnLength) void* SystemInformation,
                                                    _In_ uint32_t SystemInformationLength,
                                                    _Out_opt_ uint32_t* ReturnLength);

    static bool initialized = false;
    static FN_NtQuerySystemInformation fn_NtQuerySystemInformation = NULL;

    // get a pointer to the function the first time this is called
    if (!initialized)
    {
        initialized = true;
        HANDLE hNtdll = GetModuleHandleA(MODULE_NTDLL);
        if (hNtdll == NULL)
        {
            printf("Error, GetModuleHandle('ntdll') failed (%u)\n", GetLastError());
            return STATUS_NOT_SUPPORTED;
        }
        fn_NtQuerySystemInformation = (FN_NtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
        if (fn_NtQuerySystemInformation == NULL)
        {
            printf("Error, GetProcAddress('NtQuerySystemInformation') failed (%u)\n", GetLastError());
        }
        // Note: Intentionally leaking module handle here for common module because we need it to remain loaded
    }

    // If we were unable to link the function, the call cannot be supported
    if (fn_NtQuerySystemInformation == NULL)
    {
        return STATUS_NOT_SUPPORTED;
    }
    return fn_NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}


/* Query and return the requested type of information (XP+) */
_Success_(return != NULL) void* GetSystemInformation(_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass)
{
    void* buffer = NULL;
    uint32_t bufferSize = 0;

    // make the query, first with a null buffer to determine size, then with an allocated buffer. Continue
    //      looping if necessary until the allocated buffer is large enough
    do {
        uint32_t bytesNeeded = 0;
        NTSTATUS status = NtQuerySystemInformation(SystemInformationClass, buffer, bufferSize, &bytesNeeded);
        // if the call succeeded, we're done
        if (SUCCEEDED(status) && buffer != NULL)
        {
            break;
        }

        // if the call failed, we don't need the previous buffer, if any (even if to resize the buffer)
        if (buffer != NULL)
        {
            HeapFree(GetProcessHeap(), 0, buffer);
            buffer = NULL;
        }

        // if the status is anything but length mismatch, we're done, action failed
        if (status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL)
        {
            printf("Error, NtQuerySystemInformation failed (%08X)\n", status);
            break;
        }

        // allocate a buffer the requested size
        bufferSize = bytesNeeded;
        buffer = HeapAlloc(GetProcessHeap(), 0, bufferSize);
        if (buffer == NULL)
        {
            printf("Error, GetSystemInformation, Allocation failure (%u)\n", GetLastError());
            return NULL;
        }
    } while (true);

    return buffer;
}


/* Query and return information on all system handles (XP+) */
_Success_(return != NULL) PSYSTEM_HANDLE_INFORMATION GetSystemHandleInformation()
{
    return (PSYSTEM_HANDLE_INFORMATION)GetSystemInformation(SystemHandleInformation);
}



//-----------------------------------------------------------------------------------------------------------
// NtQueryInformationFile() related definitions and functions
//-----------------------------------------------------------------------------------------------------------

/**
 * @brief Final status of an I/O request (required by NtQueryInformationFile)
 */
#pragma warning(disable:4201)
typedef struct _IO_STATUS_BLOCK
{
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

/**
 * @brief File name information returned from NtQueryInformationFile
 */
typedef struct _FILE_NAME_INFORMATION {
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NAME_INFORMATION, * PFILE_NAME_INFORMATION;

/**
 * @brief Dynamically link and call NtQueryInformationFile() - Queries given file information, based on FILE_NAME_INFORMATION
 *
 * @remark This is an undocumented Windows API
 *
 * @param[in] FileHandle, Handle to the file to be queried on
 * @param[out] IoStatusBlock, Unused, status of resulting IO operations
 * @param[out] FileInformation, A preallocated buffer to store the result of the query
 * @param[in] Length, The length of the provided FileInformation buffer
 * @param[in] FileInformationClass, The type of information to be queried (class enum)
 * @param[out] ReturnLength (Optional) Pointer to a value where the actual/needed SystemInformation buffer size is returned
 *
 * @return Returns STATUS_SUCCESS on success, or an error code on failure.
 */
static
_Success_(SUCCEEDED(return))
NTSTATUS
NtQueryInformationFile(
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_ void* FileInformation,
    _In_ unsigned long Length,
    _In_ FILE_INFORMATION_CLASS FileInformationClass)

{
    /**
     * @brief Function type for NtQuerySystemInformation from ntdll.dll
     */
    typedef NTSTATUS(WINAPI * FN_NtQueryInformationFile)(
        _In_ HANDLE FileHandle,
        _Out_ PIO_STATUS_BLOCK IoStatusBlock,
        _Out_ void* FileInformation,
        _In_ unsigned long Length,
        _In_ FILE_INFORMATION_CLASS FileInformationClass);

    static bool initialized = false;
    static FN_NtQueryInformationFile fn_NtQueryInformationFile = NULL;

    // get a pointer to the function the first time this is called
    if (!initialized)
    {
        initialized = true;
        HANDLE hNtdll = GetModuleHandleA(MODULE_NTDLL);
        if (hNtdll == NULL)
        {
            printf("Error, GetModuleHandle('NtosKrnl') failed (%u)\n", GetLastError());
            return STATUS_NOT_SUPPORTED;
        }
        fn_NtQueryInformationFile = (FN_NtQueryInformationFile) GetProcAddress(hNtdll, "NtQueryInformationFile");
        if (NtQueryInformationFile == NULL)
        {
            printf("Error, GetProcAddress('NtQueryInformationFile') failed (%u)\n", GetLastError());
        }
        // Note: Intentionally leaking module handle here for common module because we need it to remain loaded
    }

    // If we were unable to link the function, the call cannot be supported
    if (fn_NtQueryInformationFile == NULL)
    {
        return STATUS_NOT_SUPPORTED;
    }
    return fn_NtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
}


bool GetFileNameFromHandle(HANDLE fileHandle, wchar_t * fileName, unsigned fileNameSize)
{
   // query file information once with an undersized buffer to get the size of the file name
   IO_STATUS_BLOCK ioStatusBlock;
   FILE_NAME_INFORMATION tempInfo;
   NTSTATUS status = NtQueryInformationFile(fileHandle, &ioStatusBlock, &tempInfo, sizeof(tempInfo), FileNameInformation);
   if (status != STATUS_BUFFER_OVERFLOW)
   {
       //fprintf(stderr, "NtQueryInformationFile failed for a reason besides buffer overflow. NTSTATUS: %08X\n", status);
       return false;
   }

   // query file information again with proper buffer size for file name
   // info stored by FILE_NAME_INFORMATION: fileNameLength, FileName[length], null_terminator
   unsigned fileInfoSize = tempInfo.FileNameLength + sizeof(FILE_NAME_INFORMATION);
   PFILE_NAME_INFORMATION fileInfo = malloc(fileInfoSize);
   if (!fileInfo)
   {
       fprintf(stderr, "Failed to allocate buffer for file information.\n");
       free(fileInfo);
       return false;
   }
   status = NtQueryInformationFile(fileHandle, &ioStatusBlock, fileInfo, fileInfoSize, FileNameInformation);
   if (!SUCCEEDED(status))
   {
       fprintf(stderr, "NtQueryInformationFile failed. NTSTATUS: %08X\n", status);
       free(fileInfo);
       return false;
   }

   // check if retrieved file name (including added null terminator) is larger than given buffer
   if (fileInfo->FileNameLength >= fileNameSize)
   {
       fprintf(stderr, "Retrieved file name length exceeded given buffer\n");
       free(fileInfo);
       return false;
   }

   // change character after end of char buffer to a null terminator
   fileInfo->FileName[fileInfo->FileNameLength / sizeof(fileInfo->FileName[0])] = 0;

   wcscpy_s(fileName, fileNameSize / sizeof(fileInfo->FileName[0]), fileInfo->FileName);

   free(fileInfo);
   return true;
}
