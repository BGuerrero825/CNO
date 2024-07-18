//---------------------------------------------------------------------------------------------------------------------
//  main.c
//
//  Detection Avoidance module lab for programmatically accessing Windows eventlogs files
//---------------------------------------------------------------------------------------------------------------------
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include "SeDebugPrivilege.h"
#include "WindowsQueries.h"
#include "EventLogAccess.h"


//---------------------------------------------------------------------------------------------------------------------
// Begin Code
//---------------------------------------------------------------------------------------------------------------------
/**
 * @brief Main entry point of application
 */
int main()
{
    /*
     * Use what you learned in the last section to write code that can access and report the contents of System.evtx:

        1. Complete each of the code features described in this section that are not already provided.
        2. Create a function that will return a local handle for a specified event log file
            Find the process id for the Eventlogs Service
            Query System Handles List
            Iterate list, skipping any that are not File ObjectTypeIndex and for the Eventlogs Service Process
            Create a local duplicate of the handle
            Get file name from the duplicate handle
            If name doesn't match the desired event log, clean up and keep searching
            Tip: Check for “ends with ‘\\System.evtx’
            If found, cleanup and return the duplicate file handle
        3. Use CreateFileMapping()/MapViewOfFile() to map file header and dump the header fields (printf)

        Extra Credit: Figure out how to map active chunk and dump some fields from it
        Extra Credit: Allow the log file name to be given on the command line

        Remember: The module snapshot action requires admin, so run Visual Studio as admin while debugging
        Remember also that if the module snapshot returns error 299 (ERROR_PARTIAL_COPY), that you are running mixed bit code; most likely
            you built an x86 app and are running it on a 64-bit Windows. On the other hand, if the process snapshot works, but the module
            snapshot returns ERROR_PARTIAL_COPY, you are snapshotting modules for a 32-bit process, so you must not be looking at svchost.exe
     */
    //
    // START: //////////////////////////// IMPLEMENT LAB3 main code HERE ////////////////////////////

    // Locate the Windows Event Log process which has name svchost.exe and the loaded module wevtsvc.dll
    unsigned svchostPID = FindProcessWithModule(SERVICE_HOST_EXE, EVENTLOG_SERVICE_DLL);
    if (!svchostPID)
    {
        return EXIT_FAILURE;
    }
    // printf("Got Process ID: %u\n", svchostPID);

    if (!SetDebugPrivilege(true))
    {
        return EXIT_FAILURE;
    }

    HANDLE fileHandle = FindFileHandleByName(svchostPID, EVTX_PATH);
    if (!fileHandle) {
        return EXIT_FAILURE;
    }

    if (!DumpEvtxFileHeader(fileHandle))
    {
        CloseHandle(fileHandle);
        return EXIT_FAILURE;
    }

    if (!DumpEvtxFirstChunkHeader(fileHandle))
    {
        CloseHandle(fileHandle);
        return EXIT_FAILURE;
    }

    CloseHandle(fileHandle);

    if (!SetDebugPrivilege(false))
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
    //
    // END:   /////////////////////////////////// LAB3 main code ////////////////////////////////////
    //
}
