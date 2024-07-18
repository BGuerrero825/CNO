//-------------------------------------------------------------------------------------------------
// main.c
//
// Main entry point and code for self-loader module
//-------------------------------------------------------------------------------------------------
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "PELoader.h"

// exit/return codes for this project
typedef enum _ReturnCode
{
    SUCCESS = 0,
    FAIL = 1
} ReturnCode;

// Dll to load for test
static const char* const TEST_PAYLOAD = "DllPayload.dll";

//
// App entry point
//
int main(int argc, char *argv[])
{
    //
    // Allow a command line argument to specify an alternative DLL to load, otherwise, continue to load
    // TEST_PAYLOAD. Remember, don't call DllMain() if an alternative binary is given.
    //
    // START: //////////////////////////////// Extra Credit ////////////////////////////////

    (void)argc;
    (void)argv;

    // in practice, you will load from memory, but our test payload is a DLL on disk, so we will map that into memory before loading it
    HMODULE hMod = LoadDllFromFile(TEST_PAYLOAD);
    if (hMod == NULL)
    {
        // assume loader printed error details
        return FAIL;
    }

    // END:   //////////////////////////////// Extra Credit ////////////////////////////////

    //
    // Call DllMain() with DLL_PROCESS_ATTACH for the loaded test payload, then wait for user input and call DllMain() will DLL_PROCESS_DETACH.
    //  Take advantage of utility code provided
    //
    // Then clean-up; release any resources necessary
    //
    // START: //////////////////////////////// Part 1 ////////////////////////////////

    if (!callDllMain(hMod, DLL_PROCESS_ATTACH))
    {
        fprintf(stderr, "Failed to call entry of point of loaded executable.\n");
        VirtualFree(hMod, 0, MEM_RELEASE);
        return FAIL;
    }

    printf("Running loaded executable.\n");
    system("pause");

    if (!callDllMain(hMod, DLL_PROCESS_DETACH))
    {
        fprintf(stderr, "Failed to detach loaded excutable.\n");
    }

    VirtualFree(hMod, 0, MEM_RELEASE);

    // END:   //////////////////////////////// Part 1 ////////////////////////////////

    return SUCCESS;
}
