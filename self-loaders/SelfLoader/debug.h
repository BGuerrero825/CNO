//---------------------------------------------------------------------------------------------------------------------
// debug.h
//
// Debugging tools (e.g. DBGPRINT() and hex dump)
//---------------------------------------------------------------------------------------------------------------------
#pragma once
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>


// This will allow us to use DBGPRINT() that can later be converted to use OutputDebugString() for actual code
#if _DEBUG
#define DBGPRINT    printf
#else
#define DBGPRINT(...) (void)0
#endif

// TODO: It is also handy to have a hex dump function that converts a block of bytes to hex and prints them via
//  DBGPRINT()
void HexDump(const void* data, size_t length);