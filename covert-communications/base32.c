//-------------------------------------------------------------------------------------------------
// Base32 implementation
//
// Copyright 2010 Google Inc.
// Author: Markus Gutschke
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-------------------------------------------------------------------------------------------------
#include "pch.h"
#include "base32.h"
#include <string.h>

int base32_decode(const uint8_t* encoded, uint8_t* result, unsigned bufSize)
{
    unsigned buffer = 0;
    unsigned bitsLeft = 0;
    unsigned count = 0;
    for (const uint8_t* ptr = encoded; count < bufSize && *ptr; ++ptr) {
        uint8_t ch = *ptr;
        if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '-') {
            continue;
        }
        buffer <<= 5;

        // Deal with commonly mistyped characters
        if (ch == '0') {
            ch = 'O';
        }
        else if (ch == '1') {
            ch = 'L';
        }
        else if (ch == '8') {
            ch = 'B';
        }

        // Look up one base32 digit
        if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')) {
            ch = (ch & 0x1F) - 1;
        }
        else if (ch >= '2' && ch <= '7') {
            ch -= '2' - 26;
        }
        else {
            return -1;
        }

        buffer |= ch;
        bitsLeft += 5;
        if (bitsLeft >= 8) {
            result[count++] = (uint8_t)(buffer >> (bitsLeft - 8));
            bitsLeft -= 8;
        }
    }
    if (count < bufSize) {
        result[count] = 0;
    }
    return count;
}

int base32_encode(const uint8_t* data, unsigned length, uint8_t* result, unsigned bufSize)
{
    if (length > (1 << 28))
    {
        return -1;
    }

    if (length == 0)
    {
        result[0] = 0;
        return 0;
    }

    unsigned count = 0;
    unsigned buffer = data[0];
    unsigned next = 1;
    unsigned bitsLeft = 8;
    while (count < bufSize && (bitsLeft > 0 || (next < length))) {
        if (bitsLeft < 5) {
            if (next < length) {
                buffer <<= 8;
                buffer |= data[next++] & 0xFF;
                bitsLeft += 8;
            }
            else {
                int pad = 5 - bitsLeft;
                buffer <<= pad;
                bitsLeft += pad;
            }
        }
        int index = 0x1F & (buffer >> (bitsLeft - 5));
        bitsLeft -= 5;
        // decoder supports upper or lower case. Use lowercase here to look more natural in the url strings
        result[count++] = "abcdefghijklmnopqrstuvwxyz234567"[index];
    }
    if (count < bufSize) {
        result[count] = 0;
    }
    return count;
}