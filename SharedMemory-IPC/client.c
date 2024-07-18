/**
 * @file client.c
 * @author Brian Guerrero
 * @brief Shared memory client, sends messages to a server
 * @date 2024-05-08
 * 
 */


#include <windows.h>
#include <stdio.h>
#include <conio.h>

#include "iobuffer.h"

//*********************************************************************************
// DECLARATIONS
//*********************************************************************************

/**
 * @brief Opens a name file mapping and creates pointers to server and client IOBuffers within the file mapping.
 * 
 * @param[out] pServerBuf pointer to the server IOBuffer pointer
 * @param[out] pClientBuf pointer to the client IOBuffer pointer
 * @return HANDLE, to the file mapping
 */
HANDLE openFileBuffers(pIOBuffer *pServerBuf, pIOBuffer *pClientBuf);

/**
 * @brief Opens event objects for use by the server and client for IPC
 * 
 * @param[out] hServerEvent pointer to a server controlled event handle
 * @param[out] hClientEvent pointer to a client controlled event handle
 * @return int, 0 = SUCCESS | 1 = ERROR
 */
int openEvents(HANDLE *hServerEvent, HANDLE *hClientEvent);


/**
 * @brief Sends a list of preset strings to the specified server one at a time, retransmitting if no response after 1 seconds or if response is not the correct message.
 * 
 * @param connectSocket the socket to send/recv messages on
 * @return int, 0 = SUCCESS | 1 = ERROR
 */
int sendMessages(pIOBuffer hServerBuf, pIOBuffer pClientBuf, HANDLE hServerEvent, HANDLE hClientEvent);


//*********************************************************************************
// DEFINITIONS
//********************************************************************************

/**
 * @brief Take command line inputs for address/port, set up a client socket, connect the client to the server, then send messages to the server.
 * 
 * @param argc 
 * @param argv 
 * @return int 
 */
int main(int argc, char * argv[]){

    HANDLE hMapFile = NULL;
    pIOBuffer pServerBuf, pClientBuf = NULL;
    HANDLE hServerEvent, hClientEvent = NULL;

    hMapFile = openFileBuffers(&pServerBuf, &pClientBuf);
    if (!hMapFile) {
        goto cleanup;
    }

    if (openEvents(&hServerEvent, &hClientEvent)){
        goto cleanup;
    }

    sendMessages(pServerBuf, pClientBuf, hServerEvent, hClientEvent);

    CloseHandle(hMapFile);
    CloseHandle(hServerEvent);
    CloseHandle(hClientEvent);
    UnmapViewOfFile(pServerBuf);
    return 0;

    cleanup:
    if (hMapFile){
        CloseHandle(hMapFile);
    }
    if (hServerEvent){
        CloseHandle(hServerEvent);
    }
    if (hClientEvent){
        CloseHandle(hClientEvent);
    }
    if (pServerBuf){
        UnmapViewOfFile(pServerBuf);
    }
    fprintf(stderr, "Cleanup completed.\n");
    return 1;
}


HANDLE openFileBuffers(pIOBuffer *pServerBuf, pIOBuffer *pClientBuf){

    // open the existing file mapping created by the server
    HANDLE hMapFile = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, mapName);
    if (hMapFile == NULL){
        fprintf(stderr, "OpenFileMappingA() returned null. Error: %ld.\n", GetLastError());
        return 0;
    }

    // create a pointer to the IO buffers within the file mapping
    *pClientBuf = (pIOBuffer) MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (*pClientBuf == NULL){
        fprintf(stderr, "MapViewOfFile() returned null. Error: %ld.\n", GetLastError());
        return 0;
    }
    *pServerBuf = (pIOBuffer) *pClientBuf + 1;

    return hMapFile;
}


int openEvents(HANDLE * hServerEvent, HANDLE * hClientEvent){

    // open existing server event with detect only permissions
    *hServerEvent = OpenEventA(SYNCHRONIZE, FALSE, serverEventName);
    if (*hServerEvent == NULL){
        fprintf(stderr, "OpenEventA() on server event returned null. Error: %ld.\n", GetLastError());
        return 1;
    }

    // open existing client event with modify permissions
    *hClientEvent = OpenEventA(EVENT_MODIFY_STATE, FALSE, clientEventName);
    if (*hClientEvent == NULL){
        fprintf(stderr, "OpenEventA() on client event returned null. Error: %ld.\n", GetLastError());
        return 1;
    }

    return 0;
}


int sendMessages(pIOBuffer pServerBuf, pIOBuffer pClientBuf, HANDLE hServerEvent, HANDLE hClientEvent){
    #define MESSAGES_SIZE 9
    const char *messages[MESSAGES_SIZE] = {"The", "quick", "brown", "fox", "jumps", "over", "the", "lazy", "dog"};
    uint32_t messageLen = 0;
    char recvbuf[BUFFER_SIZE];

    // while there are unsent words in words array
    uint8_t idx = 0;
    while (idx < MESSAGES_SIZE){
        printf("\n");

        // Send / copy message into client buffer, then signal to server
        messageLen = strlen(messages[idx]) * sizeof(char);
        pClientBuf->length = messageLen;
        CopyMemory((PVOID) pClientBuf->data, messages[idx], messageLen);
        SetEvent(hClientEvent);
        printf("Sent: %s (%d bytes)\n", messages[idx], messageLen);

        // wait up to 1 sec for server to signal a message echo
        uint32_t waitResponse = WaitForSingleObject(hServerEvent, 1000);
        if(waitResponse == WAIT_TIMEOUT){
            printf("Wait for server timed out, resending message.\n");
            continue;
        } else if (waitResponse == WAIT_FAILED){
            printf("Received an error while waiting for server. Error: %ld", GetLastError());
            return 1;
        }
        ZeroMemory((void *) pClientBuf, sizeof(IOBuffer));
        printf("Received signal from server.\n");

        // receive server response from server buffer
        messageLen = pServerBuf->length;
        if (messageLen > BUFFER_SIZE - sizeof(uint32_t)){ // limit message length to be copied
            messageLen = BUFFER_SIZE - sizeof(uint32_t);
            printf("Message length truncated.\n");
        }
        if (messageLen == 0){
            printf("Connection closed by server.\n");
            return 0;
        }
        CopyMemory(recvbuf, pServerBuf->data, pServerBuf->length);
        recvbuf[messageLen] = 0;
        printf("Received: %s (%d bytes)\n", recvbuf, pServerBuf->length);

        // compare response to original message sent
        if (strcmp(messages[idx], recvbuf)){ // if not a match, resend message
            printf("No match.\n");
            continue;
        } else {
            printf("Match!\n");
        }

        idx++;
    }
    // send a final 0 length message to close session
    pClientBuf->length = 0;
    SetEvent(hClientEvent);

    return 0;    
}