/**
 * @file server.c
 * @author Brian Guerrero
 * @brief Shared memory server, performs setup and client message echoing 
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
 * @brief Creates a named file mapping and creates pointers to server and client IOBuffers within the file mapping.
 * 
 * @param[out] pServerBuf pointer to the server IOBuffer pointer
 * @param[out] pClientBuf pointer to the client IOBuffer pointer
 * @return HANDLE, to the file mapping
 */
HANDLE createFileBuffers(pIOBuffer *pServerBuf, pIOBuffer *pClientBuf);

/**
 * @brief Create event objects for use by the server and client for IPC
 * 
 * @param[out] hServerEvent pointer to a server controlled event handle
 * @param[out] hClientEvent pointer to a client controlled event handle
 * @return int, 0 = SUCCESS | 1 = ERROR
 */
int createEvents(HANDLE *hServerEvent, HANDLE *hClientEvent);


/**
 * @brief Receives messages from a client and replies with the exact message received, closes the socket when the client ends the connection.
 * 
 * @param clientSocket the socket to send/recv messages on
 * @return int, 0 = SUCCESS | 1 = ERROR
 */
int echoMessages(pIOBuffer hServerBuf, pIOBuffer pClientBuf, HANDLE hServerEvent, HANDLE hClientEvent);


//*********************************************************************************
// DEFINITIONS
//********************************************************************************

/**
 * @brief Take command line inputs for address/port, set up a server socket, accept a client connection, then receive messages from the client.
 * 
 * @param argc 
 * @param argv 
 * @return int 
 */
int main(int argc, char * argv[]){

    HANDLE hMapFile = NULL;
    pIOBuffer pServerBuf, pClientBuf = NULL;
    HANDLE hServerEvent, hClientEvent = NULL;

    hMapFile = createFileBuffers(&pServerBuf, &pClientBuf);
    if (!hMapFile) {
        goto cleanup;
    }

    if (createEvents(&hServerEvent, &hClientEvent)){
        goto cleanup;
    }

    // ensure event is unsignaled
    if (!ResetEvent(hServerEvent)){
        fprintf(stderr, "ResetEvent() failed. Error: %ld.\n", GetLastError());
        goto cleanup;
    }

    echoMessages(pServerBuf, pClientBuf, hServerEvent, hClientEvent);
    
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


HANDLE createFileBuffers(pIOBuffer *pServerBuf, pIOBuffer *pClientBuf){
    // Create a file mapping in memory without a backing file, size of 2 * buffer size for each IO buffer
    HANDLE hMapFile = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, BUFFER_SIZE * 2, mapName);
    if (hMapFile == NULL){
        fprintf(stderr, "CreateFileMappingA() returned null. Error: %ld.\n", GetLastError());
        return 0;
    }

    // create a pointer to a server and client IO buffer within the file mapping
    *pClientBuf = (pIOBuffer) MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (*pClientBuf == NULL){
        fprintf(stderr, "MapViewOfFile() returned null. Error: %ld.\n", GetLastError());
        return 0;
    }
    *pServerBuf = (pIOBuffer) *pClientBuf + 1;

    return hMapFile;
}


int createEvents(HANDLE *hServerEvent, HANDLE *hClientEvent){

    // create the server signaling event
    *hServerEvent = CreateEventA(NULL, FALSE, FALSE, serverEventName);
    if (*hServerEvent == NULL){
        fprintf(stderr, "CreateEventA() for server event returned null. Error: %ld.\n", GetLastError());
        return 1;
    }

    // create the client signaling event
    *hClientEvent = CreateEventA(NULL, FALSE, FALSE, clientEventName);
    if (*hServerEvent == NULL){
        fprintf(stderr, "CreateEventA() for client event returned null. Error: %ld.\n", GetLastError());
        return 1;
    }
    
    return 0;
}


int echoMessages(pIOBuffer pServerBuf, pIOBuffer pClientBuf, HANDLE hServerEvent, HANDLE hClientEvent){
    // receive until the client ends the connection
    uint32_t messageLen = 0;
    char recvbuf[BUFFER_SIZE];

    // do while a 0 length message not received
    do {
        printf("\n");

        // wait for a client to signal a message has been sent
        if (WaitForSingleObject(hClientEvent, INFINITE) == WAIT_FAILED){
            printf("Received an error while waiting for client. Error: %ld", GetLastError());
            return 1;
        }
        ZeroMemory((void *) pServerBuf, sizeof(IOBuffer));
        printf("Received signal from client.\n");
        
        // receive client message from client buffer
        messageLen = pClientBuf->length;
        if (messageLen > BUFFER_SIZE - sizeof(uint32_t)){ // limit message length to be copied
            messageLen = BUFFER_SIZE - sizeof(uint32_t);
            printf("Message length truncated.\n");
        }
        if (messageLen == 0){
            printf("Connection closed by client.\n");
            return 0;
        }
        CopyMemory(recvbuf, pClientBuf->data, messageLen);
        recvbuf[messageLen] = 0; // use this buffer for printing only
        printf("Received: %s (%d bytes)\n", recvbuf, messageLen);

        // Echo message into server buffer
        pServerBuf->length = messageLen;
        CopyMemory(pServerBuf->data, pClientBuf->data, messageLen);
        SetEvent(hServerEvent);
        printf("Sent: %s (%d bytes)\n", recvbuf, messageLen);

    } while (messageLen > 0);

    return 0;
}