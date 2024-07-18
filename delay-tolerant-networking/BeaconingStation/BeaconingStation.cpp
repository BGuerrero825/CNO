#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <thread>
#include <mutex>
#include "..\shared\resolve.h"


// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

#define DEFAULT_PORT "27015"
#define TARGET_ADDR ""

#define INPUT_STREAM_PORT "3678"
#define DEFAULT_FILE_CHUNK 1024
#define DEFAULT_BUFLEN 512
#define SEND_LEN 1024
#define MAX_BACKOFF 2000 // 2 seconds
#define BACKOFF_INTERVAL 100 // 100 ms
#define MIN_SIGNAL_STRENGTH 25
#define GET_SIGNAL_STRENGTH 0xffffffff
#define DONE_WITH_PAYLOAD   0xeeeeeeee

// Satellite constants
#define SATELLITE_CONNECTION_DROPPED 0xffffffff

//
// Globals
//
// Where data incoming from the Data Stream will be queued.
volatile char* gDataQueue = nullptr;

// The current size of the data queue. As size runs out, this will be realloc'd *2.
volatile unsigned gDataQueueSize = 1024;

// The current index to indicate where the queue is being written to. AKA how much
// is in the queue at this time.
volatile unsigned gIndexDataQueue = 0;

// The lock to prevent concurrent modification of the queue.
std::mutex gDataQueueMutex;

// Indicates that the transmission from DataSream is complete. No new data will be added
// to the queue.
volatile bool gAllDataReceived = false;

// This thread gathers the data being transmitted by the data stream and places
// it into gDataQueue to be consumed and sent to the satellite.
void data_collector()
{
    // resolve address for datastream listener
    struct addrinfo* result = ResolveAddress("", INPUT_STREAM_PORT, AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (result == nullptr) {
        // TODO: This really shouldn't be calling WSACleanup() since it did not initialize WSA
        //WSACleanup();
        return;
    }

    PrintAddress("DataStream Listener:", result->ai_addr, (int)result->ai_addrlen);

    SOCKET datastreamSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (datastreamSocket == INVALID_SOCKET) {
        printf("socket failed with error: %ld\n", WSAGetLastError());
        freeaddrinfo(result);
        //WSACleanup();
        return;
    }

    // Setup the TCP listening socket
    int rv = bind(datastreamSocket, result->ai_addr, (int)result->ai_addrlen);
    if (rv == SOCKET_ERROR) {
        printf("bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(datastreamSocket);
        return;
    }

    freeaddrinfo(result);

    rv = listen(datastreamSocket, SOMAXCONN);
    if (rv == SOCKET_ERROR) {
        printf("listen failed with error: %d\n", WSAGetLastError());
        closesocket(datastreamSocket);
        return;
    }

    SOCKET clientSocket = accept(datastreamSocket, nullptr, nullptr);
    if (clientSocket == INVALID_SOCKET) {
        printf("accept failed with error: %d\n", WSAGetLastError());
        closesocket(datastreamSocket);
        return;
    }
    printf("DataStream connection received...\n");

    while (true)
    {
        char recvbuf[DEFAULT_BUFLEN] = { 0 };
        int rcvlen = recv(clientSocket, recvbuf, sizeof(recvbuf) - 1, 0);
        // INVALID_SOCKET indicates error
        if (rcvlen < 0)
        {
            printf("Data stream recv failed with error: %d\n", WSAGetLastError());
            break;
        }
        // 0 indicates nothing received (connection closed)
        if (rcvlen == 0)
        {
            printf("Finished Receiving from Data Stream\n");
            gAllDataReceived = true;
            break;
        }

        // else rcvlen bytes received - null terminate so we can loosely treat it as text (as expected)
        //printf("Bytes received: %d\n", rcvlen);
        recvbuf[rcvlen] = 0;

        // lock while processing received data
        gDataQueueMutex.lock();
        // if this will put us over the top, grow the receive buffer
        if (gIndexDataQueue + rcvlen > gDataQueueSize) {
            gDataQueueSize *= 2;
            // Locking: Realloc() may allocate new buffer and copy previous contents
            char* temp = (char*)realloc((char*)gDataQueue, gDataQueueSize);
            // if we ran out of memory, just act like the data wasn't received - should never happen
            if (temp == nullptr) {
                fprintf(stderr, "Receive buffer realloc() failed\n");
                gDataQueueMutex.unlock();
                break;
            }

            gDataQueue = temp;
        }
        memcpy((char*)gDataQueue + gIndexDataQueue, recvbuf, rcvlen);
        gIndexDataQueue += rcvlen;
        gDataQueueMutex.unlock();
    }
    // TODO: Not doing proper cleanup here
    //free((void *) gDataQueue); //?
    return;
    //
}

// Gets the current signal strength of the connection with the satellite
int get_signal_strength(SOCKET satelliteSocket, uint32_t &signalStrength)
{
    uint32_t getSignalBuf = GET_SIGNAL_STRENGTH;

    int rv = send(satelliteSocket, (char*)&getSignalBuf, sizeof(getSignalBuf), 0);
    if (rv == SOCKET_ERROR) {
        printf("send failed with error: %d\n", WSAGetLastError());
        return SOCKET_ERROR;
    }

    rv = recv(satelliteSocket, (char *)&signalStrength, sizeof(uint32_t), 0);
    if (rv > 0) {
        printf("Signal Strength: %d\n", signalStrength);
    }
    else if (rv == 0)
    {
        printf("Connection closed\n");
    }
    else if (rv == SOCKET_ERROR)
    {
        return rv;
    }
    else
    {
        printf("recv failed with error: %d\n", WSAGetLastError());
    }

    return rv;
}

// Creates a hash of the buffer passed in
uint32_t get_data_hash(char* buf, unsigned length)
{
    std::string strBuf = std::string(buf, buf + length);
    return (uint32_t)std::hash<std::string>{}(strBuf);
}

int __cdecl main_wrapper(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    // Init the Data Receive Queue with some space
    gDataQueue = (char*)malloc(gDataQueueSize);

    // Initialize Winsock
    WSADATA wsaData;
    int rv = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (rv != 0) {
        printf("WSAStartup failed with error: %d\n", rv);
        return 1;
    }

    // Start up data collection thread
    std::thread data_collection_thread(data_collector);
    data_collection_thread.detach();


    // resolve satellite server address
    struct addrinfo* result = ResolveAddress(TARGET_ADDR, DEFAULT_PORT, AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (result == nullptr) {
        WSACleanup();
        return 1;
    }

    PrintAddress("Satellite Address:", result->ai_addr, (int)result->ai_addrlen);

    // Attempt to connect to an address until one succeeds
    SOCKET satelliteSocket = INVALID_SOCKET;
    for (struct addrinfo* ptr = result; ptr != nullptr; ptr = ptr->ai_next) {

        // Create a SOCKET for connecting to server
        satelliteSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (satelliteSocket == INVALID_SOCKET) {
            printf("socket failed with error: %ld\n", WSAGetLastError());
            WSACleanup();
            return 1;
        }

        // Connect to server.
        rv = connect(satelliteSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (rv == SOCKET_ERROR) {
            closesocket(satelliteSocket);
            satelliteSocket = INVALID_SOCKET;
            continue;
        }
        printf("Connected to satellite...\n");
        break;
    }

    freeaddrinfo(result);

    if (satelliteSocket == INVALID_SOCKET) {
        printf("Unable to connect to server!\n");
        WSACleanup();
        return 1;
    }

    // START: //////////////////////////// TRANSMIT TO SATELLITE HERE ////////////////////////////

    unsigned backoff = BACKOFF_INTERVAL;
    unsigned sendIndex = 0;
    unsigned exitCode = EXIT_FAILURE;

    while (true)
    {
        // -------- CASE 1 --------
        // if no data in the queue, not the end of transmission, sleep and continue
        if (sendIndex >= gIndexDataQueue && !gAllDataReceived)
        {
            printf(".");
            Sleep(backoff);
            continue;
        }

        // -------- CASE 2 --------
        // if signal is weak, release lock, increase backoff, sleep, and continue
        uint32_t signalStrength = 0;
        printf("\n");
        if (get_signal_strength(satelliteSocket, signalStrength) <= 0)
        {
            printf("Failed to get satellite strength due to error, %d.", signalStrength);
            break;
        }
        if (signalStrength < MIN_SIGNAL_STRENGTH)
        {
            if (backoff < MAX_BACKOFF)
            {
                backoff += BACKOFF_INTERVAL;
            }
            Sleep(backoff);
            continue;
        }
        // signal is sufficient, reset to a low backoff
        backoff = 100;

        // -------- CASE 3 --------
        // if the entire transmission was sent to satellite, send done signal and
        // get hash for entire transmission, then break out of loop
        if (gAllDataReceived && (sendIndex >= gIndexDataQueue))
        {
            printf("Reached end of transmission data.\n");

            unsigned finalPayload = DONE_WITH_PAYLOAD;
            int retval = send(satelliteSocket, (char *)(&finalPayload), sizeof(finalPayload), 0);
            if (retval == SOCKET_ERROR)
            {
                printf("Satellite socket error on send.\n");
                break;
            }

            uint32_t finalDataHash = get_data_hash((char*)(gDataQueue), sendIndex);
            uint32_t finalSatResponse = 0;
            retval = recv(satelliteSocket, (char*)&finalSatResponse, sizeof(finalSatResponse), 0);
            if (retval == 0)
            {
                printf("Satellite connection closed.\n");
                break;
            }
            else if (retval == SOCKET_ERROR)
            {
                printf("Satellite socket error on recv.\n");
            }
            printf("Final data hash: %u  |  Final satellite response: %u\n", finalDataHash, finalSatResponse);
            if (finalDataHash == finalSatResponse)
            {
                printf("Transmission successful!\n");
                exitCode = EXIT_SUCCESS;
                break;
            }
            else
            {
                printf("Final hash did not match. Errors in transmission.\n");
                break;
            }
            continue;

        }

        // -------- CASE 4 --------
        // if data in queue reaches SEND_LEN, or if entire transmission
        // has been sent to queue: lock mutex, send SEND_LEN bytes to satellite,
        // await checksum response and progress buffer index if valid

        // calculate bytes remaining in queue that haven't been sent
        unsigned sendRemaining = gIndexDataQueue - sendIndex;
        // continue if remaining is too small and it's not the last message
        if (sendRemaining < SEND_LEN && !gAllDataReceived)
        {
            continue;
        }
        // set sendLen to the lower of sendRemaining and SEND_LEN
        unsigned sendLen = sendRemaining < SEND_LEN ? sendRemaining : SEND_LEN;
        // lock the mutex and copy data from the queue into an intermediary buffer
        // (dont lock over a send() w/ extended time)
        char sendBuf[SEND_LEN + 1] = { 0 };
        gDataQueueMutex.lock();
        memcpy_s(sendBuf, sizeof(sendBuf), (const char *) gDataQueue + sendIndex, sendLen);
        gDataQueueMutex.unlock();
        int retval = send(satelliteSocket, sendBuf, sendLen, 0);
        if (retval == SOCKET_ERROR)
        {
            printf("Satellite socket error on send.\n");
            break;
        }
        // check if satellite response is a correct hash of the message
        uint32_t dataHash = get_data_hash((char*)(gDataQueue + sendIndex), sendLen);
        uint32_t satResponse = 0;
        retval = recv(satelliteSocket, (char*)&satResponse, sizeof(satResponse), 0);
        if (retval == 0)
        {
            printf("Satellite connection closed\n");
            break;
        }
        else if (retval == SOCKET_ERROR)
        {
            printf("Satellite socket error on recv.\n");
            break;
        }
        printf("Data Hash: %u  |  Satellite response: %u\n", dataHash, satResponse);
        // if the packet was successful increment the send buffer index
        if (dataHash == satResponse)
        {
            printf("Packet successful!\n");
            sendIndex += sendLen;
        }

    }

    // END:   //////////////////////////// TRANSMIT TO SATELLITE HERE ////////////////////////////

    // shutdown the connection since no more data will be sent
    rv = shutdown(satelliteSocket, SD_SEND);
    if (rv == SOCKET_ERROR) {
        printf("shutdown failed with error: %d\n", WSAGetLastError());
    }

    closesocket(satelliteSocket);
    WSACleanup();
    return EXIT_SUCCESS;
}


int __cdecl main(int argc, char** argv)
{
    int ret_code = main_wrapper(argc, argv);
    system("pause");
    return ret_code;
}

