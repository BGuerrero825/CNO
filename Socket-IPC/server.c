/**
 * @file server.c
 * @author Brian Guerrero
 * @brief TCP message echo server
 * @date 2024-05-03
 * 
 */


#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#define DEFAULT_ADDR "0.0.0.0"
#define DEFAULT_PORT "12345"
#define BUFLEN 256


//*********************************************************************************
// DECLARATIONS
//*********************************************************************************

/**
 * @brief Checks number of supplied command line options, searches for arguments: address and port, then sets pointers to those strings.
 * 
 * @param[out] argAddr pointer to address argument pointer
 * @param[out] argPort pointer to port argument pointer
 * @return int, 0: Success | 1: Error
 */
int parseArgs(int argc, char *argv[], char **argAddr, char **argPort);

/**
 * @brief Initiates socket functionality, resolves supplied address information, binds and listens with socket on the address, and then returns the resulting network server socket.
 * 
 * @param argAddr 
 * @param argPort 
 * @return SOCKET, unconnected TCP socket | 0: Error
 */
SOCKET serverSetup(char *argAddr, char *argPort);

/**
 * @brief Receives messages from a client and replies with the exact message received, closes the socket when the client ends the connection.
 * 
 * @param clientSocket the socket to send/recv messages on
 * @return int, 0: Success | 1: Error
 */
int serverRecv(SOCKET clientSocket);


//*********************************************************************************
// DEFINITIONS
//********************************************************************************

/**
 * @brief Take command line inputs for address/port, set up a server socket, accept a client connection, then receive messages from the client.
 * Steps: WSAStartup -> getaddrinfo -> socket -> bind -> listen -> accept -> recv
 * 
 * @param argc 
 * @param argv 
 * @return int 
 */
int main(int argc, char * argv[]){

    char *argAddr = DEFAULT_ADDR;
    char *argPort = DEFAULT_PORT;
    SOCKET listenSocket;
    SOCKET clientSocket;
    
    if (argc > 1){
        if (parseArgs(argc, argv, &argAddr, &argPort)){
            return 1;
        }
    }

    // start WSA, create a socket, bind it to given addr, and listen with it
    listenSocket = serverSetup(argAddr, argPort);
    if (!listenSocket){
        goto cleanup;
    }

    // accept a connection from a client
    clientSocket = accept(listenSocket, NULL, NULL);
    printf("Connection Received.\n");
    if (clientSocket == INVALID_SOCKET) {
        fprintf(stderr, "accept() returned an invalid socket, error code: %d.\n", WSAGetLastError());
        goto cleanup;
    }

    // receive messages from the client until the connection is closed
    if (serverRecv(clientSocket) == 1) {
       goto cleanup; 
    }

    return 0;

    cleanup:
    if (clientSocket){
        closesocket(clientSocket);
    }
    if (listenSocket){
        closesocket(listenSocket);
    }
    WSACleanup();
    fprintf(stderr, "Cleanup completed.\n");
    return 1;
}


/**
 * @brief 
 * 
 * @return SOCKET 
 */
SOCKET serverSetup(char *argAddr, char *argPort){

    WSADATA wsaData;
    SOCKET listenSocket;

    // WSAStartup: Initialize socket functionality
    int retval = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (retval){
        fprintf(stderr, "WSAStartup() failed with code: %d.\n", retval);
        return 0;
    }

    // getaddrinfo: resolves given (or default) addresses at given port (or 12345) to a provided addrinfo struct
    ADDRINFO *result = NULL;
    ADDRINFO hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    retval = getaddrinfo(argAddr, argPort, &hints, &result);
    if (retval){
        fprintf(stderr, "getaddrinfo() failed with code: %d.\n", retval);
        return 0;
    }

    // create a server socket with given connection specifications
    listenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (listenSocket == INVALID_SOCKET){
        fprintf(stderr, "socket() returned an invalid socket, error code: %d.\n", WSAGetLastError());
        return 0;
    }

    // bind the server socket to the given interface information
    retval = bind(listenSocket, result->ai_addr, result->ai_addrlen);
    freeaddrinfo(result);
    if (retval == SOCKET_ERROR){
        fprintf(stderr, "bind() returned a socket error, error code: %d.\n", WSAGetLastError());
        return 0;
    }

    // start listening on the socket
    // SOMAXCONN = constant for how many connections to allow in backlog
    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR){
        fprintf(stderr, "listen() returned a socket error, error code: %d.\n", WSAGetLastError());
        return 0;
    }

    return listenSocket;
}


int serverRecv(SOCKET clientSocket){
    // receive until the client ends the connection
    char recvbuf[BUFLEN];
    int recvBytes, sendBytes;
    do {
        recvBytes = recv(clientSocket, recvbuf, BUFLEN, 0);
        if (recvBytes > 0) {
            printf("Bytes received: %d.\n", recvBytes);

            // Echo back to sender
            sendBytes = send(clientSocket, recvbuf, recvBytes, 0);
            if (sendBytes == SOCKET_ERROR) {
                fprintf(stderr, "send() returned a socket error, error code: %d.\n", WSAGetLastError());
                return 1;
            }
            printf("Bytes sent: %d.\n", sendBytes);

            // append a null terminator, or cap with null terminator if too long
            if (recvBytes < BUFLEN){
                recvbuf[recvBytes] = 0;
            }
            recvbuf[BUFLEN-1] = 0;
            printf("Message: %s\n", recvbuf);
        }
        else if (recvBytes == 0){
            printf("Connection closing.\n");
        }
        else {
            fprintf(stderr, "recv() returned a socket error, error code: %d.\n", WSAGetLastError());
            return 1;
        }
        printf("\n");

    } while (recvBytes > 0);

    return 0;
}


int parseArgs(int argc, char *argv[], char **argAddr, char **argPort){
    if (!(argc == 3 || argc == 5)){
        fprintf(stderr, "Wrong number of arguments.\nUsage: server [-a|--address] [<address>] [-p|--port] [<port>]\nDefault address: default interface\nDefault port: 12345\n");
        return 1;
    }

    for (int idx = 1; idx < argc; idx += 2){
        if (!strcmp(argv[idx], "-a") || !strcmp(argv[idx], "--address")){
            *argAddr = argv[idx+1];
            //inet_pton(AF_INET, argv[idx+1], &(bindAddr->sin_addr));
        }
        else if (!strcmp(argv[idx], "-p") || !strcmp(argv[idx], "--port")){
            if ((unsigned int) atoi(argv[idx+1]) > 65535 || atoi(argv[idx+1]) < 0){
                fprintf(stderr, "Port number is invalid, must be between 0-65535.\n");
                return 1;
            }
            *argPort = argv[idx+1];
            //bindAddr->sin_port = (unsigned short)atoi(argv[idx+1]);
        }
    }

    return 0;
}