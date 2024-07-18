/**
 * @file server.c
 * @author Brian Guerrero
 * @brief TCP message echo client
 * @date 2024-05-03
 * 
 */


#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#define DEFAULT_ADDR "localhost"
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
 * @brief Initiates socket functionality, resolves supplied address information, and then returns the resulting network client socket.
 * 
 * @param argAddr 
 * @param argPort 
 * @param[out] result pointer to server IP's ADDRINFO struct pointer
 * @return SOCKET, unconnected TCP socket | 0: Error
 */
SOCKET clientSetup(char *argAddr, char *argPort, ADDRINFO **result);

/**
 * @brief Sends a list of preset strings to the specified server one at a time, retransmitting if no response after 1 seconds or if response is not the correct message.
 * 
 * @param connectSocket the socket to send/recv messages on
 * @return int, 0: Success | 1: Error
 */
int clientSend(SOCKET connectSocket);


//*********************************************************************************
// DEFINITIONS
//********************************************************************************

/**
 * @brief Take command line inputs for address/port, set up a client socket, connect the client to the server, then send messages to the server.
 * Steps: WSAStartup -> getaddrinfo -> socket -> connect -> send -> select -> recv
 * 
 * @param argc 
 * @param argv 
 * @return int 
 */
int main(int argc, char * argv[]){

    char *argAddr = DEFAULT_ADDR;
    char *argPort = DEFAULT_PORT;
    SOCKET connectSocket; 

    if (argc > 1){
        if (parseArgs(argc, argv, &argAddr, &argPort)){
            return 1;
        }
    }

    // start WSA, resolve server address info, create a socket
    ADDRINFO *result = NULL;
    connectSocket = clientSetup(argAddr, argPort, &result);
    if (!connectSocket){
        goto cleanup;
    }

    // connect socket to the server
    if (connect(connectSocket, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR){
        connectSocket = INVALID_SOCKET;
        fprintf(stderr, "connect() returned a socket error, error code: %d.\n", WSAGetLastError());
        goto cleanup;
    }
    freeaddrinfo(result);

    // send messages to the server until all have been received
    if (clientSend(connectSocket) == 1) {
        goto cleanup;
    }

    return 0;

    cleanup:
    if (connectSocket){
        closesocket(connectSocket);
    }
    WSACleanup();
    fprintf(stderr, "Cleanup completed.\n");
    return 1;
}


SOCKET clientSetup(char *argAddr, char *argPort, ADDRINFO **result){

    WSADATA wsaData;

    // WSAStartup: Initialize socket functionality
    int retval = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (retval){
        fprintf(stderr, "WSAStartup() failed with code: %d.\n", retval);
        return 0;
    }

    // getaddrinfo: resolves given (or default) addresses at given port (or 12345) to a provided addrinfo struct
    struct addrinfo hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;
    if (!argPort){
        argPort = DEFAULT_PORT;
    }
    retval = getaddrinfo(argAddr, argPort, &hints, result);
    if (retval){
        fprintf(stderr, "getaddrinfo() failed with code: %d.\n", retval);
        return 0;
    }


    // create a client socket with given connection specifications
    SOCKET connectSocket;
    connectSocket = socket((*result)->ai_family, (*result)->ai_socktype, (*result)->ai_protocol);
    if (connectSocket == INVALID_SOCKET){
        fprintf(stderr, "socket() returned an invalid socket, error code: %d.\n", WSAGetLastError());
        freeaddrinfo(*result);
        return 0;
    }

    return connectSocket;
}


int clientSend(SOCKET connectSocket){
    #define WORDSLEN 9
    const char *words[WORDSLEN] = {"The", "quick", "brown", "fox", "jumps", "over", "the", "lazy", "dog"};

    char recvbuf[BUFLEN];
    int retval;
    fd_set sockets;
    // initialize wait time of 1 sec for select()
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    // while there are unsent words in words array
    int idx = 0;
    while (idx < WORDSLEN){
        retval = send(connectSocket, words[idx], (int) strlen(words[idx]), 0);
        if (retval == SOCKET_ERROR){
            fprintf(stderr, "send() returned a socket error, error code: %d.\n", WSAGetLastError());
            return 1;
        }
        printf("Sent: %s (%d bytes)\n", words[idx], retval);

        // init a file descriptor set with just this socket for select()
        FD_ZERO(&sockets);
        FD_SET(connectSocket, &sockets);
        // check if socket is ready to be read from
        retval = select(0, &sockets, NULL, NULL, &timeout);
        if (retval == 0){   // if timeout, retrasmit same word
            printf("Response timeout.\n");
            continue;
        } else if (retval < 0) {
            fprintf(stderr, "select() returned a socket error, error code: %d.\n", WSAGetLastError());
            return 1;
        }

        retval = recv(connectSocket, recvbuf, BUFLEN, 0);
        if (retval > 0){
            // append a null terminator, or cap with null terminator if too long
            if (retval < BUFLEN){
                recvbuf[retval] = 0;
            }
            recvbuf[BUFLEN-1] = 0;
            printf("Received: %s (%d bytes)\n", recvbuf, retval);
            if (strcmp(words[idx], recvbuf)){   // if response doesn't match, retransmit same word
                printf("Reponse did not match message.\n");
                continue;
            }
            idx++;
        } else if (retval == 0){
            printf("Connection closed by server.\n");
        } else {
            fprintf(stderr, "recv() returned a socket error, error code: %d.\n", WSAGetLastError());
            return 1;
        }
    }

    // shutdown socket
    if (shutdown(connectSocket, SD_BOTH) == SOCKET_ERROR){
        fprintf(stderr, "shutdown() returned a socket error, error code: %d.\n", WSAGetLastError());
        return 1;
    }
    printf("\n");
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
        }
        else if (!strcmp(argv[idx], "-p") || !strcmp(argv[idx], "--port")){
            if ((unsigned int) atoi(argv[idx+1]) > 65535 || atoi(argv[idx+1]) < 0){
                fprintf(stderr, "Port number is invalid, must be between 0-65535.\n");
                return 1;
            }
            *argPort = argv[idx+1];
        }
    }
    return 0;
}