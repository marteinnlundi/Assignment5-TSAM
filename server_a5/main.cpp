#include "server.h"
#include "message_handler.h"
#include "logging.h"
#include "security.h"
#include "utilities.h"
#include <thread>
#include <csignal>
#include <mutex>
#include <iostream>
#include <sys/socket.h>   // For socket functions
#include <netinet/in.h>   // For sockaddr_in, AF_INET, htons, etc.
#include <arpa/inet.h>    // For inet_pton, inet_ntoa
#include <unistd.h>       // For close()
#include <cstring>        // For memset

// Define the global variable here
std::string currentServerIP;
std::string connectedServersIPs;  
int listenSock;
std::string currentServerName;
int port;

#define BACKLOG 5 

// Signal handler
void signalHandler(int signum) {
    logMessage("INFO", "Interrupt signal (" + std::to_string(signum) + ") received. Shutting down the server.");

    if (listenSock != -1) {
        close(listenSock);
        logMessage("INFO", "Listening socket closed.");
    }

    if (logFile.is_open()) {
        logMessage("INFO", "Closing log file.");
        logFile.close();
    }

    exit(signum);  
}


int main(int argc, char *argv[]) {
    signal(SIGPIPE, SIG_IGN);

    if (argc != 6) {
        std::cerr << "Usage: ./tsamgroup1 SERVER_NAME SERVER_PORT CONNECTION_SERVER_IP CONNECTION_SERVER_PORT_START CONNECTION_SERVER_PORT_END" << std::endl;
        return EXIT_FAILURE;
    }

    currentServerName = std::string("A5_") + argv[1];
    port = atoi(argv[2]);
    connectedServersIPs = argv[3];
    int connectionServerPortStart = atoi(argv[4]);
    int connectionServerPortEnd = atoi(argv[5]);

    if (!isPortAvailable(port)) {
        port = findFreePort(4000);
    }

    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    signal(SIGTSTP, signalHandler);

    blocklist.clear();

    std::string publicIP = getPublicIP();
    currentServerIP = publicIP;

    logFile.open(LOG_FILE, std::ios::out | std::ios::app);
    if (!logFile) {
        std::cerr << "Failed to open log file" << std::endl;
        return EXIT_FAILURE;
    }

    listenSock = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSock < 0) {
        perror("socket() failed");
        return EXIT_FAILURE;
    }

    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);

    int opt = 1;
    setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));

    bind(listenSock, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
    listen(listenSock, BACKLOG);

    ServerInfo localServer = {currentServerName, currentServerIP, port, -1};
    connectedServers[currentServerName] = localServer;
    serverList.push_back(localServer);

    populateServerList(connectedServersIPs, connectionServerPortStart, connectionServerPortEnd);

    std::thread keepAliveThread(startKeepAliveLoop);
    keepAliveThread.detach();

    std::thread statusReqThread(startStatusReqLoop);
    statusReqThread.detach();

    serverLoop(listenSock);

    return 0;
}
