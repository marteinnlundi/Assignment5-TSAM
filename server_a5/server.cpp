#include "server.h"
#include "logging.h"
#include "message_handler.h"
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <thread>

// External variable definitions
std::vector<ServerInfo> serverList;
std::map<std::string, ServerInfo> connectedServers;
extern std::string currentServerName;

bool canEstablishConnection(bool isInitialConnection) {
    int connectedServerCount = connectedServers.size();

    // During initial connections, we don't need to enforce the minimum server rule
    if (isInitialConnection) {
        return true;
    }

    if (connectedServerCount < 3) {
        std::cerr << "Connection attempt failed: Less than 3 servers are currently connected (" << connectedServerCount << " connected).\n";
        return false;
    } else if (connectedServerCount >= 8) {
        std::cerr << "Connection attempt failed: More than 8 servers are already connected (" << connectedServerCount << " connected).\n";
        return false;
    }

    return true;
}

void sendHELOCommand(int sockfd) {
    std::string heloCommand = "HELO," + currentServerName;
    std::string framedCommand = frameMessage(heloCommand);
    sendWithLogging(sockfd, framedCommand);
}

int tryToConnect(ServerInfo server, bool isInitialConnection) {
    if (!canEstablishConnection(isInitialConnection)) {
        return -1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) return -1;

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(server.port);

    if (inet_pton(AF_INET, server.ipAddress.c_str(), &serverAddr.sin_addr) <= 0) {
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        close(sock);
        return -1;
    }

    server.sockfd = sock;
    connectedServers[server.groupID] = server;
    return sock;
}

void requestStatusFromServers() {
    for (const auto& entry : connectedServers) {
        const ServerInfo& server = entry.second;
        
        // Log the status request being sent
        logMessage("INFO", "Sending STATUSREQ to " + server.groupID);
        
        // Frame the STATUSREQ message
        std::string statusReqCommand = frameMessage("STATUSREQ");
        
        // Send the STATUSREQ to the server
        ssize_t result = send(server.sockfd, statusReqCommand.c_str(), statusReqCommand.length(), 0);

        if (result < 0) {
            // Log error if sending fails
            logMessage("ERROR", "Failed to send STATUSREQ to " + server.groupID);
        } else {
            // Log success if the message is sent successfully
            logMessage("INFO", "STATUSREQ sent successfully to " + server.groupID);
        }
    }
}


void sendKeepAliveMessages() {
    // C++11-compliant for loop instead of structured bindings
    for (auto& entry : connectedServers) {
        const std::string& groupID = entry.first;
        ServerInfo& server = entry.second;

        std::string keepAliveMsg = frameMessage("KEEPALIVE,0");
        sendWithLogging(server.sockfd, keepAliveMsg);
        server.lastKeepAlive = time(0);
    }
}

void startKeepAliveLoop() {
    while (true) {
        sendKeepAliveMessages();
        std::this_thread::sleep_for(std::chrono::seconds(60));
    }
}

void startStatusReqLoop() {
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(100));
        requestStatusFromServers();
    }
}

void serverLoop(int listenSock) {
    fd_set openSockets;
    FD_ZERO(&openSockets);
    FD_SET(listenSock, &openSockets);

    while (true) {
        fd_set readSockets = openSockets;
        int activity = select(listenSock + 1, &readSockets, NULL, NULL, NULL);

        if (FD_ISSET(listenSock, &readSockets)) {
            struct sockaddr_in clientAddr;
            int clientSock = accept(listenSock, (struct sockaddr*)&clientAddr, NULL);
            FD_SET(clientSock, &openSockets);
        }
    }
}

void populateServerList(const std::string &ipAddress, int portStart, int portEnd) {
    serverList.clear();
    for (int port = portStart; port <= portEnd; ++port) {
        ServerInfo newServer = {"Group_" + std::to_string(port), ipAddress, port, -1, time(0)};
        int sockfd = tryToConnect(newServer, true);
        if (sockfd >= 0) {
            connectedServers[newServer.groupID] = newServer;
            serverList.push_back(newServer);
        }
    }
}
