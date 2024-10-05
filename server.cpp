#include <iostream>
#include <vector>
#include <map>
#include <sstream>
#include <algorithm>
#include <ctime>
#include <string>
#include <cstring>
#include <thread>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

#define SOH 0x01  // Start of Header
#define EOT 0x04  // End of Transmission
#define MAX_BUFFER 5000
#define BACKLOG 5  // Maximum number of queued connections

// Structure to hold server connections
struct ServerInfo {
    std::string groupID;
    std::string ipAddress;
    int port;
    int sockfd;
    time_t lastKeepAlive;
};

std::map<int, ServerInfo> connectedServers;
std::map<std::string, std::vector<std::string>> storedMessages;
std::map<int, std::string> clientNames; // For client connections

// Helper function to frame messages with SOH and EOT
std::string frameMessage(const std::string &msg) {
    return std::string(1, SOH) + msg + std::string(1, EOT);
}

// Helper function to split string by delimiter
std::vector<std::string> splitString(const std::string &str, char delimiter) {
    std::vector<std::string> tokens;
    std::stringstream ss(str);
    std::string token;
    while (std::getline(ss, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

// Send SERVERS response with connected server details
void sendServersList(int sockfd) {
    std::stringstream response;
    response << "SERVERS";

    for (const auto &entry : connectedServers) {
        const ServerInfo &server = entry.second;
        response << "," << server.groupID << "," << server.ipAddress << "," << server.port;
    }

    std::string framedResponse = frameMessage(response.str());
    send(sockfd, framedResponse.c_str(), framedResponse.length(), 0);
}

// Send KEEPALIVE message to all connected servers
void sendKeepAliveMessages() {
    for (const auto &entry : connectedServers) {
        const ServerInfo &server = entry.second;
        std::string keepAliveMsg = frameMessage("KEEPALIVE," + std::to_string(storedMessages[server.groupID].size()));
        send(server.sockfd, keepAliveMsg.c_str(), keepAliveMsg.length(), 0);
    }
}

// Handle incoming client commands
void handleClientCommand(int clientSocket, const std::string &command) {
    std::vector<std::string> tokens = splitString(command, ',');
    if (tokens.empty()) return;

    std::string cmd = tokens[0];
    if (cmd == "HELO" && tokens.size() == 2) {
        std::string groupID = tokens[1];
        sendServersList(clientSocket);  // Respond with SERVERS list
    }
    else if (cmd == "SENDMSG" && tokens.size() >= 4) {
        std::string toGroupID = tokens[1];
        std::string fromGroupID = tokens[2];
        std::string messageContent = command.substr(command.find(tokens[3]));

        // Store message for the receiving group
        storedMessages[toGroupID].push_back("From " + fromGroupID + ": " + messageContent);
    }
    else if (cmd == "GETMSGS" && tokens.size() == 2) {
        return; // Missing
    }
    else if (cmd == "STATUSREQ") {
        return; // Missing
    }
    else {
        std::string errorMsg = "Unknown command received.";
        send(clientSocket, errorMsg.c_str(), errorMsg.length(), 0);
    }
}

// Main server loop for accepting new connections and managing clients/servers
void serverLoop(int listenSock) { // NEEDS ALOT OF LOGGING
    fd_set openSockets, readSockets;
    int maxfds = listenSock;

    FD_ZERO(&openSockets);
    FD_SET(listenSock, &openSockets);

    while (true) {
        readSockets = openSockets;

        if (select(maxfds + 1, &readSockets, NULL, NULL, NULL) < 0) {
            perror("select() failed");
            exit(EXIT_FAILURE);
        }

        for (int i = 0; i <= maxfds; ++i) {
            if (FD_ISSET(i, &readSockets)) {
                if (i == listenSock) {
                    // Accept new connection
                    struct sockaddr_in clientAddr;
                    socklen_t clientLen = sizeof(clientAddr);
                    int newSock = accept(listenSock, (struct sockaddr *)&clientAddr, &clientLen);
                    if (newSock < 0) {
                        perror("accept() failed");
                    } else {
                        FD_SET(newSock, &openSockets);
                        maxfds = std::max(maxfds, newSock);
                        std::cout << "New client/server connected on socket " << newSock << std::endl;
                    }
                } else {
                    // Handle client/server commands
                    char buffer[MAX_BUFFER];
                    memset(buffer, 0, MAX_BUFFER);
                    int bytesReceived = recv(i, buffer, MAX_BUFFER, 0);
                    if (bytesReceived <= 0) {
                        close(i);
                        FD_CLR(i, &openSockets);
                    } else {
                        std::string receivedMsg(buffer, bytesReceived);
                        std::cout << "Received: " << receivedMsg << std::endl;
                        handleClientCommand(i, receivedMsg);
                    }
                }
            }
        }
    }
}

// Main entry point of the server program
int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: ./tsamgroup1 <port>" << std::endl;
        return EXIT_FAILURE;
    }

    int port = atoi(argv[1]);
    int listenSock = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSock < 0) {
        perror("socket() failed");
        return EXIT_FAILURE;
    }

    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);

    if (bind(listenSock, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("bind() failed");
        close(listenSock);
        return EXIT_FAILURE;
    }

    if (listen(listenSock, BACKLOG) < 0) {
        perror("listen() failed");
        close(listenSock);
        return EXIT_FAILURE;
    }

    std::cout << "Server is listening on port " << port << std::endl;

    // Start main server loop
    serverLoop(listenSock);

    return 0;
}
