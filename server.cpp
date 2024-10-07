// Compile: g++ server.cpp -o tsamgroup1 -pthread
// Usage: ./tsamgroup1 60000

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
#include <cctype>

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

// Logging helper
void logMessage(const std::string& logType, const std::string& message) {
    time_t now = time(0);
    char* dt = ctime(&now);
    dt[strlen(dt)-1] = '\0'; // Remove the newline
    std::cout << "[" << dt << "] [" << logType << "] " << message << std::endl;
}

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
    logMessage("INFO", "Sent SERVERS list to socket: " + std::to_string(sockfd));
}

// Send KEEPALIVE message to all connected servers
void sendKeepAliveMessages() {
    for (const auto &entry : connectedServers) {
        const ServerInfo &server = entry.second;
        std::string keepAliveMsg = frameMessage("KEEPALIVE," + std::to_string(storedMessages[server.groupID].size()));
        send(server.sockfd, keepAliveMsg.c_str(), keepAliveMsg.length(), 0);
        logMessage("INFO", "Sent KEEPALIVE to " + server.groupID + " (" + server.ipAddress + ":" + std::to_string(server.port) + ")");
    }
}

// Helper function to trim whitespace or extra characters from strings
std::string trim(const std::string &str) {
    if (str.empty()) return "";  // Handle empty strings
    size_t first = str.find_first_not_of(" \n\r\t");
    if (first == std::string::npos) return "";  // All characters are whitespace
    size_t last = str.find_last_not_of(" \n\r\t");
    return str.substr(first, (last - first + 1));
}

// Handle incoming client commands
void handleClientCommand(int clientSocket, const std::string &command) {
    // Trim the command before processing
    std::string trimmedCommand = trim(command);

    // Check for empty commands and respond with error
    if (trimmedCommand.empty()) {
        logMessage("ERROR", "Received empty command from socket: " + std::to_string(clientSocket));
        std::string errorMsg = "ERROR: Empty command";
        send(clientSocket, frameMessage(errorMsg).c_str(), frameMessage(errorMsg).length(), 0);
        return;
    }

    // Log raw command for debugging
    logMessage("DEBUG", "Raw command received: [" + command + "]");
    logMessage("DEBUG", "Trimmed command for processing: [" + trimmedCommand + "]");

    // Split the trimmed command into tokens
    std::vector<std::string> tokens = splitString(trimmedCommand, ',');
    if (tokens.empty()) {
        logMessage("ERROR", "Invalid command received from socket: " + std::to_string(clientSocket));
        return;
    }

    std::string cmd = tokens[0];
    logMessage("INFO", "Received command: " + cmd + " from socket: " + std::to_string(clientSocket));

    // Use std::string::compare() for more reliable string comparison
    if (cmd.compare("HELO") == 0 && tokens.size() == 2) {
        std::string groupID = trim(tokens[1]);
        logMessage("INFO", "HELO received from GroupID: " + groupID);
        sendServersList(clientSocket);  // Respond with SERVERS list
    }

    else if (cmd.compare("SENDMSG") == 0 && tokens.size() >= 4) {
        // Check if the command has the correct number of arguments
        if (tokens.size() < 4) {
            logMessage("ERROR", "Ill-formed SENDMSG command from socket: " + std::to_string(clientSocket));
            std::string errorMsg = "ERROR: Incorrect SENDMSG format";
            send(clientSocket, frameMessage(errorMsg).c_str(), frameMessage(errorMsg).length(), 0);
            return;
        }

        std::string toGroupID = trim(tokens[1]);
        std::string fromGroupID = trim(tokens[2]);
        
        // Rebuild the message content by joining everything after tokens[3]
        std::string messageContent;
        for (size_t i = 3; i < tokens.size(); ++i) {
            messageContent += tokens[i];
            if (i != tokens.size() - 1) {
                messageContent += " ";  // Add space between words
            }
        }

        // If the message content is empty, handle this as an error
        if (messageContent.empty()) {
            logMessage("ERROR", "Empty message content in SENDMSG from socket: " + std::to_string(clientSocket));
            std::string errorMsg = "ERROR: Message content is empty";
            send(clientSocket, frameMessage(errorMsg).c_str(), frameMessage(errorMsg).length(), 0);
            return;
        }
        
        // Store the message for the receiving group
        storedMessages[toGroupID].push_back("From " + fromGroupID + ": " + messageContent);
        logMessage("INFO", "Message stored for GroupID: " + toGroupID);

        // Log current state of the storedMessages map for debugging
        for (const auto &entry : storedMessages) {
            logMessage("DEBUG", "Stored messages for GroupID: " + entry.first + " | Message count: " + std::to_string(entry.second.size()));
        }
    }

    else if (cmd.compare("GETMSGS") == 0 && tokens.size() == 2) {
        std::string groupID = trim(tokens[1]);
        logMessage("INFO", "GETMSGS received for GroupID: " + groupID);

        if (storedMessages.find(groupID) != storedMessages.end() && !storedMessages[groupID].empty()) {
            for (const std::string &msg : storedMessages[groupID]) {
                std::string framedMsg = frameMessage(msg + "\n");  // Add newline after each message
                send(clientSocket, framedMsg.c_str(), framedMsg.length(), 0);
            }
            storedMessages[groupID].clear();  // Clear messages after sending
            logMessage("INFO", "Messages sent to GroupID: " + groupID);
        } else {
            std::string noMessages = "No messages found for GroupID: " + groupID;
            std::string framedNoMessages = frameMessage(noMessages);
            send(clientSocket, framedNoMessages.c_str(), framedNoMessages.length(), 0);
            logMessage("INFO", "No messages found for GroupID: " + groupID);
        }
    }

    else if (cmd.compare("STATUSREQ") == 0) {  // Use compare for STATUSREQ check
        logMessage("INFO", "STATUSREQ received");
        
        // Prepare STATUSRESP response with message count for each group
        std::stringstream statusResponse;
        statusResponse << "STATUSRESP";
        for (const auto &entry : storedMessages) {
            statusResponse << "," << entry.first << "," << entry.second.size();
        }
        std::string framedStatus = frameMessage(statusResponse.str());
        send(clientSocket, framedStatus.c_str(), framedStatus.length(), 0);
        logMessage("INFO", "STATUSRESP sent to socket: " + std::to_string(clientSocket));
    }
    else {
        logMessage("ERROR", "Unknown command: " + cmd);
        
        // Send an error message back to the client
        std::string errorMsg = "ERROR: Unknown command " + cmd;
        std::string framedError = frameMessage(errorMsg);
        send(clientSocket, framedError.c_str(), framedError.length(), 0);
    }
}

// Main server loop for accepting new connections and managing clients/servers
void serverLoop(int listenSock) { // NEEDS ALOT OF LOGGING
    fd_set openSockets, readSockets;
    int maxfds = listenSock;

    FD_ZERO(&openSockets);
    FD_SET(listenSock, &openSockets);

    logMessage("INFO", "Server started main loop");

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
                        logMessage("INFO", "New client/server connected on socket " + std::to_string(newSock));
                        char clientIP[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &(clientAddr.sin_addr), clientIP, INET_ADDRSTRLEN);
                        logMessage("INFO", "Client IP: " + std::string(clientIP) + " Port: " + std::to_string(ntohs(clientAddr.sin_port)));
                    }
                } else {
                    // Handle client/server commands
                    char buffer[MAX_BUFFER];
                    memset(buffer, 0, MAX_BUFFER);
                    int bytesReceived = recv(i, buffer, MAX_BUFFER, 0);
                    if (bytesReceived <= 0) {
                        close(i);
                        FD_CLR(i, &openSockets);
                        logMessage("INFO", "Connection closed on socket: " + std::to_string(i));
                    } else {
                        std::string receivedMsg(buffer, bytesReceived);
                        logMessage("INFO", "Received data on socket " + std::to_string(i) + ": " + receivedMsg);
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
    logMessage("INFO", "Server started on port " + std::to_string(port));

    // Start main server loop
    serverLoop(listenSock);

    return 0;
}
