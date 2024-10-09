// Compile: g++ server.cpp -o tsamgroup1 -pthread
// Usage: ./tsamgroup1 60000 130.208.246.249 5001 5005

// TODO: Passa að portið sé laust, gera auto.

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
#include <cstdlib>
#include <ctime>
#include <sys/select.h>
#include <fstream>
#include <sys/stat.h>

#define SOH 0x01  // Start of Header
#define EOT 0x04  // End of Transmission
#define MAX_BUFFER 5000
#define BACKLOG 5  // Maximum number of queued connections
#define TIMEOUT_SEC 5  // 5-second timeout for waiting for server response
#define MAX_LOG_FILE_SIZE 1024 * 1024 * 5  // 5MB max log size
#define LOG_FILE "server_log.txt"
#define ROTATED_LOG_FILE "server_log_old.txt"

// Structure to hold server information
struct ServerInfo {
    std::string groupID;  // Group ID for the server
    std::string ipAddress;
    int port;
    int sockfd;           // Socket file descriptor
    time_t lastKeepAlive; // Timestamp of the last KEEPALIVE message
};


std::vector<ServerInfo> serverList; // Dynamic list of instructor servers
std::map<int, ServerInfo> connectedServers; // Map for connected servers and their information
std::map<std::string, std::vector<std::string>> storedMessages; // Map for stored messages per group
std::map<int, std::string> clientNames; // For client connections
// Define the current server's information
std::string currentServerName = "A5_1";  // Update this as needed
std::string currentServerIP = "89.160.229.150";  // The current server's IP address (Rasp PI behind Fortigate using port mapping)
int port;  // The port this server is listening on

std::ofstream logFile; // Setup the log file

// Choose a random server from the list
ServerInfo chooseRandomServer() {
    srand(time(0));  // Seed the random number generator
    int randomIndex = rand() % serverList.size();
    return serverList[randomIndex];
}

// Try to connect to a server, return the socket file descriptor or -1 if failed
int tryToConnect(ServerInfo server) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket() failed");
        return -1;
    }

    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(server.port);
    
    if (inet_pton(AF_INET, server.ipAddress.c_str(), &serverAddr.sin_addr) <= 0) {
        perror("inet_pton() failed");
        close(sockfd);
        return -1;
    }

    // Attempt to connect to the server
    if (connect(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("connect() failed");
        close(sockfd);
        return -1;
    }

    std::cout << "Connected to server " << server.ipAddress << " on port " << server.port << std::endl;
    return sockfd;
}

// Attempt to connect to one of the instructor servers from the list
int connectToServer() {
    std::vector<int> triedIndexes;

    while (triedIndexes.size() < serverList.size()) {
        ServerInfo server = chooseRandomServer();

        // Make sure we haven't already tried this server
        if (std::find(triedIndexes.begin(), triedIndexes.end(), server.port) == std::end(triedIndexes)) {
            int sockfd = tryToConnect(server);
            if (sockfd >= 0) {
                // Add the instructor server to the connectedServers map
                server.sockfd = sockfd;  // Store the socket file descriptor
                connectedServers[sockfd] = server;  // Add to the connected servers map

                std::cout << "Added instructor server to connected servers: " << server.ipAddress << ":" << server.port << std::endl;
                return sockfd;  // Successful connection
            } else {
                std::cout << "Failed to connect to " << server.ipAddress << " on port " << server.port << std::endl;
            }
            triedIndexes.push_back(server.port);  // Mark this server as tried
        }
    }

    std::cerr << "All server connection attempts failed." << std::endl;
    return -1;
}


// Send the "HELO,A5 1" command to a random server
void sendHELOCommand(int sockfd) {
    std::string heloCommand = "HELO,A5 1";
    std::string framedCommand = std::string(1, SOH) + heloCommand + std::string(1, EOT);
    send(sockfd, framedCommand.c_str(), framedCommand.length(), 0);
    std::cout << "Sent: HELO,A5 1" << std::endl;
}

// Receive and print any output from the server
void receiveServerResponse(int sockfd) {
    fd_set readfds;
    struct timeval timeout;
    char buffer[MAX_BUFFER];
    
    FD_ZERO(&readfds);
    FD_SET(sockfd, &readfds);

    timeout.tv_sec = TIMEOUT_SEC;
    timeout.tv_usec = 0;

    // Wait for response from the server with a timeout
    int activity = select(sockfd + 1, &readfds, NULL, NULL, &timeout);

    if (activity > 0 && FD_ISSET(sockfd, &readfds)) {
        // Response received from the server
        int bytesReceived = recv(sockfd, buffer, MAX_BUFFER, 0);
        if (bytesReceived > 0) {
            std::string receivedMsg(buffer, bytesReceived);
            std::cout << "Received from server: " << receivedMsg << std::endl;
        } else {
            std::cerr << "No data received or connection closed." << std::endl;
        }
    } else {
        // No response received within the timeout period
        std::cout << "No response from server within " << TIMEOUT_SEC << " seconds." << std::endl;
        sendHELOCommand(sockfd);
    }
}

// Function to rotate log file if it exceeds the max size
void rotateLogFile() {
    struct stat logFileInfo;
    if (stat(LOG_FILE, &logFileInfo) == 0 && logFileInfo.st_size >= MAX_LOG_FILE_SIZE) {
        // Close current log file
        logFile.close();

        // Rename the old log file
        rename(LOG_FILE, ROTATED_LOG_FILE);

        // Re-open a new log file
        logFile.open(LOG_FILE, std::ios::out | std::ios::app);
    }
}

// Logs messages to a file
void logMessage(const std::string& logType, const std::string& message) {
    time_t now = time(0);
    char* dt = ctime(&now);
    dt[strlen(dt)-1] = '\0'; // Remove the newline

    // Log to console
    std::cout << "[" << dt << "] [" << logType << "] " << message << std::endl;
    std::string logEntry = "[" + std::string(dt) + "] [" + logType + "] " + message + "\n";

    // Write to log file
    logFile << logEntry;
    logFile.flush();
    
    // Rotate log file if it exceeds max size
    rotateLogFile();
}

// Dynamically populate the connection server list based on provided arguments
// TODO: Þarf að laga einhvernvegin server names, kanski gera ping taka server name og populate-a
void populateServerList(const std::string &ipAddress, int portStart, int portEnd) {
    serverList.clear();
    int groupNumber = 1;
    for (int port = portStart; port <= portEnd; ++port) {
        serverList.push_back({"CONNECTION_SERVER_" + std::to_string(groupNumber), ipAddress, port, -1, 0});
        ++groupNumber;
    }
    logMessage("INFO", "Populated server list with IP: " + ipAddress + " and ports from " + std::to_string(portStart) + " to " + std::to_string(portEnd));
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

    // Add current server's information to the response
    response << "," << currentServerName << "," << currentServerIP << "," << port;

    // Iterate over the connectedServers map and append other connected servers' details
    for (const auto &entry : connectedServers) {
        const ServerInfo &server = entry.second;
        response << "," << server.groupID << "," << server.ipAddress << "," << server.port;
    }

    // Frame and send the response
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
        send(clientSocket, frameMessage(errorMsg ).c_str(), frameMessage(errorMsg).length(), 0);
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
            std::string errorMsg = "ERROR: Incorrect SENDMSG format\n";
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
void serverLoop(int listenSock, int connectedSock) {
    fd_set openSockets, readSockets;
    int maxfds = listenSock;

    FD_ZERO(&openSockets);
    FD_SET(listenSock, &openSockets);

    logMessage("INFO", "Server started main loop");

    // After successfully connecting to an instructor server, receive and print its response
    receiveServerResponse(connectedSock);

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
    if (argc != 5) {
        std::cerr << "Usage: ./tsamgroup1 SERVER_PORT CONNECTION_SERVER_IP CONNECTION_SERVER_PORT_START CONNECTION_SERVER_PORT_END" << std::endl;
        return EXIT_FAILURE;
    }

    // Assign the command-line arguments
    port = atoi(argv[1]);
    currentServerIP = argv[2];
    int connectionServerPortStart = atoi(argv[3]);
    int connectionServerPortEnd = atoi(argv[4]);

    // Open the log file for writing
    logFile.open(LOG_FILE, std::ios::out | std::ios::app);
    if (!logFile) {
        std::cerr << "Failed to open log file" << std::endl;
        return EXIT_FAILURE;
    }

    // Populate the server list dynamically based on command-line arguments
    populateServerList(currentServerIP, connectionServerPortStart, connectionServerPortEnd);

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

    // Connect to one of the predefined servers
    int connectedSock = connectToServer();
    if (connectedSock < 0) {
        return EXIT_FAILURE;  // Exit if unable to connect to any server
    }

    // Start main server loop
    serverLoop(listenSock, connectedSock);

    return 0;
}
