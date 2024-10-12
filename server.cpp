// Compile: g++ server.cpp -o tsamgroup1 -pthread
// Usage: ./tsamgroup1 60000 130.208.246.249 5001 5005

// TODO: Byrja að tengjast fleiri serverum og double checka virkni á KEEPALIVE
// TODO: Modify connectToServer to establish connections with at least 3 servers.
// Loop through the server list and try to connect to each server until 
// a minimum of 3 connections are established.
// Ensure to retry if a connection fails and update the connectedServers map.
// TODO: In the main server loop, ensure that KEEPALIVE messages are sent periodically 
// to all connected servers.
// Check if the last KEEPALIVE was received within a reasonable time (e.g., 60 seconds). 
// If not, remove the server from the list of connected servers and log a warning.
// TODO: Implement message routing in the SENDMSG command.
// If the destination server for the message is not the current server, 
// forward the message to the appropriate server in the connectedServers list.
// If the destination server is unavailable, store the message and forward it later.
// TODO: Modify the SENDMSG command handler to store messages for disconnected servers.
// When the destination server reconnects, check storedMessages and forward any 
// queued messages.
// Ensure that GETMSGS can retrieve stored messages when requested by the destination server.
// TODO: Implement the LISTSERVERS command in handleClientCommand function.
// When a client sends LISTSERVERS, respond with a list of currently connected servers, 
// including their GroupID, IP address, and port.
// TODO: Add logic to retry failed server connections periodically.
// If a server disconnects, try to reconnect after a set interval.
// Ensure the connection attempt does not block the main server loop.
// TODO: Implement the STATUSREQ command to send a request to other servers 
// asking for their status, including message counts.
// Respond with a STATUSRESP showing the number of messages queued or forwarded 
// for each connected server.
// TODO: Implement server failure detection.
// If a server does not respond to multiple KEEPALIVE messages or other commands,
// mark the server as disconnected and remove it from connectedServers.



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
#include <chrono>
#include <set>
#include <array>
#include <cstdio>
#include <netdb.h>
#include <mutex>
#include <csignal>
#include <signal.h>

int listenSock; 


#define SOH 0x01  // Start of Header
#define EOT 0x04  // End of Transmission
#define MAX_BUFFER 5000
#define BACKLOG 5  // Maximum number of queued connections
#define TIMEOUT_SEC 5  // 5-second timeout for waiting for server response
#define MAX_LOG_FILE_SIZE 1024 * 1024 * 5  // 5MB max log size
#define LOG_FILE "server_log.txt"
#define ROTATED_LOG_FILE "server_log_old.txt"
#define BLOCK_TIME_MINUTES 1  // Block IPs for 30 minutes


// Structure to hold server information
struct ServerInfo {
    std::string groupID;  // Group ID for the server
    std::string ipAddress;
    int port;
    int sockfd;           // Socket file descriptor
    time_t lastKeepAlive; // Timestamp of the last KEEPALIVE message
};

std::mutex logMutex;  // Define a global mutex
std::vector<ServerInfo> serverList; // Dynamic list of instructor servers
std::map<int, ServerInfo> connectedServers; // Map for connected servers and their information
std::map<std::string, std::vector<std::string>> storedMessages; // Map for stored messages per group
std::map<int, std::string> clientNames; // For client connections
std::string connectedServersIPs;

// Define the current server's information
std::string currentServerName = "A5_1";
std::string currentServerIP;  // The current server's public IP address (Rasp PI behind Fortigate using port mapping)
int port;  // The port this server is listening on

std::ofstream logFile; // Setup the log file
// Blocklist to track blocked IPs and their unblock time (using chrono for time tracking)
std::map<std::string, std::chrono::time_point<std::chrono::system_clock>> blocklist;
// Map to track failed commands per IP
std::map<std::string, int> failedCommandCount;
fd_set openSockets;  // File descriptor set for open sockets

void rotateLogFile();

// Logs messages to a file

void logMessage(const std::string& logType, const std::string& message) {
    std::lock_guard<std::mutex> lock(logMutex);  // Lock the mutex

    time_t now = time(0);
    char* dt = ctime(&now);
    dt[strlen(dt) - 1] = '\0';  // Remove the newline

    // Log to console
    std::cout << "[" << dt << "] [" << logType << "] " << message << std::endl;
    std::string logEntry = "[" + std::string(dt) + "] [" + logType + "] " + message + "\n";

    // Write to log file
    logFile << logEntry;
    logFile.flush();  // Ensure immediate writing to the file

    // Rotate log file if needed
    rotateLogFile();
}

// Choose a random server from the list
ServerInfo chooseRandomServer() {
    srand(time(0));  // Seed the random number generator
    int randomIndex = rand() % serverList.size();
    return serverList[randomIndex];
}

bool isPortAvailable(int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return false;
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    int result = bind(sockfd, (struct sockaddr*)&addr, sizeof(addr));
    close(sockfd);
    return result == 0;
}

int findFreePort() {
    int port = 4000;  
    while (!isPortAvailable(port)) {
        port++;
    }
    return port;
}

std::string getPublicIP() {
    std::string command = "curl -s ifconfig.me";
    std::array<char, 128> buffer;
    std::string result;

    FILE* pipe = popen(command.c_str(), "r"); 
    if (!pipe) throw std::runtime_error("popen() failed!"); 

    // Read the output of the command
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }
    pclose(pipe); 
    return result;
}


std::string pingServer(const std::string &ip) {
    std::string command = "ping -c 1 " + ip;
    std::array<char, 128> buffer;
    std::string result;

    FILE* pipe = popen(command.c_str(), "r"); 
    if (!pipe) throw std::runtime_error("popen() failed!"); 

    // Read the output of the command
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }
    pclose(pipe);
    return result;
}

// Function to rotate log file if it exceeds the max size
void rotateLogFile() {
    struct stat logFileInfo;
    if (stat(LOG_FILE, &logFileInfo) == 0 && logFileInfo.st_size >= MAX_LOG_FILE_SIZE) {
        logFile.close();
        logMessage("INFO", "Rotating log file..."); // Log before rotation
        
        // Rename current log file
        rename(LOG_FILE, ROTATED_LOG_FILE);

        // Re-open the log file
        logFile.open(LOG_FILE, std::ios::out | std::ios::app);
        if (logFile) {
            logMessage("INFO", "Log file rotation completed, new log started.");
        } else {
            std::cerr << "Failed to reopen log file after rotation." << std::endl;
        }
    }
}

void sendHELOCommand(int sockfd);

// Try to connect to a server, return the socket file descriptor or -1 if failed
int tryToConnect(ServerInfo server) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        logMessage("ERROR", "socket() failed for server " + server.ipAddress);
        return -1;
    }

    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(server.port);  // Correctly set the port in network byte order

    if (inet_pton(AF_INET, server.ipAddress.c_str(), &serverAddr.sin_addr) <= 0) {
        logMessage("ERROR", "inet_pton() failed for IP " + server.ipAddress);
        close(sockfd);
        return -1;
    }

    // Attempt to connect to the server
    if (connect(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        logMessage("ERROR", "connect() failed to " + server.ipAddress + " on port " + std::to_string(server.port));
        close(sockfd);
        return -1;
    }
    
    // Send HELO after successful connection
    sendHELOCommand(sockfd);
    logMessage("INFO", "Successfully connected to server " + server.ipAddress + " on port " + std::to_string(server.port));
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


// Send the "HELO,A5_1" command to a random server
void sendHELOCommand(int sockfd) {
    std::string heloCommand = "HELO," + currentServerName;  // Send the current server's group ID
    std::string framedCommand = std::string(1, SOH) + heloCommand + std::string(1, EOT);
    
    logMessage("DEBUG", "Framed HELO command: " + framedCommand + " on socket " + std::to_string(sockfd));
    
    ssize_t result = send(sockfd, framedCommand.c_str(), framedCommand.length(), 0);
    if (result >= 0) {
        logMessage("INFO", "Sent HELO command: " + heloCommand + " on socket " + std::to_string(sockfd));
    } else {
        logMessage("ERROR", "Failed to send HELO command on socket " + std::to_string(sockfd));
    }
}

ssize_t recvWithLogging(int sockfd, char *buffer, size_t bufferSize); 
std::string unframeMessage(const std::string &msg);

// Helper function to trim whitespace or extra characters from strings
std::string trim(const std::string &str) {
    if (str.empty()) return "";  // Handle empty strings
    size_t first = str.find_first_not_of(" \n\r\t");
    if (first == std::string::npos) return "";  // All characters are whitespace
    size_t last = str.find_last_not_of(" \n\r\t");
    return str.substr(first, (last - first + 1));
}

// Exports the server names from helo commands
std::string receiveHELOResponse(int sockfd) {
    char buffer[MAX_BUFFER];
    memset(buffer, 0, MAX_BUFFER);

    fd_set readfds;
    struct timeval timeout;

    FD_ZERO(&readfds);
    FD_SET(sockfd, &readfds);

    timeout.tv_sec = TIMEOUT_SEC;
    timeout.tv_usec = 0;

    logMessage("DEBUG", "Waiting for HELO response on socket " + std::to_string(sockfd));

    int activity = select(sockfd + 1, &readfds, NULL, NULL, &timeout);
    if (activity > 0 && FD_ISSET(sockfd, &readfds)) {
        logMessage("DEBUG", "Receiving HELO response on socket " + std::to_string(sockfd));
        int bytesReceived = recvWithLogging(sockfd, buffer, MAX_BUFFER);
        if (bytesReceived > 0) {
            std::string response(buffer, bytesReceived);
            logMessage("INFO", "Received framed HELO response: " + response + " on socket " + std::to_string(sockfd));

            // Unframe the message (strip SOH and EOT)
            std::string unframedResponse = unframeMessage(response);
            logMessage("DEBUG", "Unframed HELO response: " + unframedResponse);

            // Check if the unframed response starts with "HELO,"
            if (unframedResponse.rfind("HELO,", 0) == 0) {
                logMessage("DEBUG", "Valid HELO prefix found in response: " + unframedResponse);

                // Extract the server name, which is everything after "HELO,"
                std::string serverName = unframedResponse.substr(5);  // Skip "HELO,"
                serverName = trim(serverName);  // Trim any extra spaces or newlines

                if (!serverName.empty()) {
                    logMessage("DEBUG", "Extracted server name: " + serverName);
                    return serverName;
                } else {
                    logMessage("ERROR", "Extracted server name is empty.");
                    return "";  // Return empty if server name is empty
                }
            } else {
                logMessage("ERROR", "Response doesn't start with 'HELO,': " + unframedResponse);
                return "";  // Invalid response
            }
        } else {
            logMessage("ERROR", "No data received in HELO response, bytes received: " + std::to_string(bytesReceived));
            return "";  // No data received
        }
    } else if (activity == 0) {
        logMessage("WARNING", "No response from server after HELO, timeout reached on socket " + std::to_string(sockfd));
        return "";  // Timeout reached
    } else {
        logMessage("ERROR", "Error in select() during HELO response waiting.");
        return "";  // Error in select
    }
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
        int bytesReceived = recvWithLogging(sockfd, buffer, MAX_BUFFER);
        if (bytesReceived > 0) {
            std::string receivedMsg(buffer, bytesReceived);
            logMessage("INFO", "Received message from server: " + receivedMsg);
        }
    } else if (activity == 0) {
        logMessage("WARNING", "No response from server within " + std::to_string(TIMEOUT_SEC) + " seconds, retrying...");
        sendHELOCommand(sockfd);  // Resend HELO in case of no response
    } else {
        logMessage("ERROR", "Error occurred during select() for socket " + std::to_string(sockfd));
    }
}

// Logging enhanced send function
ssize_t sendWithLogging(int sockfd, const std::string &message) {
    ssize_t bytesSent = send(sockfd, message.c_str(), message.length(), 0);
    if (bytesSent < 0) {
        logMessage("ERROR", "Failed to send message on socket " + std::to_string(sockfd));
    } else {
        logMessage("INFO", "Sent message on socket " + std::to_string(sockfd) + ": " + message);
    }
    return bytesSent;
}

// Logging enhanced receive function
ssize_t recvWithLogging(int sockfd, char *buffer, size_t bufferSize) {
    ssize_t bytesReceived = recv(sockfd, buffer, bufferSize, 0);
    if (bytesReceived < 0) {
        logMessage("ERROR", "Failed to receive message on socket " + std::to_string(sockfd));
    } else {
        std::string receivedMsg(buffer, bytesReceived);
        logMessage("DEBUG", "Raw data received on socket " + std::to_string(sockfd) + ": " + receivedMsg);
        logMessage("INFO", "Bytes received on socket " + std::to_string(sockfd) + ": " + std::to_string(bytesReceived));
    }
    return bytesReceived;
}




// Ping the server and get the server name
std::string pingServerAndGetName(const std::string &ipAddress) {
    std::string pingResult = pingServer(ipAddress);
    if (pingResult.find("1 packets transmitted, 1 received") != std::string::npos) {
        // Ping succeeded, try to get the hostname
        struct sockaddr_in sa;
        char host[1024];

        sa.sin_family = AF_INET;
        inet_pton(AF_INET, ipAddress.c_str(), &sa.sin_addr);

        int result = getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, sizeof(host), NULL, 0, 0);
        if (result == 0) {
            // Successfully resolved the name
            return std::string(host);
        } else {
            // Could not resolve hostname, return IP as fallback
            return ipAddress;
        }
    } else {
        // Ping failed, mark server as unreachable
        return "UNREACHABLE_" + ipAddress;
    }
}

// Update the populateServerList to fetch server names using ping
void populateServerList(const std::string &ipAddress, int portStart, int portEnd) {
    serverList.clear();
    int groupNumber = 1;

    logMessage("DEBUG", "Starting to populate server list from " + ipAddress + " for port range " + std::to_string(portStart) + " to " + std::to_string(portEnd));

    for (int port = portStart; port <= portEnd; ++port) {
        logMessage("DEBUG", "Attempting to connect to server on port " + std::to_string(port));

        int sockfd = tryToConnect({ "Group_" + std::to_string(groupNumber), ipAddress, port, -1, 0 });
        if (sockfd >= 0) {
            logMessage("DEBUG", "Connection to server on port " + std::to_string(port) + " successful. Sending HELO.");

            sendHELOCommand(sockfd);
            std::string responseName = receiveHELOResponse(sockfd);

            if (!responseName.empty()) {
                logMessage("DEBUG", "Received valid server name from HELO response: " + responseName);
            } else {
                responseName = "server_" + std::to_string(port);
                logMessage("WARNING", "Fallback to default server name: " + responseName);
            }

            // Add the server with the final name
            serverList.push_back({responseName, ipAddress, port, sockfd, time(0)});
            logMessage("INFO", "Populated server: " + responseName + " (" + ipAddress + ":" + std::to_string(port) + ")");
        } else {
            logMessage("ERROR", "Failed to connect to server " + ipAddress + " on port " + std::to_string(port));
        }

        ++groupNumber;
    }

    logMessage("DEBUG", "Finished populating server list.");
}

// Function to check if an IP is blocked
bool isBlocked(const std::string &ip) {
    auto now = std::chrono::system_clock::now();
    if (blocklist.find(ip) != blocklist.end()) {
        if (blocklist[ip] > now) {
            return true;
        } else {
            // Remove IP from blocklist after block time expires
            blocklist.erase(ip);
            logMessage("INFO", "Unblocked IP: " + ip);
        }
    }
    return false;
}

// Function to block an IP for 30 minutes
void blockIP(const std::string &ip) {
    auto now = std::chrono::system_clock::now();
    auto unblockTime = now + std::chrono::minutes(BLOCK_TIME_MINUTES);
    blocklist[ip] = unblockTime;
    logMessage("INFO", "Blocked IP: " + ip + " for 30 minutes.");
}

// Helper function to frame messages with SOH and EOT
std::string frameMessage(const std::string &msg) {
    return std::string(1, SOH) + msg + std::string(1, EOT);
}

// Helper function to unframe messages (remove SOH and EOT)
std::string unframeMessage(const std::string &msg) {
    if (msg[0] == SOH && msg[msg.size() - 1] == EOT) {
        return msg.substr(1, msg.size() - 2);  // Strip SOH and EOT
    }
    return msg;
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

void monitorKeepAlive() {
    time_t currentTime = time(0);

    for (auto it = connectedServers.begin(); it != connectedServers.end(); ) {
        // Check if the server has not sent KEEPALIVE within 10 * TIMEOUT_SEC
        if (difftime(currentTime, it->second.lastKeepAlive) > TIMEOUT_SEC * 10) {
            logMessage("WARNING", "No KEEPALIVE from server " + it->second.ipAddress + ". Closing connection.");

            close(it->second.sockfd);  // Close the connection
            FD_CLR(it->second.sockfd, &openSockets);  // Remove from FD_SET to avoid Bad file descriptor
            it = connectedServers.erase(it);  // Remove the server from the list
        } else {
            ++it;
        }
    }
}

void sendKeepAliveMessages() {
    time_t currentTime = time(0);

    for (auto &entry : connectedServers) {
        ServerInfo &server = entry.second;

        // Send KEEPALIVE if the last one was sent more than 60 seconds ago
        if (difftime(currentTime, server.lastKeepAlive) >= 60) {
            std::string keepAliveMsg = frameMessage("KEEPALIVE," + std::to_string(storedMessages[server.groupID].size()));
            ssize_t result = sendWithLogging(server.sockfd, keepAliveMsg);

            if (result >= 0) {
                server.lastKeepAlive = currentTime;
                logMessage("INFO", "Sent KEEPALIVE to server " + server.ipAddress + ":" + std::to_string(server.port) + ", messages queued: " + std::to_string(storedMessages[server.groupID].size()));
            }
        }
    }
}


void resetBlocklist() {
    blocklist.clear();
    logMessage("INFO", "Blocklist has been cleared.");
}


void handleClientCommand(int clientSocket, const std::string &command, const std::string &clientIP, fd_set &openSockets) {
    // Trim the command before processing
    std::string unframedCommand = unframeMessage(command);
    std::string trimmedCommand = trim(unframedCommand);

    // Check if the client is blocked
    if (isBlocked(clientIP)) {
        logMessage("INFO", "Blocked IP attempted to connect: " + clientIP);
        close(clientSocket);  // Close the connection immediately
        FD_CLR(clientSocket, &openSockets);  // Remove the socket from the FD set
        return;
    }

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

    // Split the command into tokens
    std::vector<std::string> tokens = splitString(trimmedCommand, ',');
    std::string cmd = tokens[0];

    if (cmd.compare("RESETBLOCK") == 0) {
        resetBlocklist();  // Call the resetBlocklist function
        std::string resetMsg = "Blocklist has been cleared.";
        send(clientSocket, frameMessage(resetMsg).c_str(), frameMessage(resetMsg).length(), 0);
        logMessage("INFO", "Blocklist reset via command.");
        return;
    }

    if (cmd.compare("HELO") == 0 && tokens.size() == 2) {
        std::string groupID = trim(tokens[1]);

        // Update the connectedServers map with the new server info
        struct sockaddr_in addr;
        socklen_t addr_size = sizeof(struct sockaddr_in);
        getpeername(clientSocket, (struct sockaddr *)&addr, &addr_size);
        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(addr.sin_addr), clientIP, INET_ADDRSTRLEN);

        ServerInfo newServer = {groupID, std::string(clientIP), ntohs(addr.sin_port), clientSocket, time(0)};
        connectedServers[clientSocket] = newServer;  // Add the new server to the connectedServers map

        logMessage("INFO", "HELO received from GroupID: " + groupID + ", IP: " + std::string(clientIP) + ", Port: " + std::to_string(ntohs(addr.sin_port)));

        sendServersList(clientSocket);  // Respond with SERVERS list
    
    } else if (cmd.compare("SENDMSG") == 0 && tokens.size() >= 4) {
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

        if (messageContent.empty()) {
            logMessage("ERROR", "Empty message content in SENDMSG from socket: " + std::to_string(clientSocket));
            std::string errorMsg = "ERROR: Message content is empty";
            send(clientSocket, frameMessage(errorMsg).c_str(), frameMessage(errorMsg).length(), 0);
            return;
        }

        // Store the message for the receiving group
        storedMessages[toGroupID].push_back("From " + fromGroupID + ": " + messageContent);
        logMessage("INFO", "Message stored for GroupID: " + toGroupID);

        // Debug logging for stored messages
        logMessage("DEBUG", "Current stored messages for GroupID " + toGroupID + ": ");
        for (const auto &msg : storedMessages[toGroupID]) {
            logMessage("DEBUG", msg);
        }

    } else if (cmd.compare("GETMSGS") == 0 && tokens.size() == 2) {
        std::string groupID = trim(tokens[1]);
        logMessage("INFO", "GETMSGS received for GroupID: " + groupID);

        if (storedMessages.find(groupID) != storedMessages.end() && !storedMessages[groupID].empty()) {
            // Send all messages for the group
            for (const std::string &msg : storedMessages[groupID]) {
                std::string framedMsg = frameMessage(msg + "\n");
                send(clientSocket, framedMsg.c_str(), framedMsg.length(), 0);
            }

            // Clear messages after sending
            storedMessages[groupID].clear();
            logMessage("INFO", "Messages sent to GroupID: " + groupID);
        } else {
            // No messages found
            std::string noMessages = "No messages found for GroupID: " + groupID;
            std::string framedNoMessages = frameMessage(noMessages);
            send(clientSocket, framedNoMessages.c_str(), framedNoMessages.length(), 0);
            logMessage("INFO", "No messages found for GroupID: " + groupID);
        }

    } else if (cmd.compare("STATUSREQ") == 0) {
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

    } else if (cmd.compare("KEEPALIVE") == 0) {
        std::string clientGroupID = clientNames[clientSocket];  // Get client GroupID from the map

        logMessage("INFO", "KEEPALIVE received from " + clientIP + ":" + std::to_string(port) + 
                   " with message count: " + std::to_string(storedMessages[clientGroupID].size()));

        // Check if there are any messages for this client
        if (storedMessages.find(clientGroupID) != storedMessages.end() && !storedMessages[clientGroupID].empty()) {
            for (const std::string &msg : storedMessages[clientGroupID]) {
                std::string framedMsg = frameMessage(msg + "\n");
                send(clientSocket, framedMsg.c_str(), framedMsg.length(), 0);
            }
            storedMessages[clientGroupID].clear();  // Clear the messages after sending
            logMessage("INFO", "Queued messages sent to client: " + clientGroupID);
        } else {
            // No messages queued, just acknowledge the KEEPALIVE
            std::string keepAliveAck = "KEEPALIVE: No messages queued";
            send(clientSocket, frameMessage(keepAliveAck).c_str(), frameMessage(keepAliveAck).length(), 0);
            logMessage("INFO", "No messages queued for client: " + clientGroupID);
        }

    } else {
        logMessage("ERROR", "Unknown command: " + cmd);

        // Send an error message back to the client
        std::string errorMsg = "ERROR: Unknown command " + cmd;
        std::string framedError = frameMessage(errorMsg);
        send(clientSocket, framedError.c_str(), framedError.length(), 0);
    }
}


std::set<std::string> blacklist; // Stores group IDs or IP addresses of blacklisted entities

// Function to check if a server is blacklisted
bool isBlacklisted(const std::string& groupID) {
    return blacklist.find(groupID) != blacklist.end();
}

// Add to blacklist after detection
void addToBlacklist(const std::string& groupID) {
    blacklist.insert(groupID);
    logMessage("INFO", "Added to blacklist: " + groupID);
}

void removeExpiredBlocks() {
    auto now = std::chrono::system_clock::now();
    for (auto it = blocklist.begin(); it != blocklist.end(); ) {
        if (it->second < now) {
            it = blocklist.erase(it);
        } else {
            ++it;
        }
    }
}

void serverLoop(int listenSock) {
    struct timeval timeout;
    int maxfds = listenSock;

    FD_ZERO(&openSockets);
    FD_SET(listenSock, &openSockets);

    logMessage("INFO", "Server started main loop");

    while (true) {
        fd_set readSockets = openSockets;  // Copy the set for select()
        timeout.tv_sec = 60;  // 60-second timeout for select()
        timeout.tv_usec = 0;

        int activity = select(maxfds + 1, &readSockets, NULL, NULL, &timeout);

        if (activity < 0 && errno != EINTR) {
            perror("select() failed");
            exit(EXIT_FAILURE);
        } else if (activity == 0) {
            logMessage("INFO", "No activity detected in 60 seconds, checking connections.");
            monitorKeepAlive();  // Check if we have inactive servers
            continue;
        }

        for (int i = 0; i <= maxfds; ++i) {
            if (FD_ISSET(i, &readSockets)) {
                if (i == listenSock) {
                    struct sockaddr_in clientAddr;
                    socklen_t clientLen = sizeof(clientAddr);
                    int newSock = accept(listenSock, (struct sockaddr *)&clientAddr, &clientLen);
                    if (newSock < 0) {
                        perror("accept() failed");
                    } else {
                        char clientIP[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);

                        FD_SET(newSock, &openSockets);
                        maxfds = std::max(maxfds, newSock);
                        logMessage("INFO", "New client/server connected on socket " + std::to_string(newSock) + " from IP: " + std::string(clientIP));
                    }
                } else {
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

                        struct sockaddr_in addr;
                        socklen_t addr_size = sizeof(struct sockaddr_in);
                        getpeername(i, (struct sockaddr *)&addr, &addr_size);
                        char clientIP[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &(addr.sin_addr), clientIP, INET_ADDRSTRLEN);

                        handleClientCommand(i, receivedMsg, clientIP, openSockets);
                    }
                }
            }
        }
    }
}

// Global variable to hold the main socket descriptor
int mainSocket = -1;

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

    exit(signum);  // Exit with the signal code
}

// Function to ensure the server connects to at least 3 other servers
void ensureMinimumConnections() {
    int connectedCount = 0;
    std::vector<int> triedIndexes;
    
    while (connectedCount < 3 && triedIndexes.size() < serverList.size()) {
        for (auto &server : serverList) {
            if (connectedServers.find(server.sockfd) == connectedServers.end()) {
                // Attempt to connect if not already connected
                int sockfd = tryToConnect(server);
                if (sockfd >= 0) {
                    server.sockfd = sockfd;
                    connectedServers[sockfd] = server;
                    connectedCount++;
                    logMessage("INFO", "Successfully connected to " + server.ipAddress + ":" + std::to_string(server.port));
                } else {
                    logMessage("ERROR", "Failed to connect to server " + server.ipAddress);
                }
            }
            triedIndexes.push_back(server.port);
        }
    }
    
    if (connectedCount < 3) {
        logMessage("WARNING", "Less than 3 server connections established.");
    } else {
        logMessage("INFO", "Successfully connected to at least 3 servers.");
    }
}

// Retry connection to failed servers every 30 seconds
void retryFailedConnections() {
    for (auto &server : serverList) {
        if (connectedServers.find(server.sockfd) == connectedServers.end()) {
            // Try reconnecting
            int sockfd = tryToConnect(server);
            if (sockfd >= 0) {
                server.sockfd = sockfd;
                connectedServers[sockfd] = server;
                logMessage("INFO", "Reconnected to server " + server.ipAddress);
            }
        }
    }
}

// Ensure periodic connection retries
void periodicConnectionRetries() {
    while (true) {
        retryFailedConnections();
        std::this_thread::sleep_for(std::chrono::seconds(30));  // Retry every 30 seconds
    }
}

// Start periodic keep-alive messages to all connected servers
void startKeepAliveLoop() {
    while (true) {
        sendKeepAliveMessages();
        std::this_thread::sleep_for(std::chrono::seconds(60));  // Send KEEPALIVE every 60 seconds
    }
}
int main(int argc, char *argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: ./tsamgroup1 SERVER_PORT CONNECTION_SERVER_IP CONNECTION_SERVER_PORT_START CONNECTION_SERVER_PORT_END" << std::endl;
        return EXIT_FAILURE;
    }

    // Assign command-line arguments
    port = atoi(argv[1]);                     // Port this server will listen on
    connectedServersIPs = argv[2];                // IP address of this server
    int connectionServerPortStart = atoi(argv[3]);  // Start of port range for connecting to other servers
    int connectionServerPortEnd = atoi(argv[4]);    // End of port range for connecting to other servers

    // Register signal handlers to handle interruptions (Ctrl+C, SIGTERM, SIGTSTP)
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    signal(SIGTSTP, signalHandler);  // Handle Ctrl+Z to clean up

    // Clear the blocklist
    blocklist.clear();

    // Retrieve public IP for the current server
    std::string publicIP = getPublicIP();
    currentServerIP = publicIP;  // Dynamically set the IP address
    logMessage("INFO", "Server's public IP: " + publicIP);

    // Open the log file for writing
    logFile.open(LOG_FILE, std::ios::out | std::ios::app);
    if (!logFile) {
        std::cerr << "Failed to open log file" << std::endl;
        return EXIT_FAILURE;
    }
    logMessage("INFO", "Log file opened successfully");

    // Populate the server list based on command-line input (range of ports)
    populateServerList(connectedServersIPs, connectionServerPortStart, connectionServerPortEnd);

    // Create the main listening socket
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

    // Set socket options (e.g., reuse address)
    int opt = 1;
    if (setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt() failed");
        close(listenSock);
        return EXIT_FAILURE;
    }

    // Bind the socket to the specified port
    if (bind(listenSock, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("bind() failed");
        close(listenSock);
        return EXIT_FAILURE;
    }

    // Start listening for incoming connections
    if (listen(listenSock, BACKLOG) < 0) {
        perror("listen() failed");
        close(listenSock);
        return EXIT_FAILURE;
    }

    std::cout << "Server is listening on port " << port << std::endl;
    logMessage("INFO", "Server started on port " + std::to_string(port));

    // Attempt to connect to at least 3 other servers
    ensureMinimumConnections();

    // Create a thread to send periodic keep-alive messages to connected servers
    std::thread keepAliveThread(startKeepAliveLoop);
    keepAliveThread.detach();  // Run the keep-alive logic in the background

    // Create a thread to periodically retry connecting to servers that have disconnected
    std::thread retryThread(periodicConnectionRetries);
    retryThread.detach();  // Run the retry logic in the background

    // Main server loop for handling client/server commands
    serverLoop(listenSock);

    return 0;  // Execution will never reach this line, as the server loop runs indefinitely
}
