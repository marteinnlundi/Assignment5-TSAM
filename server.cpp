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
    logMessage("INFO", "Connecting to server " + server.ipAddress + ":" + std::to_string(server.port));

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        logMessage("ERROR", "Failed to create socket");
        return -1;
    }

    int opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        logMessage("ERROR", "Failed to set socket options");
        close(sock);
        return -1;
    }

    // Bind the client socket to the same port as the server's listening socket
    struct sockaddr_in localAddr;
    memset(&localAddr, 0, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = INADDR_ANY;
    localAddr.sin_port = htons(port);  // Bind to the specified port

    if (bind(sock, (struct sockaddr*)&localAddr, sizeof(localAddr)) == -1) {
        logMessage("ERROR", "Failed to bind to local port " + std::to_string(port));
        close(sock);
        return -1;
    }

    // Delay to ensure the port is fully registered
    logMessage("DEBUG", "Introducing delay to ensure proper port registration");
    sleep(1);

    // Set up the remote server address
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(server.port);

    if (inet_pton(AF_INET, server.ipAddress.c_str(), &serverAddr.sin_addr) <= 0) {
        logMessage("ERROR", "Invalid remote address: " + server.ipAddress);
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        logMessage("ERROR", "Failed to connect to server " + server.ipAddress + ":" + std::to_string(server.port));
        close(sock);
        return -1;
    }

    logMessage("INFO", "Successfully connected to server " + server.ipAddress + " on port " + std::to_string(server.port));

    return sock;
}

// Try to connect to a server using the already bound socket
int tryToConnectUsingBoundSocket(int sockfd, const std::string& remoteIP, int remotePort) {
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(remotePort);

    if (inet_pton(AF_INET, remoteIP.c_str(), &serverAddr.sin_addr) <= 0) {
        logMessage("ERROR", "Invalid remote address: " + remoteIP);
        return -1;
    }

    // Use the already bound socket to connect to the remote server
    if (connect(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        logMessage("ERROR", "Failed to connect to server " + remoteIP + ":" + std::to_string(remotePort) + " - " + strerror(errno));
        return -1;
    }

    logMessage("INFO", "Successfully connected to server " + remoteIP + " on port " + std::to_string(remotePort));
    return 0; // Return success
}

std::string receiveHELOResponse(int sockfd);

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

                // Send HELO command
                sendHELOCommand(sockfd);

                // Receive SERVERS response and update server list
                receiveHELOResponse(sockfd);

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

    // Log local port info for verification
    struct sockaddr_in localAddr;
    socklen_t addrLen = sizeof(localAddr);
    if (getsockname(sockfd, (struct sockaddr*)&localAddr, &addrLen) == -1) {
        logMessage("ERROR", "Failed to get local socket info before sending HELO command.");
    } else {
        logMessage("INFO", "Local port before sending HELO: " + std::to_string(ntohs(localAddr.sin_port)));
    }

    logMessage("DEBUG", "Framed HELO command: " + framedCommand + " on socket " + std::to_string(sockfd));

    ssize_t result = send(sockfd, framedCommand.c_str(), framedCommand.length(), 0);
    if (result >= 0) {
        logMessage("INFO", "Sent HELO command: " + heloCommand + " on socket " + std::to_string(sockfd));
    } else {
        logMessage("ERROR", "Failed to send HELO command on socket " + std::to_string(sockfd));
    }
}

// Send the "HELO,A5_1" command to a random server with retry logic
void sendHELOCommandWithRetry(int sockfd) {
    std::string heloCommand = "HELO," + currentServerName;  // Send the current server's group ID
    std::string framedCommand = std::string(1, SOH) + heloCommand + std::string(1, EOT);
    
    int maxRetries = 3;  // Maximum number of retries for the HELO command
    int retryCount = 0;
    bool success = false;

    while (retryCount < maxRetries && !success) {
        logMessage("DEBUG", "Framed HELO command: " + framedCommand + " on socket " + std::to_string(sockfd));
        
        ssize_t result = send(sockfd, framedCommand.c_str(), framedCommand.length(), 0);
        if (result >= 0) {
            logMessage("INFO", "Sent HELO command: " + heloCommand + " on socket " + std::to_string(sockfd));

            // Wait for SERVERS response
            std::string response = receiveHELOResponse(sockfd);
            if (!response.empty()) {
                logMessage("INFO", "Received valid response after HELO command on retry " + std::to_string(retryCount + 1));
                success = true;
            } else {
                logMessage("WARNING", "No valid SERVERS response after HELO command on retry " + std::to_string(retryCount + 1));
                retryCount++;
            }
        } else {
            logMessage("ERROR", "Failed to send HELO command on socket " + std::to_string(sockfd) + ". Retrying...");
            retryCount++;
        }

        if (!success) {
            std::this_thread::sleep_for(std::chrono::seconds(2));  // Wait before retrying
        }
    }

    if (!success) {
        logMessage("ERROR", "HELO command failed after " + std::to_string(maxRetries) + " retries.");
    }
}

ssize_t recvWithLogging(int sockfd, char *buffer, size_t bufferSize); 
std::string unframeMessage(const std::string &msg);
std::string frameMessage(const std::string &msg);
std::vector<std::string> splitString(const std::string &str, char delimiter);

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

    logMessage("DEBUG", "Waiting for HELO or SERVERS response on socket " + std::to_string(sockfd));

    int activity = select(sockfd + 1, &readfds, NULL, NULL, &timeout);
    if (activity > 0 && FD_ISSET(sockfd, &readfds)) {
        logMessage("DEBUG", "Receiving response on socket " + std::to_string(sockfd));
        int bytesReceived = recvWithLogging(sockfd, buffer, MAX_BUFFER);
        if (bytesReceived > 0) {
            std::string response(buffer, bytesReceived);
            logMessage("INFO", "Received framed response: " + response + " on socket " + std::to_string(sockfd));

            // Unframe the message (strip SOH and EOT)
            std::string unframedResponse = unframeMessage(response);
            logMessage("DEBUG", "Unframed response: " + unframedResponse);

            // Check if the response starts with "SERVERS,"
            if (unframedResponse.rfind("SERVERS", 0) == 0) {
                logMessage("DEBUG", "Valid SERVERS prefix found in response: " + unframedResponse);

                // Remove "SERVERS," from the response
                std::string serversList = unframedResponse.substr(8);

                // Split the servers by ';'
                std::vector<std::string> servers = splitString(serversList, ';');
                for (const auto& serverInfo : servers) {
                    // Split the serverInfo by ','
                    std::vector<std::string> fields = splitString(serverInfo, ',');
                    if (fields.size() == 3) {
                        std::string groupID = fields[0];
                        std::string ipAddress = fields[1];
                        int serverPort = std::stoi(fields[2]);
                        logMessage("INFO", "Adding server from SERVERS response: " + groupID + " " + ipAddress + ":" + std::to_string(serverPort));

                        ServerInfo newServer = {groupID, ipAddress, serverPort, -1, time(0)};
                        
                        // Try to connect to the server and add to connectedServers
                        int sockfd = tryToConnect(newServer);
                        if (sockfd >= 0) {
                            newServer.sockfd = sockfd;
                            connectedServers[sockfd] = newServer;  // Add to connected servers map
                            logMessage("INFO", "Connected to server and added to connectedServers: " + newServer.groupID);
                        } else {
                            logMessage("ERROR", "Failed to connect to server: " + newServer.groupID);
                        }

                        serverList.push_back(newServer);  // Add to serverList
                    } else {
                        logMessage("ERROR", "Invalid server info format in SERVERS response: " + serverInfo);
                    }
                }
                return "";
            } else {
                logMessage("ERROR", "Response doesn't start with 'SERVERS,' : " + unframedResponse);
                return "";
            }
        } else {
            logMessage("ERROR", "No data received in response, bytes received: " + std::to_string(bytesReceived));
            return "";
        }
    } else if (activity == 0) {
        logMessage("WARNING", "No response from server after HELO or SERVERS, timeout reached on socket " + std::to_string(sockfd));
        return "";  // Timeout reached
    } else {
        logMessage("ERROR", "Error in select() during response waiting.");
        return "";
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

            std::string unframedMessage = unframeMessage(receivedMsg);

            // Handle the MESSAGES response from the server (for GETMSGS)
            if (unframedMessage.rfind("MESSAGES,", 0) == 0) {
                logMessage("INFO", "Received MESSAGES response: " + unframedMessage);

                // Step 3: Extract the GroupID and messages
                std::vector<std::string> tokens = splitString(unframedMessage, ',');
                if (tokens.size() >= 2) {
                    std::string groupID = tokens[1];
                    std::string messageContent;

                    // Rebuild the message content
                    for (size_t i = 2; i < tokens.size(); ++i) {
                        messageContent += tokens[i];
                        if (i != tokens.size() - 1) {
                            messageContent += " ";  // Add space between words
                        }
                    }

                    // Step 4: Forward the messages to the original requesting client
                    logMessage("INFO", "Forwarding received messages to the client who requested GETMSGS for GroupID: " + groupID);

                    std::string response = "MESSAGES," + groupID + "," + messageContent;
                    std::string framedResponse = frameMessage(response);

                    // Send the message to the original client (make sure to manage the client socket reference)
                    send(sockfd, framedResponse.c_str(), framedResponse.length(), 0);  // Assuming sockfd refers to the requesting client
                } else {
                    logMessage("ERROR", "Invalid MESSAGES response format: " + unframedMessage);
                }
            } 
            // Handle other types of messages (e.g., KEEPALIVE, STATUSRESP)
            else if (unframedMessage.rfind("KEEPALIVE", 0) == 0) {
                logMessage("INFO", "Received KEEPALIVE message from server.");

                // Update the last KEEPALIVE timestamp
                connectedServers[sockfd].lastKeepAlive = time(0);
            }
        }
    } 
    else if (activity == 0) {
        logMessage("WARNING", "No response from server within timeout of " + std::to_string(TIMEOUT_SEC) + " seconds, retrying...");
        sendHELOCommand(sockfd);  // Optionally resend HELO or handle timeout cases
    } 
    else {
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

        // Process the message (for GETMSGS and STATUSRESP)
        std::string unframedMessage = unframeMessage(receivedMsg);

        // Example for GETMSGS response
        if (unframedMessage.rfind("MESSAGES,", 0) == 0) {
            logMessage("INFO", "Messages received: " + unframedMessage);
        }
        // Example for STATUSRESP response
        else if (unframedMessage.rfind("STATUSRESP", 0) == 0) {
            logMessage("INFO", "Status response received: " + unframedMessage);
        }

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

        ServerInfo newServer = {"Group_" + std::to_string(groupNumber), ipAddress, port, -1, time(0)};
        int sockfd = tryToConnect(newServer);
        if (sockfd >= 0) {
            logMessage("DEBUG", "Connection to server on port " + std::to_string(port) + " successful. Sending HELO.");

            sendHELOCommand(sockfd);
            std::string responseName = receiveHELOResponse(sockfd);

            if (!responseName.empty()) {
                logMessage("DEBUG", "Received valid server name from HELO response: " + responseName);
                newServer.groupID = responseName;
            } else {
                responseName = "server_" + std::to_string(port);
                logMessage("WARNING", "Fallback to default server name: " + responseName);
                newServer.groupID = responseName;
            }

            newServer.sockfd = sockfd;
            connectedServers[sockfd] = newServer;  // Add to connected servers map
            serverList.push_back(newServer);  // Add to serverList
            logMessage("INFO", "Populated server and added to connectedServers: " + newServer.groupID);
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

    // Add the current server's information to the response (this server)
    response << "," << currentServerName << "," << currentServerIP << "," << port;

    // Iterate over the serverList and append other connected servers' details
    for (const auto& server : serverList) {
        response << ";" << server.groupID << "," << server.ipAddress << "," << std::to_string(server.port);
    }

    // Frame and send the response
    std::string framedResponse = frameMessage(response.str());
    send(sockfd, framedResponse.c_str(), framedResponse.length(), 0);

    // Log the SERVERS response for debugging
    logMessage("INFO", "Sent SERVERS list to socket: " + std::to_string(sockfd) + " - " + framedResponse);
}

void monitorKeepAlive() {
    time_t currentTime = time(0);

    for (auto it = connectedServers.begin(); it != connectedServers.end(); ) {
        double timeSinceLastKeepAlive = difftime(currentTime, it->second.lastKeepAlive);

        logMessage("DEBUG", "Checking KEEPALIVE for server: " + it->second.ipAddress + 
                   ". Time since last KEEPALIVE: " + std::to_string(timeSinceLastKeepAlive) + " seconds.");

        if (timeSinceLastKeepAlive > 120) {  // Timeout window for inactivity
            logMessage("WARNING", "No KEEPALIVE from server " + it->second.ipAddress +
                       " in the last " + std::to_string(timeSinceLastKeepAlive) + " seconds. Closing connection.");

            // Close the socket and remove the server
            close(it->second.sockfd);
            FD_CLR(it->second.sockfd, &openSockets);
            it = connectedServers.erase(it);
        } else {
            ++it;
        }
    }
}

// Send periodic keep-alive messages to all connected servers
void sendKeepAliveMessages() {
    time_t currentTime = time(0);

    for (auto it = connectedServers.begin(); it != connectedServers.end(); ) {
        ServerInfo &server = it->second;

        // Send KEEPALIVE if the last one was sent more than 60 seconds ago
        if (difftime(currentTime, server.lastKeepAlive) >= 60) {
            std::string keepAliveMsg = frameMessage("KEEPALIVE");

            ssize_t result = send(server.sockfd, keepAliveMsg.c_str(), keepAliveMsg.length(), 0);

            if (result < 0) {
                if (errno == EPIPE) {
                    // Handle broken pipe error
                    logMessage("WARNING", "Broken pipe detected for server " + server.ipAddress + ":" + std::to_string(server.port) + ". Closing connection.");

                    // Close the socket, remove from FD_SET, and erase from the map
                    close(server.sockfd);
                    FD_CLR(server.sockfd, &openSockets);  // Remove from FD_SET

                    // Safely remove the server from connectedServers
                    it = connectedServers.erase(it);
                } else {
                    logMessage("ERROR", "Failed to send KEEPALIVE to " + server.ipAddress + ":" + std::to_string(server.port) + ". Error: " + strerror(errno));
                    ++it;  // Move to the next server
                }
            } else {
                server.lastKeepAlive = currentTime;
                logMessage("INFO", "Sent KEEPALIVE to server " + server.ipAddress + ":" + std::to_string(server.port));
                ++it;  // Move to the next server
            }
        } else {
            ++it;  // Move to the next server
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

        logMessage("DEBUG", "Processing HELO for socket: " + std::to_string(clientSocket) + ", groupID: " + groupID);

        // Send SERVERS response to the client
        sendServersList(clientSocket);
        
        // Check if this server already exists in the list and replace it if found
        bool serverExists = false;
        for (auto &server : serverList) {
            if (server.groupID == groupID) {
                logMessage("INFO", "Replacing existing server with GroupID: " + groupID);
                server.sockfd = clientSocket;  // Update the socket descriptor
                server.lastKeepAlive = time(0);  // Reset keep-alive timestamp
                serverExists = true;
                break;
            }
        }

        // If the server doesn't exist, add it to the list
        if (!serverExists) {
            // Limit the server list to 8 servers
            if (serverList.size() >= 8) {
                logMessage("INFO", "Server list limit reached, removing the 3rd server in the list.");
                serverList.erase(serverList.begin() + 2);  // Remove the 3rd server
            }

            // Add the new server
            struct sockaddr_in addr;
            socklen_t addr_size = sizeof(struct sockaddr_in);
            getpeername(clientSocket, (struct sockaddr *)&addr, &addr_size);
            char clientIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(addr.sin_addr), clientIP, INET_ADDRSTRLEN);

            ServerInfo newServer = {groupID, std::string(clientIP), ntohs(addr.sin_port), clientSocket, time(0)};
            serverList.push_back(newServer);
            logMessage("INFO", "Added new server to the list: " + groupID);
        }

        // Log the current server list for debugging
        logMessage("DEBUG", "Current server list after HELO processing:");
        for (const auto &server : serverList) {
            logMessage("DEBUG", "Server in list: GroupID: " + server.groupID + ", IP: " + server.ipAddress + ", Port: " + std::to_string(server.port));
        }

    } else if (cmd.compare("SENDMSG") == 0 && tokens.size() >= 4) {
        std::string toGroupID = trim(tokens[1]);
        std::string fromGroupID = trim(tokens[2]);

        // Rebuild the message content
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

        // Store the message locally for the `toGroupID`
        logMessage("DEBUG", "Storing message for GroupID: " + toGroupID + " from " + fromGroupID + ": " + messageContent);
        storedMessages[toGroupID].push_back("From " + fromGroupID + ": " + messageContent);
        logMessage("INFO", "Message stored locally for GroupID: " + toGroupID);

        // Log all stored messages for debugging
        logMessage("DEBUG", "Stored messages for GroupID " + toGroupID + ": ");
        for (const auto &msg : storedMessages[toGroupID]) {
            logMessage("DEBUG", msg);
        }

    } else if (cmd.compare("GETMSGS") == 0 && tokens.size() == 2) {
        std::string groupID = trim(tokens[1]);
        logMessage("INFO", "Received GETMSGS command for GroupID: " + groupID);

        // Check local storage for messages
        if (storedMessages.find(groupID) != storedMessages.end() && !storedMessages[groupID].empty()) {
            logMessage("INFO", "Found local messages for GroupID: " + groupID);

            // Send local messages to the client
            std::string response = "MESSAGES," + groupID;
            for (const auto& message : storedMessages[groupID]) {
                response += "," + message;
            }

            // Frame the response and send it
            std::string framedResponse = frameMessage(response);
            send(clientSocket, framedResponse.c_str(), framedResponse.length(), 0);

            // Clear the messages after sending
            storedMessages[groupID].clear();
            logMessage("INFO", "Sent and cleared local messages for GroupID: " + groupID);
        } 
        else if (connectedServers.empty()) {
            logMessage("ERROR", "No connected servers available to forward GETMSGS request for GroupID: " + groupID);

            std::string errorMsg = "ERROR: No connected servers available to retrieve messages for GroupID: " + groupID;
            std::string framedError = frameMessage(errorMsg);
            send(clientSocket, framedError.c_str(), framedError.length(), 0);
        } 
        else {
            logMessage("INFO", "No local messages for GroupID: " + groupID + ". Forwarding GETMSGS to connected servers.");

            // Frame and forward the GETMSGS request to all connected servers
            std::string forwardMsg = frameMessage("GETMSGS," + groupID);
            for (const auto& server : connectedServers) {
                ssize_t result = send(server.second.sockfd, forwardMsg.c_str(), forwardMsg.length(), 0);
                if (result < 0) {
                    logMessage("ERROR", "Failed to send GETMSGS to server: " + server.second.groupID);
                } else {
                    logMessage("INFO", "Forwarded GETMSGS command to server: " + server.second.groupID);
                }
            }
        }

    } else if (cmd.compare("STATUSREQ") == 0) {
        logMessage("INFO", "STATUSREQ received");

        std::string aggregatedStatus = "STATUSRESP";  // Start with STATUSRESP

        // Collect local server status (messages stored in this server)
        for (const auto& entry : storedMessages) {
            aggregatedStatus += "," + entry.first + "," + std::to_string(entry.second.size());
        }

        // Send STATUSREQ to all connected servers and aggregate their responses
        for (const auto& server : connectedServers) {
            std::string statusReqCommand = frameMessage("STATUSREQ");
            ssize_t result = send(server.second.sockfd, statusReqCommand.c_str(), statusReqCommand.length(), 0);

            if (result < 0) {
                logMessage("ERROR", "Failed to send STATUSREQ to server: " + server.second.groupID);
            } else {
                char buffer[MAX_BUFFER];
                ssize_t bytesReceived = recv(server.second.sockfd, buffer, MAX_BUFFER, 0);
                if (bytesReceived > 0) {
                    std::string response(buffer, bytesReceived);
                    std::string unframedResponse = unframeMessage(response);

                    if (unframedResponse.rfind("STATUSRESP", 0) == 0) {
                        aggregatedStatus += "," + unframedResponse.substr(10);  // Append without "STATUSRESP"
                    }
                }
            }
        }

        // Return the final aggregated status response to the client
        std::string framedStatus = frameMessage(aggregatedStatus);
        send(clientSocket, framedStatus.c_str(), framedStatus.length(), 0);
        logMessage("INFO", "Sent aggregated STATUSRESP to client: " + aggregatedStatus);

    } else if (cmd.compare("KEEPALIVE") == 0) {
        logMessage("DEBUG", "Received KEEPALIVE on socket: " + std::to_string(clientSocket));

        if (clientNames.find(clientSocket) == clientNames.end()) {
            logMessage("ERROR", "No clientGroupID found for socket: " + std::to_string(clientSocket));
            return;
        }

        std::string clientGroupID = clientNames[clientSocket];
        logMessage("INFO", "KEEPALIVE received from " + clientIP + ":" + std::to_string(port) +
                " with message count: " + std::to_string(storedMessages[clientGroupID].size()));

        // Log the last keep-alive timestamp
        connectedServers[clientSocket].lastKeepAlive = time(0);  // Update the timestamp
        logMessage("INFO", "Updated last KEEPALIVE timestamp for client " + clientGroupID);
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
            // Check if any servers haven't sent KEEPALIVE in 120 seconds
            monitorKeepAlive();  
            continue;
        }

        // Existing logic for handling client and server connections
        for (int i = 0; i <= maxfds; ++i) {
            if (FD_ISSET(i, &readSockets)) {
                if (i == listenSock) {
                    // Accept new connections
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
                    // Handle client commands
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

// Function to ensure the server connects to at least 3 other servers using the same bound socket
void ensureMinimumConnections(int sockfd) {
    int connectedCount = 0;
    std::vector<int> triedIndexes;
    
    while (connectedCount < 3 && triedIndexes.size() < serverList.size()) {
        for (auto &server : serverList) {
            if (connectedServers.find(server.sockfd) == connectedServers.end()) {
                // Attempt to connect using the already bound socket (sockfd)
                int result = tryToConnectUsingBoundSocket(sockfd, server.ipAddress, server.port);
                if (result == 0) {
                    server.sockfd = sockfd;  // Reuse the bound socket
                    connectedServers[sockfd] = server;
                    connectedCount++;
                    logMessage("INFO", "Successfully connected to " + server.ipAddress + ":" + std::to_string(server.port));

                    // Send HELO command with retry logic
                    sendHELOCommandWithRetry(sockfd);
                    receiveHELOResponse(sockfd);  // Get SERVERS response
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
            logMessage("INFO", "Attempting to reconnect to server " + server.ipAddress + " on port " + std::to_string(server.port));

            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock == -1) {
                logMessage("ERROR", "Failed to create socket");
                continue;
            }

            int opt = 1;
            if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
                logMessage("ERROR", "Failed to set socket options");
                close(sock);
                continue;
            }

            // Bind the client socket to the same port as the server's listening socket
            struct sockaddr_in localAddr;
            memset(&localAddr, 0, sizeof(localAddr));
            localAddr.sin_family = AF_INET;
            localAddr.sin_addr.s_addr = INADDR_ANY;
            localAddr.sin_port = htons(port);

            if (bind(sock, (struct sockaddr*)&localAddr, sizeof(localAddr)) == -1) {
                logMessage("ERROR", "Failed to bind to local port " + std::to_string(port));
                close(sock);
                continue;
            }

            // Delay to ensure the port is fully registered
            logMessage("DEBUG", "Introducing delay to ensure proper port registration");
            sleep(1);

            // Set up the remote server address
            struct sockaddr_in serverAddr;
            memset(&serverAddr, 0, sizeof(serverAddr));
            serverAddr.sin_family = AF_INET;
            serverAddr.sin_port = htons(server.port);

            if (inet_pton(AF_INET, server.ipAddress.c_str(), &serverAddr.sin_addr) <= 0) {
                logMessage("ERROR", "Invalid remote address: " + server.ipAddress);
                close(sock);
                continue;
            }

            if (connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
                logMessage("ERROR", "Failed to connect to server " + server.ipAddress + ":" + std::to_string(server.port));
                close(sock);
                continue;
            }

            server.sockfd = sock;
            connectedServers[sock] = server;
            logMessage("INFO", "Reconnected to server " + server.ipAddress + " on port " + std::to_string(server.port));

            sendHELOCommandWithRetry(sock);
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
        sendKeepAliveMessages();  // Send KEEPALIVE to all connected servers
        std::this_thread::sleep_for(std::chrono::seconds(60));  // Send KEEPALIVE every 60 seconds
    }
}

int main(int argc, char *argv[]) {
    // Ignore SIGPIPE to prevent crashes when writing to closed sockets
    signal(SIGPIPE, SIG_IGN);

    if (argc != 5) {
        std::cerr << "Usage: ./tsamgroup1 SERVER_PORT CONNECTION_SERVER_IP CONNECTION_SERVER_PORT_START CONNECTION_SERVER_PORT_END" << std::endl;
        return EXIT_FAILURE;
    }

    // Assign command-line arguments
    port = atoi(argv[1]);  // Use the original port value for internal logic
    connectedServersIPs = argv[2];
    int connectionServerPortStart = atoi(argv[3]);
    int connectionServerPortEnd = atoi(argv[4]);

    // Register signal handlers to handle interruptions (Ctrl+C, SIGTERM, SIGTSTP)
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    signal(SIGTSTP, signalHandler);  // Handle Ctrl+Z to clean up

    // Clear the blocklist
    blocklist.clear();

    // Retrieve public IP for the current server
    std::string publicIP = getPublicIP();
    currentServerIP = publicIP;
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

    // Set socket options (reuse address)
    int opt = 1;
    if (setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        perror("setsockopt() failed");
        close(listenSock);
        return EXIT_FAILURE;
    }

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

    logMessage("INFO", "Server started on port " + std::to_string(port));

    // Ensure that we connect to at least 3 other servers
    ensureMinimumConnections(listenSock);

    // Start the thread for periodic keep-alive messages
    std::thread keepAliveThread(startKeepAliveLoop);
    keepAliveThread.detach();  // Start the KEEPALIVE thread

    // Main server loop
    serverLoop(listenSock);

    return 0;
}