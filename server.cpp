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
#include <iomanip>

int listenSock; 

#define SOH 0x01  // Start of Header
#define EOT 0x04  // End of Transmission
#define ESCAPE 0x10  // Data Link Escape
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
std::map<std::string, ServerInfo> connectedServers; // Map from groupID to ServerInfo
std::map<int, std::string> sockfdToGroupID; // Map from sockfd to groupID
std::map<std::string, std::vector<std::string>> storedMessages; // Map for stored messages per group
std::map<int, std::string> clientNames; // For client connections
std::string connectedServersIPs;

// Define the current server's information
std::string currentServerName;  // Will be initialized in main() from the command-line argument
std::string currentServerIP;  // The current server's public IP address
int port;  // The port this server is listening on

std::ofstream logFile; // Setup the log file
// Blocklist to track blocked IPs and their unblock time (using chrono for time tracking)
std::map<std::string, std::chrono::time_point<std::chrono::system_clock>> blocklist;
// Map to track failed commands per IP
std::map<std::string, int> failedCommandCount;
fd_set openSockets;  // File descriptor set for open sockets

void rotateLogFile();
std::string unframeMessage(const std::string &msg);
std::string frameMessage(const std::string &msg);
void processServersResponse(const std::string &response);
void sendServersList(int sockfd);

// Function to check the number of connected servers before allowing new connections
bool canEstablishConnection(bool isInitialConnection) {
    int connectedServerCount = connectedServers.size();

    // During initial connections, we don't need to enforce the minimum server rule
    if (isInitialConnection) {
        return true;  // Allow connection attempts without enforcing the 3-server minimum
    }

    if (connectedServerCount < 3) {
        std::cerr << "Connection attempt failed: Less than 3 servers are currently connected (" << connectedServerCount << " connected).\n";
        return false;
    } else if (connectedServerCount >= 8) {
        std::cerr << "Connection attempt failed: More than 8 servers are already connected (" << connectedServerCount << " connected).\n";
        return false;
    }

    return true; // Proceed if the number of connections is between 3 and 8
}


std::string stringToHex(const std::string& input) {
    std::stringstream hexStream;
    for (unsigned char c : input) {
        hexStream << std::hex << std::setw(2) << std::setfill('0') << (int)c << " ";
    }
    return hexStream.str();
}

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
        logMessage("ERROR", "Error creating socket during port check");
        return false;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    // Try to bind the socket to the given port
    int result = bind(sockfd, (struct sockaddr*)&addr, sizeof(addr));
    close(sockfd);  // Close the socket after checking

    // Return true if bind was successful, meaning the port is available
    return result == 0;
}

int findFreePort(int startPort) {
    int port = startPort;
    
    while (!isPortAvailable(port)) {
        logMessage("WARNING", "Port " + std::to_string(port) + " is not available. Trying next port...");
        port++;  // Increment port number if not available
    }

    return port;  // Return the first available port
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
int tryToConnect(ServerInfo server, bool isInitialConnection) {
    // Check if the number of connections is within the allowed range
    if (!canEstablishConnection(isInitialConnection)) {
        return -1;  // Exit early if connection conditions are not met
    }

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

    sleep(1); // Delay to ensure the port is fully registered

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

    // Add the server to the connectedServers list after a successful connection
    server.sockfd = sock;  // Update the socket descriptor
    connectedServers[server.groupID] = server;  // Map from groupID to ServerInfo
    sockfdToGroupID[sock] = server.groupID;     // Map sockfd to groupID

    logMessage("INFO", "Added connected server to list: " + server.groupID);

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

std::string receiveHELOResponseWithRetry(int sockfd, int retries);

// Attempt to connect to one of the instructor servers from the list
int connectToServer() {
    std::vector<int> triedIndexes;

    while (triedIndexes.size() < serverList.size()) {
        ServerInfo server = chooseRandomServer();

        // Make sure we haven't already tried this server
        if (std::find(triedIndexes.begin(), triedIndexes.end(), server.port) == std::end(triedIndexes)) {
            int sockfd = tryToConnect(server, true);
            if (sockfd >= 0) {
                // Add the instructor server to the connectedServers map
                server.sockfd = sockfd;  // Store the socket file descriptor
                connectedServers[server.groupID] = server;  // Map from groupID to ServerInfo
                sockfdToGroupID[sockfd] = server.groupID;   // Map sockfd to groupID

                // Send HELO command
                sendHELOCommand(sockfd);

                // Receive SERVERS response and update server list
                receiveHELOResponseWithRetry(sockfd, 3);

                std::cout << "Added instructor server to connected servers: " << server.ipAddress << ":" << std::to_string(server.port) << std::endl;
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

// Send the "HELO,A5_x" command to a random server
void sendHELOCommand(int sockfd) {
    std::string heloCommand = "HELO," + currentServerName;  // Send the current server's group ID
    std::string framedCommand = frameMessage(heloCommand);

    // Log local port info for verification
    struct sockaddr_in localAddr;
    socklen_t addrLen = sizeof(localAddr);
    if (getsockname(sockfd, (struct sockaddr*)&localAddr, &addrLen) == -1) {
        logMessage("ERROR", "Failed to get local socket info before sending HELO command.");
    } else {
        logMessage("INFO", "Local port before sending HELO: " + std::to_string(ntohs(localAddr.sin_port)));
    }
    ssize_t result = send(sockfd, framedCommand.c_str(), framedCommand.length(), 0);
    if (result >= 0) {
        logMessage("INFO", "Sent HELO command: " + heloCommand + " on socket " + std::to_string(sockfd));
    } else {
        logMessage("ERROR", "Failed to send HELO command on socket " + std::to_string(sockfd));
    }
}

ssize_t recvWithLogging(int sockfd, char *buffer, size_t bufferSize);
std::vector<std::string> splitString(const std::string &str, char delimiter);

// Helper function to trim whitespace or extra characters from strings
std::string trim(const std::string &str) {
    if (str.empty()) return "";  // Handle empty strings
    size_t first = str.find_first_not_of(" \n\r\t");
    if (first == std::string::npos) return "";  // All characters are whitespace
    size_t last = str.find_last_not_of(" \n\r\t");
    return str.substr(first, (last - first + 1));
}

// Utility function to validate IP addresses
bool isValidIP(const std::string& ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) != 0;
}

// Helper function to split and handle multiple commands in a received message
std::vector<std::string> extractCommands(const std::string &message) {
    std::vector<std::string> commands;
    size_t pos = 0, found;
    while((found = message.find("SERVERS,", pos)) != std::string::npos) {
        // Extracting the part before SERVERS and handling it separately
        if (found > pos) {
            commands.push_back(message.substr(pos, found - pos));
        }
        pos = found;
        found = message.find(EOT, pos);  // Look for the EOT character to finish this command
        if (found != std::string::npos) {
            commands.push_back(message.substr(pos, found - pos + 1));  // Include EOT
            pos = found + 1;
        } else {
            break;  // No more complete commands found
        }
    }
    if (pos < message.size()) {
        commands.push_back(message.substr(pos));  // Push remaining part if any
    }
    return commands;
}

// Helper function to split and extract multiple commands based on SOH and EOT
std::vector<std::string> extractFramedCommands(const std::string &message) {
    std::vector<std::string> commands;
    size_t start = 0;

    while (start < message.size()) {
        // Find the SOH (0x01) and EOT (0x04) positions
        size_t sohPos = message.find(SOH, start);
        size_t eotPos = message.find(EOT, sohPos);

        if (sohPos != std::string::npos && eotPos != std::string::npos) {
            // Extract the message between SOH and EOT
            std::string framedMessage = message.substr(sohPos + 1, eotPos - sohPos - 1);
            commands.push_back(framedMessage);
            start = eotPos + 1;  // Move to the next possible framed message
        } else {
            break;  // No more SOH/EOT pairs found
        }
    }

    return commands;
}

// Helper function to process unframed messages (e.g., "HELO,Instr_1" or "SERVERS,...")
void processUnframedCommand(int clientSocket, const std::string &unframedCommand) {
    if (unframedCommand.find("HELO") == 0) {
        // Handle HELO command
        logMessage("INFO", "HELO command received: " + unframedCommand);
        // Process the HELO message here (for example, save the group name)
    } 
    else if (unframedCommand.find("SERVERS") == 0) {
        logMessage("INFO", "SERVERS command received: " + unframedCommand);
        processServersResponse(unframedCommand);  // Process the received servers list
        sendServersList(clientSocket);  // Send the current server list to the client
        return;  // Exit after handling the SERVERS command
    } 
    else {
        logMessage("ERROR", "Unknown or invalid command received: " + unframedCommand);
    }
}

void handleClientCommand(int clientSocket, const std::string &command, const std::string &clientIP, fd_set &openSockets);
void processStatusResponse(const std::string& statusResp);

// Main function to process received message on a socket
void processReceivedMessage(int sockfd, const std::string &message) {
    // Get client IP for further command handling
    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(struct sockaddr_in);
    getpeername(sockfd, (struct sockaddr *)&addr, &addr_size);
    char clientIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(addr.sin_addr), clientIP, INET_ADDRSTRLEN);

    // Check if the message starts with SOH and ends with EOT
    if (message.front() == SOH && message.back() == EOT) {
        // Extract framed commands and unframe each one
        std::vector<std::string> framedCommands = extractFramedCommands(message);
        for (const auto &framedCommand : framedCommands) {
            std::string unframedCommand = unframeMessage(framedCommand);

            // Process the unframed command
            handleClientCommand(sockfd, unframedCommand, clientIP, openSockets);
        }
    } else {
        // The message is not framed, process it as it is
        handleClientCommand(sockfd, message, clientIP, openSockets);
    }

    // Process MESSAGES command and store them locally
    if (message.rfind("MESSAGES,", 0) == 0) {
        logMessage("INFO", "Processing MESSAGES response: " + message);

        // Parse the MESSAGES response (format: MESSAGES,<groupID>,<msg1>,<msg2>,...)
        std::vector<std::string> tokens = splitString(message, ',');
        if (tokens.size() >= 3) {
            std::string groupID = tokens[1];
            std::string messageContent;

            // Rebuild the message content from the remaining tokens
            for (size_t i = 2; i < tokens.size(); ++i) {
                messageContent += tokens[i];
                if (i != tokens.size() - 1) {
                    messageContent += " ";  // Add space between words
                }
            }

            // Store the messages locally for the group
            storedMessages[groupID].push_back(messageContent);
            logMessage("INFO", "Stored new message for GroupID: " + groupID);
        } else {
            logMessage("ERROR", "Invalid MESSAGES response format: " + message);
        }
    }
}

// Adjusting the receiving function to handle the case where multiple commands are sent together
std::string receiveHELOResponseWithRetry(int sockfd, int retries = 3) {
    char buffer[MAX_BUFFER];
    memset(buffer, 0, MAX_BUFFER);
    int attempts = 0;
    bool success = false;

    while (attempts < retries && !success) {
        fd_set readfds;
        struct timeval timeout;

        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);

        timeout.tv_sec = TIMEOUT_SEC;
        timeout.tv_usec = 0;

        int activity = select(sockfd + 1, &readfds, NULL, NULL, &timeout);
        if (activity > 0 && FD_ISSET(sockfd, &readfds)) {
            int bytesReceived = recvWithLogging(sockfd, buffer, MAX_BUFFER);
            if (bytesReceived > 0) {
                std::string response(buffer, bytesReceived);
                logMessage("INFO", "Received framed response: " + response + " on socket " + std::to_string(sockfd));

                // Process the received message to handle multiple commands
                processReceivedMessage(sockfd, response);

                // Check if the response contains a SERVERS command
                if (response.find("SERVERS") != std::string::npos) {
                    logMessage("INFO", "Successfully received SERVERS response. Stopping retries.");
                    success = true;  // Mark success to exit retry loop
                } else {
                    logMessage("WARNING", "No valid SERVERS response in this attempt. Retrying...");
                }
            } else {
                logMessage("ERROR", "No data received in response.");
            }
        } else if (activity == 0) {
            logMessage("WARNING", "No response from server after HELO or SERVERS, retrying...");
        } else {
            logMessage("ERROR", "Error in select() during response waiting.");
        }

        attempts++;
        if (attempts < retries && !success) {
            logMessage("INFO", "Retrying to get SERVERS response. Attempt " + std::to_string(attempts + 1) + " of " + std::to_string(retries));
            sendHELOCommand(sockfd);  // Resend HELO command to request SERVERS response again
        } else if (!success) {
            logMessage("ERROR", "Max retries reached. Failed to get valid SERVERS response.");
        }
    }
    
    return success ? "SERVERS" : "";  // Return success if SERVERS was received
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
                logMessage("INFO", "Processing MESSAGES response: " + unframedMessage);

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
                std::string groupID = sockfdToGroupID[sockfd];  // Get the groupID from sockfd
                connectedServers[groupID].lastKeepAlive = time(0);  // Update lastKeepAlive using groupID
            } else if (unframedMessage.rfind("STATUSRESP", 0) == 0) {
                logMessage("INFO", "Received STATUSRESP message from server.");
                processStatusResponse(unframedMessage);
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
        logMessage("DEBUG", "Hex dump of sent message: " + stringToHex(message));
    }
    return bytesSent;
}

// Logging enhanced receive function
ssize_t recvWithLogging(int sockfd, char *buffer, size_t bufferSize) {
    ssize_t bytesReceived = recv(sockfd, buffer, bufferSize, 0);
    if (bytesReceived < 0) {
        logMessage("ERROR", "Failed to receive message on socket " + std::to_string(sockfd));
    } else {
        // Log raw data in both hex and string form
        std::string receivedMsg(buffer, bytesReceived);
        std::stringstream hexDump;
        hexDump << "Hex dump of raw data on socket " + std::to_string(sockfd) + ": ";
        for (int i = 0; i < bytesReceived; ++i) {
            hexDump << std::hex << std::setw(2) << std::setfill('0') << (int)(unsigned char)buffer[i] << " ";
        }
        logMessage("INFO", "Bytes received on socket " + std::to_string(sockfd) + ": " + std::to_string(bytesReceived));
        logMessage("DEBUG", "Hex dump of received message: " + stringToHex(receivedMsg));
    }
    return bytesReceived;
}

// Update the populateServerList to fetch server names using ping
void populateServerList(const std::string &ipAddress, int portStart, int portEnd) {
    serverList.clear();
    int groupNumber = 1;
    for (int port = portStart; port <= portEnd; ++port) {
        ServerInfo newServer = {"Random_" + std::to_string(groupNumber), ipAddress, port, -1, time(0)};
        int sockfd = tryToConnect(newServer, true);
        if (sockfd >= 0) {
            sendHELOCommand(sockfd);
            std::string responseName = receiveHELOResponseWithRetry(sockfd, 3);

            if (!responseName.empty()) {
                newServer.groupID = responseName;
            } else {
                responseName = "server_" + std::to_string(port);
                logMessage("WARNING", "Fallback to default server name: " + responseName);
                newServer.groupID = responseName;
            }

            newServer.sockfd = sockfd;
            connectedServers[newServer.groupID] = newServer;  // Map from groupID to ServerInfo
            sockfdToGroupID[sockfd] = newServer.groupID;      // Map sockfd to groupID
            serverList.push_back(newServer);  // Add to serverList
            logMessage("INFO", "Populated server and added to connectedServers: " + newServer.groupID);
        } else {
            logMessage("ERROR", "Failed to connect to server " + ipAddress + " on port " + std::to_string(port));
        }

        ++groupNumber;
    }
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

// Helper function to frame messages with SOH and EOT with byte stuffing (ESCAPE handling)
std::string frameMessage(const std::string &msg) {
    std::string framedMsg;
    framedMsg += SOH;  // Start with SOH
    
    // Byte stuffing for SOH and EOT only
    for (char c : msg) {
        if (c == SOH || c == EOT) {
            framedMsg += ESCAPE;  // Insert ESCAPE before SOH or EOT
        }
        framedMsg += c;  // Append the actual character
    }
    
    framedMsg += EOT;  // End with EOT
    return framedMsg;
}

// Helper function to unframe messages (remove SOH and EOT) and handle byte unstuffing
std::string unframeMessage(const std::string &msg) {
    // Check if the message starts with SOH and ends with EOT
    if (msg.empty() || msg.front() != SOH || msg.back() != EOT) {
        logMessage("ERROR", "Invalid framing in message: [" + msg + "]");
        return msg;  // Return the original message since it's already unframed
    }

    std::string data = msg.substr(1, msg.size() - 2);  // Remove SOH and EOT
    std::string unframedMsg;
    bool escapeNext = false;

    for (char c : data) {
        if (escapeNext) {
            unframedMsg += c;  // Append escaped character
            escapeNext = false;
        } else if (c == ESCAPE) {
            escapeNext = true;  // Flag the next character to be escaped
        } else {
            unframedMsg += c;  // Normal character
        }
    }

    if (escapeNext) {
        logMessage("ERROR", "Incomplete escape sequence in message: " + msg);
        return "";
    }
    return unframedMsg;
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

    // Ensure current server's IP and port are advertised correctly
    response << "," << currentServerName << "," << currentServerIP << "," << std::to_string(port);

    std::set<std::string> uniqueServers;  // A set to track unique servers

    // Add the current server to the uniqueServers set
    uniqueServers.insert(currentServerName + "," + currentServerIP + "," + std::to_string(port));

    // Debug: Print the current connectedServers list
    logMessage("DEBUG", "Connected servers list before adding new entries:");
    for (const auto& connectedServer : connectedServers) {
        const ServerInfo& serverInfo = connectedServer.second; // Access the ServerInfo from the map
        std::string serverDetails = serverInfo.groupID + "," + serverInfo.ipAddress + "," + std::to_string(serverInfo.port);
        logMessage("DEBUG", serverDetails);

        if (uniqueServers.find(serverDetails) == uniqueServers.end()) {
            uniqueServers.insert(serverDetails);
            response << ";" << serverDetails;
        }
    }

    // Debug: Print the current serverList before modifying it
    logMessage("DEBUG", "ServerList before adding to SERVERS list:");
    for (const auto& server : serverList) {
        std::string serverDetails = server.groupID + "," + server.ipAddress + "," + std::to_string(server.port);
        logMessage("DEBUG", serverDetails);

        if (uniqueServers.find(serverDetails) == uniqueServers.end()) {
            uniqueServers.insert(serverDetails);
            response << ";" << serverDetails;
        }
    }

    // Frame the message with SOH and EOT
    std::string framedResponse = frameMessage(response.str());

    // Send the framed response to the socket
    ssize_t result = send(sockfd, framedResponse.c_str(), framedResponse.length(), 0);
    if (result >= 0) {
        logMessage("INFO", "Successfully sent SERVERS list to socket: " + std::to_string(sockfd) + " - " + framedResponse);
    } else {
        logMessage("ERROR", "Failed to send SERVERS list to socket: " + std::to_string(sockfd) + " - Error: " + strerror(errno));
    }
}

std::mutex serverMutex;  // Add a mutex for server-related operations

void monitorKeepAlive() {
    std::lock_guard<std::mutex> lock(serverMutex);  // Lock before accessing shared containers
    time_t currentTime = time(0);

    for (auto it = connectedServers.begin(); it != connectedServers.end(); ) {
        double timeSinceLastKeepAlive = difftime(currentTime, it->second.lastKeepAlive);
        if (timeSinceLastKeepAlive > 120) {
            close(it->second.sockfd);
            FD_CLR(it->second.sockfd, &openSockets);
            it = connectedServers.erase(it);  // Safely remove
        } else {
            ++it;
        }
    }
}

// Send periodic keep-alive messages to all servers in serverList
void sendKeepAliveMessages() {
    std::lock_guard<std::mutex> lock(serverMutex);  // Ensure thread-safe access

    time_t currentTime = time(0);

    for (auto it = connectedServers.begin(); it != connectedServers.end(); ) {
        ServerInfo& server = it->second;

        // Only proceed if enough time has passed since the last KEEPALIVE
        if (difftime(currentTime, server.lastKeepAlive) >= 60) {
            // Count the number of messages waiting for this server
            int numMessages = 0;
            if (storedMessages.find(server.groupID) != storedMessages.end()) {
                numMessages = storedMessages[server.groupID].size();
            }

            // Prepare the KEEPALIVE message
            std::string keepAliveMsg = frameMessage("KEEPALIVE," + std::to_string(numMessages));

            // Try to send the KEEPALIVE message
            ssize_t result = send(server.sockfd, keepAliveMsg.c_str(), keepAliveMsg.length(), 0);

            if (result < 0) {
                // Handle connection errors
                if (errno == EPIPE || errno == EBADF || errno == ECONNRESET) {
                    logMessage("WARNING", "Failed to send KEEPALIVE to " + server.ipAddress + ":" + std::to_string(server.port) + ". Error: " + strerror(errno));

                    // Close the socket
                    close(server.sockfd);

                    // Remove the server from FD_SET and connectedServers
                    FD_CLR(server.sockfd, &openSockets);
                    it = connectedServers.erase(it);  // Safely erase and update iterator
                    continue;  // Skip to the next iteration
                } else {
                    logMessage("ERROR", "Unexpected error sending KEEPALIVE to " + server.ipAddress + ":" + std::to_string(server.port) + ". Error: " + strerror(errno));
                }
            } else {
                // Update lastKeepAlive on successful send
                server.lastKeepAlive = currentTime;
                logMessage("INFO", "Sent KEEPALIVE to server " + server.groupID + " with " + std::to_string(numMessages) + " messages.");
            }
        }

        ++it;  // Move to the next element only if no removal occurred
    }
}

void resetBlocklist() {
    blocklist.clear();
    logMessage("INFO", "Blocklist has been cleared.");
}

// Process the SERVERS response
void processServersResponse(const std::string &response) {
    std::vector<std::string> serverEntries = splitString(response, ';');  // Split the response into individual server entries

    logMessage("INFO", "Processing SERVERS response. Current connected servers: " + std::to_string(connectedServers.size()));

    bool firstServerHandled = false;  // To ensure we handle the first server separately

    for (const auto &entry : serverEntries) {
        // Parse each server entry (format: groupID, IP, port)
        std::vector<std::string> tokens = splitString(entry, ',');
        if (tokens.size() == 3) {
            std::string groupID = tokens[0];
            std::string ipAddress = tokens[1];
            int port = std::stoi(tokens[2]);

            if (groupID == currentServerName) {
                // Skip ourselves
                continue;
            }

            if (connectedServers.find(groupID) != connectedServers.end()) {
                logMessage("INFO", "Server already connected: " + groupID);
            } else {
                ServerInfo newServer = {groupID, ipAddress, port, -1, time(0)};
                int sockfd = tryToConnect(newServer, true);
                if (sockfd >= 0) {
                    newServer.sockfd = sockfd;
                    connectedServers[groupID] = newServer;
                    sockfdToGroupID[sockfd] = groupID;
                    serverList.push_back(newServer);
                    logMessage("INFO", "Added new server: " + groupID);
                } else {
                    logMessage("ERROR", "Failed to connect to server " + groupID + " at " + ipAddress + ":" + std::to_string(port));
                }
            }
        } else {
            logMessage("ERROR", "Malformed server entry: " + entry);
        }
    }

    // Ensure we maintain at least 3 connected servers
    if (connectedServers.size() < 3) {
        logMessage("WARNING", "Fewer than 3 connected servers. Current count: " + std::to_string(connectedServers.size()));
    }

    logMessage("INFO", "Finished processing SERVERS response. Total connected servers: " + std::to_string(connectedServers.size()));
}

void requestStatusFromServers() {
    for (const auto& entry : connectedServers) {
        const ServerInfo& server = entry.second;
        logMessage("INFO", "Sending STATUSREQ to " + server.groupID);

        // Ensure the server is connected (i.e., has a valid socket descriptor)
        if (server.sockfd > 0) {
            // Send STATUSREQ command to the server
            std::string statusReqCommand = frameMessage("STATUSREQ");
            ssize_t result = send(server.sockfd, statusReqCommand.c_str(), statusReqCommand.length(), 0);

            if (result >= 0) {
                logMessage("INFO", "Sent STATUSREQ to " + server.groupID);

                // Wait for the response
                char buffer[MAX_BUFFER];
                ssize_t bytesReceived = recvWithLogging(server.sockfd, buffer, MAX_BUFFER);
                if (bytesReceived > 0) {
                    std::string receivedMsg(buffer, bytesReceived);
                    std::string unframedMessage = unframeMessage(receivedMsg);
                    logMessage("INFO", "Received STATUSRESP from " + server.groupID + ": " + unframedMessage);

                    // Process STATUSRESP
                    processStatusResponse(unframedMessage);
                } else {
                    logMessage("ERROR", "No response received from " + server.groupID);
                }
            } else {
                logMessage("ERROR", "Failed to send STATUSREQ to " + server.groupID);
            }
        } else {
            logMessage("ERROR", "Invalid socket for server " + server.groupID + ". Skipping STATUSREQ.");
        }
    }
}

// Helper function to check if the groupID belongs to a server in our server list
bool isServerInOurList(const std::string& groupID) {
    return connectedServers.find(groupID) != connectedServers.end();
}

// Function to receive MESSAGES response with retries
bool receiveMessagesWithRetry(int sockfd, const std::string& groupID, int retries = 3) {
    char buffer[MAX_BUFFER];
    int attempts = 0;
    bool success = false;

    while (attempts < retries && !success) {
        fd_set readfds;
        struct timeval timeout;

        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);

        // 5-second timeout for each retry
        timeout.tv_sec = TIMEOUT_SEC;
        timeout.tv_usec = 0;

        logMessage("INFO", "Waiting for MESSAGES response for GroupID: " + groupID + ", Attempt " + std::to_string(attempts + 1));

        int activity = select(sockfd + 1, &readfds, NULL, NULL, &timeout);
        if (activity > 0 && FD_ISSET(sockfd, &readfds)) {
            int bytesReceived = recvWithLogging(sockfd, buffer, MAX_BUFFER);
            if (bytesReceived > 0) {
                std::string response(buffer, bytesReceived);
                std::string unframedResponse = unframeMessage(response);

                // Check if the response is MESSAGES
                if (unframedResponse.rfind("MESSAGES,", 0) == 0) {
                    logMessage("INFO", "Received MESSAGES response: " + unframedResponse);
                    success = true;  // Mark success if we receive the correct response
                } else {
                    logMessage("WARNING", "Unexpected response received: " + unframedResponse);
                }
            } else {
                logMessage("ERROR", "Failed to receive response from server.");
            }
        } else if (activity == 0) {
            logMessage("WARNING", "Timeout waiting for MESSAGES response, retrying...");
        } else {
            logMessage("ERROR", "Error during select() waiting for MESSAGES response.");
        }

        attempts++;
    }

    if (!success) {
        logMessage("ERROR", "Failed to receive MESSAGES response after " + std::to_string(retries) + " attempts.");
    }

    return success;
}

// Function to send GETMSGS command with retries
bool sendGETMSGSWithRetry(ServerInfo &server, int maxRetries = 5) {
    for (int attempt = 1; attempt <= maxRetries; ++attempt) {
        logMessage("INFO", "Attempting to send GETMSGS to server: " + server.groupID + " (" + server.ipAddress + ":" + std::to_string(server.port) + "), attempt " + std::to_string(attempt));

        if (server.sockfd < 0) {
            logMessage("ERROR", "Invalid socket for GroupID: " + server.groupID + ". Attempting to reconnect.");

            int newSockfd = tryToConnect(server, true);
            if (newSockfd >= 0) {
                server.sockfd = newSockfd;  // Update with the new socket descriptor
                sockfdToGroupID[newSockfd] = server.groupID;  // Update mapping
                connectedServers[server.groupID] = server;    // Update connectedServers
                logMessage("INFO", "Reconnected to server " + server.groupID + " (" + server.ipAddress + ":" + std::to_string(server.port) + ")");
            } else {
                logMessage("ERROR", "Reconnection to server " + server.groupID + " failed.");
                return false;
            }
        }

        // Skip sending GETMSGS to the current server (self-check)
        if (server.groupID == currentServerName) {
            logMessage("INFO", "Skipping GETMSGS to self (GroupID: " + currentServerName + ")");
            return false;
        }

        std::string getMsgsCommand = frameMessage("GETMSGS," + server.groupID);
        ssize_t result = send(server.sockfd, getMsgsCommand.c_str(), getMsgsCommand.length(), 0);

        if (result < 0) {
            logMessage("ERROR", "Failed to send GETMSGS to server: " + server.groupID + " (" + server.ipAddress + ":" + std::to_string(server.port) + "), Error: " + strerror(errno));

            if (errno == EBADF) {
                close(server.sockfd);
                connectedServers[server.groupID].sockfd = -1;
                sockfdToGroupID.erase(server.sockfd);
                continue;
            }
        } else {
            logMessage("INFO", "GETMSGS sent successfully to server: " + server.groupID + " (" + server.ipAddress + ":" + std::to_string(server.port) + ")");
            return true;
        }
    }

    logMessage("ERROR", "Could not send GETMSGS to server: " + server.groupID);
    return false;
}

std::vector<std::string> messageRequestQueue;  // Global or class-level list to hold message requests

// Function to check if a GroupID is already in the queue
bool isInQueue(const std::string& groupID) {
    return std::find(messageRequestQueue.begin(), messageRequestQueue.end(), groupID) != messageRequestQueue.end();
}

void processStatusResponse(const std::string& statusResp) {
    logMessage("DEBUG", "Entering processStatusResponse with message: " + statusResp);

    std::vector<std::string> responses = splitString(statusResp, 'K');
    for (const auto& response : responses) {
        if (response.rfind("STATUSRESP", 0) == 0) {
            std::vector<std::string> tokens = splitString(response, ',');

            if (tokens.size() < 3 || tokens[0] != "STATUSRESP") {
                logMessage("ERROR", "Invalid STATUSRESP format: " + response);
                continue;
            }

            for (size_t i = 1; i < tokens.size(); i += 2) {
                std::string groupID = tokens[i];
                int msgCount;

                try {
                    msgCount = std::stoi(tokens[i + 1]);
                } catch (const std::exception& e) {
                    logMessage("ERROR", "Invalid message count in STATUSRESP: " + tokens[i + 1]);
                    continue;
                }

                if (msgCount > 0 && !isInQueue(groupID)) {  // Check to avoid adding duplicates
                    if (groupID == currentServerName || isServerInOurList(groupID)) {
                        logMessage("INFO", "Adding " + std::to_string(msgCount) + " messages to request queue for GroupID: " + groupID);
                        messageRequestQueue.push_back(groupID);  // Add to the queue
                    } else {
                        logMessage("INFO", "Ignoring messages for unknown server (GroupID: " + groupID + ")");
                    }
                }
            }
        }
    }

    logMessage("DEBUG", "Exiting processStatusResponse.");
}

void processMessageRequestQueue() {
    while (!messageRequestQueue.empty()) {
        std::string groupID = messageRequestQueue.front();
        messageRequestQueue.erase(messageRequestQueue.begin());

        logMessage("INFO", "Processing GETMSGS for GroupID: " + groupID);

        // Skip sending to the current server itself
        if (groupID == currentServerName) {
            logMessage("INFO", "Skipping GETMSGS for self (GroupID: " + currentServerName + ")");
            continue;
        }

        auto serverIter = connectedServers.find(groupID);
        if (serverIter != connectedServers.end()) {
            ServerInfo& server = connectedServers[groupID];
            bool sentSuccessfully = sendGETMSGSWithRetry(server);
            if (!sentSuccessfully) {
                logMessage("ERROR", "Failed to process GETMSGS for GroupID: " + groupID);
            }
        } else {
            logMessage("ERROR", "Server not found in connectedServers for GroupID: " + groupID);
        }
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

    // Handle blacklisting: check if the server is blacklisted
    if (isBlacklisted(clientIP)) {
        logMessage("INFO", "Blacklisted IP attempted to connect: " + clientIP);
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

    // If command is invalid, increase failure count and block if threshold is reached
    if (cmd != "HELO" && cmd != "SERVERS" && cmd != "SENDMSG" && cmd != "GETMSGS" && cmd != "STATUSREQ" && cmd != "KEEPALIVE") {
        logMessage("ERROR", "Unknown command: " + cmd);

        // Increment failure count for the client
        failedCommandCount[clientIP]++;
        if (failedCommandCount[clientIP] > 3) {  // Block after 3 failed commands
            blockIP(clientIP);  // Block the IP
            logMessage("WARNING", "Blocked IP due to too many invalid commands: " + clientIP);
            std::string blockMsg = "ERROR: Too many invalid commands, you are blocked.";
            send(clientSocket, frameMessage(blockMsg).c_str(), frameMessage(blockMsg).length(), 0);
            close(clientSocket);
            FD_CLR(clientSocket, &openSockets);
            return;
        }

        // Send an error message back to the client
        std::string errorMsg = "ERROR: Unknown command " + cmd;
        std::string framedError = frameMessage(errorMsg);
        send(clientSocket, framedError.c_str(), framedError.length(), 0);
        return;
    }

    if (cmd.compare("HELO") == 0) {
        // Enhanced HELO handling
        std::string groupID;
        
        // Extract group ID or assign a fallback if missing
        if (tokens.size() >= 2) {
            groupID = trim(tokens[1]);
        } else {
            groupID = "A5_Unknown";  // Default groupID if none is provided
            logMessage("WARNING", "Received HELO without group ID, assigning: " + groupID);
        }
        // Send SERVERS response to the client
        sendServersList(clientSocket);
        
        if (groupID == currentServerName) {
            logMessage("INFO", "Received HELO from ourselves. Ignoring.");
            return;
        }

        auto it = connectedServers.find(groupID);
        if (it != connectedServers.end()) {
            logMessage("INFO", "Server already connected: " + groupID);
            it->second.sockfd = clientSocket;
            it->second.lastKeepAlive = time(0);
            sockfdToGroupID[clientSocket] = groupID;
        } else {
            if (connectedServers.size() >= 8) {
                logMessage("INFO", "Connected servers limit reached, cannot add new server: " + groupID);
                return;
            }

            ServerInfo newServer = {groupID, clientIP, port, clientSocket, time(0)};
            connectedServers[groupID] = newServer;
            sockfdToGroupID[clientSocket] = groupID;
            logMessage("INFO", "Added new server to connectedServers: " + groupID);
        }

    } else if (cmd.compare("SERVERS") == 0) {
        logMessage("INFO", "SERVERS command received in handleclientcommands: " + trimmedCommand);
        sendServersList(clientSocket);  // This function sends the current server list to the client
        return;  // Exit to avoid executing further commands    

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

        // Store the message locally for the destination GroupID
        storedMessages[toGroupID].push_back("From " + fromGroupID + ": " + messageContent);
        logMessage("INFO", "Message stored locally for GroupID: " + toGroupID);

    } else if (cmd.compare("GETMSGS") == 0 && tokens.size() == 2) {
        std::string groupID = trim(tokens[1]);

        // Debugging: Print out all currently stored messages before processing
        logMessage("DEBUG", "Current stored messages before processing GETMSGS:");
        for (const auto& entry : storedMessages) {
            logMessage("DEBUG", "GroupID: " + entry.first + ", Messages: " + std::to_string(entry.second.size()));
            for (const auto& msg : entry.second) {
                logMessage("DEBUG", "Message: " + msg);
            }
        }

        logMessage("INFO", "Processing GETMSGS for GroupID: " + groupID);

        // Send the locally stored messages if they exist
        if (storedMessages.find(groupID) != storedMessages.end() && !storedMessages[groupID].empty()) {
            logMessage("INFO", "Found " + std::to_string(storedMessages[groupID].size()) + " messages for GroupID: " + groupID);

            // Construct the MESSAGES response
            std::string response = "MESSAGES," + groupID;
            for (const auto& message : storedMessages[groupID]) {
                response += "," + message;
            }

            // Frame and send the response
            std::string framedResponse = frameMessage(response);
            send(clientSocket, framedResponse.c_str(), framedResponse.length(), 0);
            logMessage("INFO", "Sent and cleared local messages for GroupID: " + groupID);

            // Clear the messages after sending
            storedMessages[groupID].clear();
        } else {
            logMessage("INFO", "No local messages for GroupID: " + groupID);
            // Send response indicating no messages available
            std::string noMessageResponse = frameMessage("MESSAGES," + groupID + ",NO_MESSAGES");
            send(clientSocket, noMessageResponse.c_str(), noMessageResponse.length(), 0);
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
        if (clientNames.find(clientSocket) == clientNames.end()) {
            logMessage("ERROR", "No clientGroupID found for socket: " + std::to_string(clientSocket));
            return;
        }

        std::string clientGroupID = clientNames[clientSocket];
        logMessage("INFO", "KEEPALIVE received from " + clientIP + ":" + std::to_string(port) +
                " with message count: " + std::to_string(storedMessages[clientGroupID].size()));

        // Log the last keep-alive timestamp
        std::string groupID = sockfdToGroupID[clientSocket];
        connectedServers[groupID].lastKeepAlive = time(0);  // Update the timestamp
        logMessage("INFO", "Updated last KEEPALIVE timestamp for client " + clientGroupID);
    } else if (cmd.compare("MESSAGES") == 0 && tokens.size() >= 3) {
        std::string fromGroupID = tokens[1];
        
        // Rebuild the message content
        std::string messageContent;
        for (size_t i = 2; i < tokens.size(); ++i) {
            messageContent += tokens[i];
            if (i != tokens.size() - 1) {
                messageContent += " ";  // Add space between words
            }
        }

        // Store the message locally for this group
        storedMessages[fromGroupID].push_back(messageContent);
        logMessage("INFO", "Stored new message for GroupID: " + fromGroupID);
    } else {
        logMessage("ERROR", "Unknown command: " + cmd);

        // Send an error message back to the client
        std::string errorMsg = "ERROR: Unknown command " + cmd;
        std::string framedError = frameMessage(errorMsg);
        send(clientSocket, framedError.c_str(), framedError.length(), 0);
    }
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

            // Periodically remove expired blocks
            removeExpiredBlocks();

            processMessageRequestQueue();  // Process the message queue in each loop

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

                    // Remove from sockfdToGroupID and connectedServers if necessary
                    auto it = sockfdToGroupID.find(i);
                    if (it != sockfdToGroupID.end()) {
                        std::string groupID = it->second;
                        connectedServers.erase(groupID);
                        sockfdToGroupID.erase(it);
                    }
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

// Start periodic keep-alive messages to all connected servers
void startKeepAliveLoop() {
    while (true) {
        sendKeepAliveMessages();  // Send KEEPALIVE to all connected servers
        std::this_thread::sleep_for(std::chrono::seconds(80));  // Send KEEPALIVE every 60 seconds
    }
}

// Start periodic STATUSREQ messages to all connected servers
void startStatusReqLoop() {
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(100));  // Send STATUSREQ every 60 seconds
        requestStatusFromServers();  // Send STATUSREQ to all connected servers
    }
}

int main(int argc, char *argv[]) {
    // Ignore SIGPIPE to prevent crashes when writing to closed sockets
    signal(SIGPIPE, SIG_IGN);

    if (argc != 6) {
        std::cerr << "Usage: ./tsamgroup1 SERVER_NAME SERVER_PORT CONNECTION_SERVER_IP CONNECTION_SERVER_PORT_START CONNECTION_SERVER_PORT_END" << std::endl;
        return EXIT_FAILURE;
    }

    // Assign command-line arguments
    currentServerName = std::string("A5_") + argv[1];  // Pass the group number as part of the server name
    port = atoi(argv[2]);  // Port value from the second argument
    connectedServersIPs = argv[3];
    int connectionServerPortStart = atoi(argv[4]);
    int connectionServerPortEnd = atoi(argv[5]);

    // Check if the requested port is available
    if (!isPortAvailable(port)) {
        logMessage("WARNING", "Port " + std::to_string(port) + " is not available. Trying to find another available port starting from 4000...");
        port = findFreePort(4000);  // Call findFreePort starting at 4000 if requested port is not available
        logMessage("INFO", "Server will use available port: " + std::to_string(port));
    }

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

    // *** Add local server to both connectedServers and serverList ***
    ServerInfo localServer;
    localServer.groupID = currentServerName;
    localServer.ipAddress = currentServerIP;
    localServer.port = port;
    localServer.sockfd = -1; // Since it's the local server, we won't connect to it.

    // Add the local server to both connectedServers and serverList
    connectedServers[currentServerName] = localServer;
    serverList.push_back(localServer); // Add to serverList

    logMessage("INFO", "Local server added to both serverList and connectedServers with GroupID: " + currentServerName + ", IP: " + currentServerIP + ", Port: " + std::to_string(port));

    // Populate the server list based on command-line input (range of ports)
    populateServerList(connectedServersIPs, connectionServerPortStart, connectionServerPortEnd);

    logMessage("INFO", "Server " + currentServerName + " started on port " + std::to_string(port));

    // Start the thread for periodic keep-alive messages
    std::thread keepAliveThread(startKeepAliveLoop);
    keepAliveThread.detach();  // Start the KEEPALIVE thread

    // Start the thread for periodic STATUSREQ messages
    std::thread statusReqThread(startStatusReqLoop);
    statusReqThread.detach();  // Start the STATUSREQ thread

    // Main server loop
    serverLoop(listenSock);

    return 0;
}