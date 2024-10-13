// Compile: g++ Client.cpp -o client
// Usage: ./client <server_ip> <server_port>

// The client connects to the server and allows sending commands:
// SENDMSG - Send a message to the server for the specified GROUP ID
// GETMSGS  - Get a single message from the server for the specified GROUP ID
// LISTSERVERS - List servers your server is connected to
// QUIT    - Exit the client

// The client prints out all commands sent and responses received with a timestamp (date and time, no nanoseconds).

#include <iostream>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define SOH 0x01  // Start of Header
#define EOT 0x04  // End of Transmission
#define MAX_BUFFER 5000  // Maximum buffer size for receiving data

// Function to frame a message with SOH and EOT
std::string frameMessage(const std::string &msg) {
    return std::string(1, SOH) + msg + std::string(1, EOT);
}

// Function to unframe a message, removing SOH and EOT
std::string unframeMessage(const std::string &msg) {
    if (msg[0] == SOH && msg[msg.size() - 1] == EOT) {
        return msg.substr(1, msg.size() - 2);  // Remove SOH and EOT
    }
    return msg;
}

// Function to connect to the server
int connectToServer(const std::string &serverIP, int serverPort) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);  // Create socket
    if (sockfd < 0) {
        std::cerr << "Socket creation failed!" << std::endl;
        return -1;
    }

    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));  // Initialize server address structure
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(serverPort);
    inet_pton(AF_INET, serverIP.c_str(), &serverAddr.sin_addr);  // Convert IP address

    if (connect(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "Connection to server failed!" << std::endl;
        close(sockfd);
        return -1;
    }

    std::cout << "Connected to server!" << std::endl;
    return sockfd;
}

// Function to send a framed command to the server
void sendCommand(int sockfd, const std::string &command) {
    std::string framedCommand = frameMessage(command);  // Frame the message
    send(sockfd, framedCommand.c_str(), framedCommand.length(), 0);  // Send it
}

// Function to receive and unframe a response from the server
// Function to receive and unframe a response from the server with a timeout
std::string receiveResponse(int sockfd) {
    char buffer[MAX_BUFFER];
    memset(buffer, 0, MAX_BUFFER);  // Clear the buffer

    // Set a timeout for receiving data
    struct timeval tv;
    tv.tv_sec = 5;  // 5 seconds timeout
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    int bytesReceived = recv(sockfd, buffer, MAX_BUFFER, 0);  // Receive data

    if (bytesReceived < 0) {
        std::cout << "No response from server within the timeout period." << std::endl;
        return "";  // Timeout or error
    } else if (bytesReceived == 0) {
        std::cout << "Server closed the connection." << std::endl;
        return "";  // Server closed the connection
    }
    
    return unframeMessage(std::string(buffer, bytesReceived));  // Unframe the message
}

// Function to prompt and handle the SENDMSG command
void handleSendMsg(int sockfd) {
    std::string groupID, fromGroupID, message;

    // Get the Group ID
    std::cout << "Enter destination Group ID: ";
    std::getline(std::cin, groupID);

    // Get the source Group ID
    std::cout << "Enter your Group ID: ";
    std::getline(std::cin, fromGroupID);

    // Get the message content
    std::cout << "Enter the message: ";
    std::getline(std::cin, message);

    // Construct and send the SENDMSG command
    std::string command = "SENDMSG," + groupID + "," + fromGroupID + "," + message;
    sendCommand(sockfd, command);

    // Receive and display the server's response
    std::string response = receiveResponse(sockfd);
    if (!response.empty()) {
        std::cout << "Response from server: " << response << std::endl;
    }
}

// Function to prompt and handle the GETMSG command
void handleGetMsgs(int sockfd) {
    std::string groupID;

    // Get the Group ID
    std::cout << "Enter Group ID to retrieve messages for: ";
    std::getline(std::cin, groupID);

    // Construct and send the GETMSG command
    std::string command = "GETMSGS," + groupID;
    sendCommand(sockfd, command);

    // Receive and display the server's response
    std::string response = receiveResponse(sockfd);
    if (!response.empty()) {
        std::cout << "Response from server: " << response << std::endl;
    }
}

// Function to handle the modified LISTSERVERS command (which will send HELO,GIMMEEE)
void handleListServers(int sockfd) {
    // Send the modified HELO command instead of LISTSERVERS
    sendCommand(sockfd, "HELO,GIMMEEE");

    // Receive and display the server's response
    std::string response = receiveResponse(sockfd);
    if (!response.empty()) {
        std::cout << "Response from server: " << response << std::endl;
    }
}

// Main client loop to handle commands
void clientLoop(int sockfd) {
    std::string command;

    while (true) {
        // Display available commands
        std::cout << "\nAvailable commands:\n"
                  << "1. SENDMSG (Send a message)\n"
                  << "2. GETMSG (Get a message)\n"
                  << "3. LISTSERVERS (List connected servers)\n"
                  << "4. QUIT (Exit the program)\n"
                  << "Enter the number corresponding to your choice: ";
        std::getline(std::cin, command);

        // Handle each command based on user input
        if (command == "1") {
            handleSendMsg(sockfd);
        } else if (command == "2") {
            handleGetMsgs(sockfd);
        } else if (command == "3") {
            handleListServers(sockfd);  // Send HELO,GIMMEEE instead of LISTSERVERS
        } else if (command == "4" || command == "QUIT") {
            break;
        } else {
            std::cout << "Invalid command. Please try again." << std::endl;
        }
    }

    close(sockfd);  // Close the socket after quitting
}

// Main function to connect to the server and start the client loop
int main(int argc, char *argv[]) {
    // Check for correct number of command-line arguments
    if (argc != 3) {
        std::cerr << "Usage: ./client <server_ip> <server_port>" << std::endl;
        return EXIT_FAILURE;
    }

    std::string serverIP = argv[1];
    int serverPort = atoi(argv[2]);

    // Connect to the server
    int sockfd = connectToServer(serverIP, serverPort);
    if (sockfd != -1) {
        clientLoop(sockfd);  // Start the client loop
    }

    return 0;
}
