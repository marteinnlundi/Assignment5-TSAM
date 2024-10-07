#include <iostream>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define SOH 0x01  
#define EOT 0x04  
#define MAX_BUFFER 5000

std::string frameMessage(const std::string &msg) {
    return std::string(1, SOH) + msg + std::string(1, EOT);
}

std::string unframeMessage(const std::string &msg) {
    if (msg[0] == SOH && msg[msg.size() - 1] == EOT) {
        return msg.substr(1, msg.size() - 2);
    }
    return msg;
}

int connectToServer(const std::string &serverIP, int serverPort) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        std::cerr << "Socket creation failed!" << std::endl;
        return -1;
    }

    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(serverPort);
    inet_pton(AF_INET, serverIP.c_str(), &serverAddr.sin_addr);

    if (connect(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "Connection to server failed!" << std::endl;
        close(sockfd);
        return -1;
    }

    std::cout << "Connected to server!" << std::endl;
    return sockfd;
}

void sendCommand(int sockfd, const std::string &command) {
    std::string framedCommand = frameMessage(command);
    send(sockfd, framedCommand.c_str(), framedCommand.length(), 0);
}

std::string receiveResponse(int sockfd) {
    char buffer[MAX_BUFFER];
    memset(buffer, 0, MAX_BUFFER);
    int bytesReceived = recv(sockfd, buffer, MAX_BUFFER, 0);
    if (bytesReceived <= 0) {
        return "";
    }
    return unframeMessage(std::string(buffer, bytesReceived));
}

void clientLoop(int sockfd) {
    std::string command;
    while (true) {
        std::cout << "Enter command (HELO, SENDMSG, GETMSGS, LISTSERVERS, or QUIT): ";
        std::getline(std::cin, command);

        if (command == "QUIT") {
            break;
        }

        sendCommand(sockfd, command);

        std::string response = receiveResponse(sockfd);
        if (!response.empty()) {
            std::cout << "Response from server: " << response << std::endl;
        }
    }

    close(sockfd);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: ./client <server_ip> <server_port>" << std::endl;
        return EXIT_FAILURE;
    }

    std::string serverIP = argv[1];
    int serverPort = atoi(argv[2]);

    int sockfd = connectToServer(serverIP, serverPort);
    if (sockfd != -1) {
        clientLoop(sockfd);
    }

    return 0;
}
