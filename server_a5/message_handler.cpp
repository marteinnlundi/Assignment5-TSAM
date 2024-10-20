#include "message_handler.h"
#include "logging.h"
#include <iostream>
#include <sys/socket.h>
#include <cstring>

std::string frameMessage(const std::string &msg) {
    std::string framedMsg = "\x01" + msg + "\x04";
    return framedMsg;
}

std::string unframeMessage(const std::string &msg) {
    if (msg.front() != '\x01' || msg.back() != '\x04') {
        return msg;
    }
    return msg.substr(1, msg.size() - 2);
}

std::vector<std::string> extractFramedCommands(const std::string &message) {
    std::vector<std::string> commands;
    size_t start = 0;

    while (start < message.size()) {
        size_t sohPos = message.find('\x01', start);
        size_t eotPos = message.find('\x04', sohPos);

        if (sohPos != std::string::npos && eotPos != std::string::npos) {
            std::string framedMessage = message.substr(sohPos + 1, eotPos - sohPos - 1);
            commands.push_back(framedMessage);
            start = eotPos + 1;
        } else {
            break;
        }
    }
    return commands;
}

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

void processReceivedMessage(int sockfd, const std::string &message) {
    std::string unframedMessage = unframeMessage(message);
    logMessage("INFO", "Processing message: " + unframedMessage);

    std::vector<std::string> commands = extractCommands(unframedMessage);
    for (const auto &cmd : commands) {
        logMessage("DEBUG", "Command: " + cmd);
    }
}

ssize_t sendWithLogging(int sockfd, const std::string &message) {
    ssize_t bytesSent = send(sockfd, message.c_str(), message.size(), 0);
    if (bytesSent >= 0) {
        logMessage("INFO", "Sent message: " + message);
    }
    return bytesSent;
}

ssize_t recvWithLogging(int sockfd, char *buffer, size_t bufferSize) {
    ssize_t bytesReceived = recv(sockfd, buffer, bufferSize, 0);
    if (bytesReceived >= 0) {
        logMessage("INFO", "Received message: " + std::string(buffer, bytesReceived));
    }
    return bytesReceived;
}
