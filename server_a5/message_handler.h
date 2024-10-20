#ifndef MESSAGE_HANDLER_H
#define MESSAGE_HANDLER_H
#define EOT 0x04  // End of Transmission

#include <string>
#include <vector>

std::string frameMessage(const std::string &msg);
std::string unframeMessage(const std::string &msg);
std::vector<std::string> extractFramedCommands(const std::string &message);
std::vector<std::string> extractCommands(const std::string &message);
void processReceivedMessage(int sockfd, const std::string &message);
ssize_t sendWithLogging(int sockfd, const std::string &message);
ssize_t recvWithLogging(int sockfd, char *buffer, size_t bufferSize);

#endif
