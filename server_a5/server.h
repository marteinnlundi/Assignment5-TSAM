#ifndef SERVER_H
#define SERVER_H

#include <string>
#include <vector>
#include <map>
#include <ctime>
#include <mutex>
#include <iostream>

struct ServerInfo {
    std::string groupID;
    std::string ipAddress;
    int port;
    int sockfd;
    time_t lastKeepAlive;
};

extern std::vector<ServerInfo> serverList;
extern std::map<std::string, ServerInfo> connectedServers;
extern std::string currentServerName;
extern std::string currentServerIP;
extern std::string connectedServersIPs;  // Declare this variable globally

void sendHELOCommand(int sockfd);
int tryToConnect(ServerInfo server, bool isInitialConnection);
void sendKeepAliveMessages();
void startKeepAliveLoop();
void startStatusReqLoop();
void serverLoop(int listenSock);
void populateServerList(const std::string &ipAddress, int portStart, int portEnd);
bool isPortAvailable(int port);
int findFreePort(int startPort);
bool canEstablishConnection(bool isInitialConnection);
void requestStatusFromServers();

#endif
