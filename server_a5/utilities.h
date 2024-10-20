#ifndef UTILITIES_H
#define UTILITIES_H

#include <string>
#include <vector>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>

std::vector<std::string> splitString(const std::string &str, char delimiter);
std::string trim(const std::string &str);
std::string getPublicIP();
bool isPortAvailable(int port);
int findFreePort(int startPort);


#endif
