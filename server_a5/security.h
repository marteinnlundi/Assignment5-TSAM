#ifndef SECURITY_H
#define SECURITY_H
#define BLOCK_TIME_MINUTES 30 

#include <string>
#include <chrono>
#include <map>

extern std::map<std::string, std::chrono::time_point<std::chrono::system_clock>> blocklist;

bool isBlocked(const std::string &ip);
void blockIP(const std::string &ip);
void resetBlocklist();
void removeExpiredBlocks();

#endif
