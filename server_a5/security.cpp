#include "security.h"
#include "logging.h"
#include <chrono>

std::map<std::string, std::chrono::time_point<std::chrono::system_clock>> blocklist;

bool isBlocked(const std::string &ip) {
    auto now = std::chrono::system_clock::now();
    if (blocklist.find(ip) != blocklist.end()) {
        if (blocklist[ip] > now) {
            return true;
        } else {
            blocklist.erase(ip);
        }
    }
    return false;
}

void blockIP(const std::string &ip) {
    auto now = std::chrono::system_clock::now();
    blocklist[ip] = now + std::chrono::minutes(BLOCK_TIME_MINUTES);
    logMessage("INFO", "Blocked IP: " + ip + " for " + std::to_string(BLOCK_TIME_MINUTES) + " minutes.");
}

void resetBlocklist() {
    blocklist.clear();
    logMessage("INFO", "Blocklist has been cleared.");
}

void removeExpiredBlocks() {
    auto now = std::chrono::system_clock::now();
    for (auto it = blocklist.begin(); it != blocklist.end();) {
        if (it->second < now) {
            it = blocklist.erase(it);
        } else {
            ++it;
        }
    }
}
