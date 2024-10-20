#include "logging.h"
#include <ctime>
#include <iostream>
#include <sys/stat.h>
#include <cstring>  

std::mutex logMutex;
std::ofstream logFile;

void logMessage(const std::string &logType, const std::string &message) {
    std::lock_guard<std::mutex> lock(logMutex);
    
    time_t now = time(0);
    char* dt = ctime(&now);
    dt[strlen(dt) - 1] = '\0'; // Remove newline

    std::cout << "[" << dt << "] [" << logType << "] " << message << std::endl;
    logFile << "[" << dt << "] [" << logType << "] " << message << "\n";
    logFile.flush();

    rotateLogFile();
}

void rotateLogFile() {
    struct stat logFileInfo;
    if (stat("server_log.txt", &logFileInfo) == 0 && logFileInfo.st_size >= MAX_LOG_FILE_SIZE) {
        logFile.close();
        rename("server_log.txt", "server_log_old.txt");
        logFile.open("server_log.txt", std::ios::out | std::ios::app);
    }
}
