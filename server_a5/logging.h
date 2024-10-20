#ifndef LOGGING_H
#define LOGGING_H
#define LOG_FILE "server_log.txt"
#define MAX_LOG_FILE_SIZE (1024 * 1024 * 5)

#include <string>
#include <mutex>
#include <fstream>

extern std::mutex logMutex;
extern std::ofstream logFile;

void logMessage(const std::string &logType, const std::string &message);
void rotateLogFile();

#endif
