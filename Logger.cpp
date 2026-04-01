#include "Logger.h"
#include <iostream>
#include <fstream>
#include <chrono>
#include <mutex>

std::mutex logMutex;

void logEvent(const std::string& message, const std::string& level) {
    std::lock_guard<std::mutex> lock(logMutex);
    std::ofstream logFile("server.log", std::ios_base::app);
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    std::string timeStr = std::ctime(&now_time);
    timeStr.pop_back();
    std::string logEntry = "[" + timeStr + "] [" + level + "] " + message;
    
    std::string color = "\033[0m"; 
    if (level == "SUCCESS") color = "\033[32m"; 
    else if (level == "WARNING") color = "\033[33m"; 
    else if (level == "CRITICAL" || level == "ERROR") color = "\033[31m"; 

    std::cout << color << logEntry << "\033[0m\n";
    if (logFile.is_open()) logFile << logEntry << "\n";
}