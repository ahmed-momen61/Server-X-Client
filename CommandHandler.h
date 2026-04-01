#ifndef COMMANDHANDLER_H
#define COMMANDHANDLER_H
#include <string>
#include <map>
#include <mutex>

extern std::map<std::string, int> onlineUsers;
extern std::mutex userMutex;

std::string execSysCommand(const std::string& cmd);
std::string evaluateCommand(const std::string& cmd, const std::string& role, const std::string& clientIP, const std::string& username);
#endif