#ifndef COMMANDHANDLER_H
#define COMMANDHANDLER_H

#include <string>

std::string execSysCommand(const std::string& cmd);
std::string evaluateCommand(const std::string& cmd, const std::string& role, const std::string& clientIP);

#endif