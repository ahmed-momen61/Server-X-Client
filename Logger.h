#ifndef LOGGER_H
#define LOGGER_H

#include <string>

void logEvent(const std::string& message, const std::string& level = "INFO");

#endif