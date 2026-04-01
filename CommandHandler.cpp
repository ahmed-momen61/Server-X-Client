#include "CommandHandler.h"
#include "Logger.h"
#include <array>
#include <memory>
#include <cstdio>
#include <fstream>
#include <vector>
#include <sstream>

std::string execSysCommand(const std::string& cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) {
        return "Error: Failed to execute system command.\n";
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result.empty() ? "(No output)\n" : result;
}

std::string evaluateCommand(const std::string& cmd, const std::string& role, const std::string& clientIP) {
    if (cmd.find("passwords_backup.txt") != std::string::npos || cmd.find("admin_keys") != std::string::npos) {
        logEvent("HONEYPOT TRIGGERED by IP: " + clientIP + ". Attempted to access restricted bait file.", "CRITICAL");
        return "HONEYPOT_TRIGGER";
    }

    const std::vector<std::string> sysFiles = {
        "Server.cpp", "Client.cpp", "server", "client", "users.txt", "server.log",
        "Logger.h", "Logger.cpp", "Security.h", "Security.cpp", "CommandHandler.h", "CommandHandler.cpp"
    };

    std::string targetFile = "";
    size_t spacePos = cmd.find(" ");
    if (spacePos != std::string::npos) {
        targetFile = cmd.substr(spacePos + 1);
    }

    if (role != "Top" && !targetFile.empty()) {
        for (const auto& sf : sysFiles) {
            if (targetFile.find(sf) != std::string::npos) {
                return "[-] Error: File not found or access denied.\n";
            }
        }
    }

    if (cmd.find("rm ") == 0 || cmd.find("delete ") == 0) {
        if (role != "Top") return "Error: Delete permission denied. (Requires Top Level)\n";
        
        std::string filename = cmd.substr(cmd.find(" ") + 1);
        if (std::remove(filename.c_str()) == 0) {
            return "[+] File '" + filename + "' deleted successfully from server.\n";
        } else {
            return "[-] Error: Could not delete file. Maybe it doesn't exist?\n";
        }
    }
    else if (cmd.find("cp ") == 0) {
        if (role == "Entry") return "Error: Copy permission denied. (Requires Medium/Top Level)\n";
        
        size_t firstSpace = cmd.find(" ");
        size_t secondSpace = cmd.find(" ", firstSpace + 1);
        
        if (secondSpace == std::string::npos) return "[-] Error: Invalid syntax. Use: cp source_file dest_file\n";
        
        std::string src = cmd.substr(firstSpace + 1, secondSpace - firstSpace - 1);
        std::string dest = cmd.substr(secondSpace + 1);
        
        std::ifstream source(src, std::ios::binary);
        std::ofstream destination(dest, std::ios::binary);
        
        if (!source) return "[-] Error: Source file not found.\n";
        
        destination << source.rdbuf();
        return "[+] File copied successfully from " + src + " to " + dest + "\n";
    }
    else if (cmd.find("cat ") == 0) {
        std::string filename = cmd.substr(cmd.find(" ") + 1);
        std::ifstream file(filename);
        
        if (!file) return "[-] Error: File '" + filename + "' not found or access denied.\n";
        
        std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        return "\n--- Content of " + filename + " ---\n" + content + "\n-------------------------\n";
    }
    else if (cmd == "ls") {
        std::string rawOutput = execSysCommand("ls -la");
        if (role == "Top") return rawOutput;

        std::stringstream ss(rawOutput);
        std::string line;
        std::string filteredOutput = "";

        while (std::getline(ss, line)) {
            bool isHidden = false;
            for (const auto& sf : sysFiles) {
                if (line.find(sf) != std::string::npos) {
                    isHidden = true;
                    break;
                }
            }
            if (!isHidden) {
                filteredOutput += line + "\n";
            }
        }
        return filteredOutput.empty() ? "(Empty Directory)\n" : filteredOutput;
    }
    
    return "[-] Unknown or unsupported command.\n";
}