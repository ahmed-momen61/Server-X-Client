#include "CommandHandler.h"
#include "Logger.h"
#include "Security.h"
#include <sys/socket.h>
#include <vector>
#include <sstream>
#include <cstdio>
#include <memory>
#include <array>

std::string execSysCommand(const std::string& cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) return "Error executing command.\n";
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) result += buffer.data();
    return result.empty() ? "(No output)\n" : result;
}

std::string evaluateCommand(const std::string& cmd, const std::string& role, const std::string& clientIP, const std::string& username) {
    // 1. Honeypot check
    if (cmd.find("passwords_backup.txt") != std::string::npos) {
        logEvent("HONEYPOT TRIGGERED by: " + username, "CRITICAL");
        return "HONEYPOT_TRIGGER";
    }

    // 2. Chat System
    if (cmd == "chat_list") {
        std::string list = "\n--- Online Users ---\n";
        std::lock_guard<std::mutex> lock(userMutex);
        for (auto const& [name, sock] : onlineUsers) list += "- " + name + (name == username ? " (You)" : "") + "\n";
        return list;
    }
    if (cmd.find("broadcast ") == 0) {
        std::string msg = "\n[BROADCAST from " + username + "]: " + cmd.substr(10) + "\n";
        std::string encrypted = encryptAES(msg);
        std::lock_guard<std::mutex> lock(userMutex);
        for (auto const& [name, sock] : onlineUsers) if (name != username) send(sock, encrypted.c_str(), encrypted.length(), 0);
        return "[+] Broadcast sent.";
    }
    if (cmd.find("msg ") == 0) {
        size_t firstSpace = cmd.find(" ", 4);
        if (firstSpace == std::string::npos) return "Usage: msg <user> <text>";
        std::string target = cmd.substr(4, firstSpace - 4);
        std::string msg = cmd.substr(firstSpace + 1);
        std::lock_guard<std::mutex> lock(userMutex);
        if (onlineUsers.count(target)) {
            std::string enc = encryptAES("\n[Private from " + username + "]: " + msg + "\n");
            send(onlineUsers[target], enc.c_str(), enc.length(), 0);
            return "[+] Message sent to " + target;
        }
        return "[-] User offline.";
    }

    // 3. RBAC & File Access
    const std::vector<std::string> sysFiles = {"Server.cpp", "Client.cpp", "server", "client", "users.txt", "server.log", "Logger.h", "Logger.cpp", "Security.h", "Security.cpp", "CommandHandler.h", "CommandHandler.cpp"};
    if (role != "Top") {
        for (const auto& sf : sysFiles) if (cmd.find(sf) != std::string::npos) return "[-] Access denied to system files.\n";
    }

    if (cmd == "ls") {
        std::string raw = execSysCommand("ls -la");
        if (role == "Top") return raw;
        std::stringstream ss(raw), out; std::string line;
        while (std::getline(ss, line)) {
            bool hidden = false;
            for (const auto& sf : sysFiles) if (line.find(sf) != std::string::npos) { hidden = true; break; }
            if (!hidden) out << line << "\n";
        }
        return out.str();
    }

    if (cmd.find("rm ") == 0 && role != "Top") return "[-] Error: Delete permission denied.\n";
    if (cmd.find("cp ") == 0 && role == "Entry") return "[-] Error: Copy permission denied.\n";

    return execSysCommand(cmd); 
}