#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <string>
#include <pthread.h>
#include "Security.h"

const std::string RESET  = "\033[0m";
const std::string GREEN  = "\033[32m";
const std::string RED    = "\033[31m";
const std::string CYAN   = "\033[36m";
const std::string YELLOW = "\033[33m";
const std::string WHITE  = "\033[37m";
const std::string BOLD   = "\033[1m";

void* receiverThread(void* arg) {
    int sock = *(int*)arg;
    char buffer[8192];
    while (true) {
        memset(buffer, 0, 8192);
        int bytesReceived = read(sock, buffer, 8192);
        if (bytesReceived <= 0) break;
        
        // فك تشفير الرسالة القادمة من السيرفر
        std::string msg = decryptAES(std::string(buffer));
        
        // التحقق من نظام الفخاخ (Honeypot)
        if (msg.find("HONEYPOT_TRIGGER") != std::string::npos) {
            std::cout << RED << BOLD << "\n[!] SECURITY ALERT: Unauthorized access attempt detected. DISCONNECTING..." << RESET << std::endl;
            exit(0);
        }

        std::cout << "\r" << msg << "\n" << CYAN << "Bayezid-Shell> " << RESET << std::flush;
    }
    return nullptr;
}

void printGuide() {
    std::cout << CYAN << "===============================================================" << RESET << "\n";
    std::cout << WHITE << BOLD << "              BAYEZID SECURE SHELL - COMMAND GUIDE             " << RESET << "\n";
    std::cout << CYAN << "===============================================================" << RESET << "\n";
    std::cout << GREEN << BOLD << " [File Operations] " << RESET << "\n";
    std::cout << "  ls                : List accessible files (RBAC Filtered)\n";
    std::cout << "  cat <file>        : Read file content\n";
    std::cout << "  cp <src> <dest>   : Copy files (Medium/Top Levels)\n";
    std::cout << "  rm <file>         : Delete files (Top Level Only)\n";
    std::cout << "\n";
    std::cout << YELLOW << BOLD << " [Encrypted Chat System - AES 256] " << RESET << "\n";
    std::cout << "  chat_list         : Show all online employees\n";
    std::cout << "  msg <user> <text> : Send a private, encrypted message\n";
    std::cout << "  broadcast <text>  : Send an encrypted message to everyone\n";
    std::cout << "\n";
    std::cout << RED << BOLD << " [System] " << RESET << "\n";
    std::cout << "  help              : Show this command guide again\n";
    std::cout << "  exit              : Securely disconnect from server\n";
    std::cout << CYAN << "===============================================================" << RESET << "\n\n";
}

int main() {
    const int port = 8080;
    int sock = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr);

    if (connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cout << RED << "[-] Connection Failed. Ensure server is running on port " << port << RESET << std::endl;
        return 1;
    }

    std::cout << CYAN << BOLD << "--- Welcome to Bayezid Secure Access Terminal ---" << RESET << "\n";
    
    std::string username, password;
    std::cout << "Username: "; std::getline(std::cin, username);
    std::cout << "Password: "; std::getline(std::cin, password);

    std::string credentials = username + ":" + password;
    send(sock, credentials.c_str(), credentials.length(), 0);

    char authBuffer[4096] = {0};
    int authRead = read(sock, authBuffer, 4096);
    
    if (authRead <= 0) {
        std::cout << RED << "[-] Server connection closed during authentication." << RESET << std::endl;
        return 1;
    }

    std::string authResp = decryptAES(std::string(authBuffer));

    if (authResp.find("Auth_Success:") == 0) {
        std::string role = authResp.substr(13);
        std::cout << GREEN << BOLD << "\n[+] Authenticated Successfully!" << RESET << "\n";
        std::cout << YELLOW << "Current Assigned Role: " << role << RESET << "\n\n";

        printGuide();

        pthread_t t;
        pthread_create(&t, NULL, receiverThread, &sock);

        while (true) {
            std::cout << CYAN << "Bayezid-Shell> " << RESET;
            std::string cmd;
            std::getline(std::cin, cmd);

            if (cmd.empty()) continue;

            if (cmd == "help") {
                printGuide();
                continue;
            }
            if (cmd == "exit") {
                std::string encExit = encryptAES("exit");
                send(sock, encExit.c_str(), encExit.length(), 0);
                std::cout << YELLOW << "Disconnecting safely..." << RESET << std::endl;
                break;
            }

            std::string encryptedCmd = encryptAES(cmd);
            send(sock, encryptedCmd.c_str(), encryptedCmd.length(), 0);
        }
    } else {
        std::cout << RED << "\n[-] Authentication Failed: " << authResp << RESET << std::endl;
    }

    close(sock);
    return 0;
}