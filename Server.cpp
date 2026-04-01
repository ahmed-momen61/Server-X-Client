#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <csignal>
#include <atomic>
#include <pthread.h>
#include <map>
#include <mutex>
#include "Logger.h"
#include "Security.h"
#include "CommandHandler.h"

std::atomic<bool> serverRunning(true);
int myServerFd;
std::map<std::string, int> onlineUsers;
std::mutex userMutex;
std::mutex ipMutex;
std::map<std::string, int> failedAttempts;
std::map<std::string, std::chrono::time_point<std::chrono::system_clock>> blockedIPs;

struct ClientInfo { int socket; struct sockaddr_in address; };

void* handleClient(void* arg) {
    pthread_detach(pthread_self());
    ClientInfo* client = (ClientInfo*)arg;
    int clientSocket = client->socket;
    std::string clientIP = inet_ntoa(client->address.sin_addr);
    char buffer[4096];

    // Brute-force check
    {
        std::lock_guard<std::mutex> lock(ipMutex);
        if (blockedIPs.count(clientIP) && std::chrono::system_clock::now() < blockedIPs[clientIP]) {
            send(clientSocket, "IP_BLOCKED", 10, 0); close(clientSocket); delete client; return nullptr;
        }
    }

    int bytes = read(clientSocket, buffer, 4096);
    if (bytes > 0) {
        std::string creds(buffer); size_t colon = creds.find(':');
        if (colon != std::string::npos) {
            std::string user = creds.substr(0, colon), pass = creds.substr(colon+1), role;
            if (authenticateUser(user, pass, role)) {
                { std::lock_guard<std::mutex> lock(userMutex); onlineUsers[user] = clientSocket; }
                logEvent("User [" + user + "] authenticated. Role: " + role, "SUCCESS");
                std::string success = encryptAES("Auth_Success:" + role);
                send(clientSocket, success.c_str(), success.length(), 0);

                while (true) {
                    memset(buffer, 0, 4096);
                    int cmdBytes = read(clientSocket, buffer, 4096);
                    if (cmdBytes <= 0) break;
                    std::string cmd = decryptAES(std::string(buffer));
                    if (cmd == "exit") break;
                    logEvent("User [" + user + "] executed: " + cmd);
                    std::string resp = evaluateCommand(cmd, role, clientIP, user);
                    if (resp == "HONEYPOT_TRIGGER") {
                        send(clientSocket, encryptAES("HONEYPOT_TRIGGER").c_str(), 64, 0); break;
                    }
                    std::string encResp = encryptAES(resp);
                    send(clientSocket, encResp.c_str(), encResp.length(), 0);
                }
                { std::lock_guard<std::mutex> lock(userMutex); onlineUsers.erase(user); }
            } else {
                std::lock_guard<std::mutex> lock(ipMutex);
                if (++failedAttempts[clientIP] >= 3) blockedIPs[clientIP] = std::chrono::system_clock::now() + std::chrono::minutes(5);
                send(clientSocket, "AUTH_FAILED", 11, 0);
            }
        }
    }
    close(clientSocket); delete client; return nullptr;
}

int main() {
    signal(SIGINT, [](int){ serverRunning = false; close(myServerFd); });
    myServerFd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1; setsockopt(myServerFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in cfg = {AF_INET, htons(8080), INADDR_ANY};
    bind(myServerFd, (struct sockaddr*)&cfg, sizeof(cfg));
    listen(myServerFd, 10);
    logEvent("Bayezid Secure Server started on port 8080", "INFO");
    while (serverRunning) {
        struct sockaddr_in c_cfg; socklen_t len = sizeof(c_cfg);
        int c_sock = accept(myServerFd, (struct sockaddr*)&c_cfg, &len);
        if (c_sock < 0) break;
        ClientInfo* n_c = new ClientInfo{c_sock, c_cfg};
        pthread_t t; pthread_create(&t, NULL, handleClient, n_c);
    }
    return 0;
}