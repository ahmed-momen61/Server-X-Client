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

std::mutex ipMutex;

std::map<std::string, int> failedAttempts;
std::map<std::string, std::chrono::time_point<std::chrono::system_clock>> blockedIPs;
const int MAX_ATTEMPTS = 3;
const int BLOCK_DURATION_MINUTES = 5;

struct ClientInfo {
    int socket;
    struct sockaddr_in address;
};

void* handleClient(void* arg) {
    pthread_detach(pthread_self());
    ClientInfo* client = (ClientInfo*)arg;
    int clientSocket = client->socket;
    std::string clientIP = inet_ntoa(client->address.sin_addr);
    
    struct timeval timeout;
    timeout.tv_sec = 300; 
    timeout.tv_usec = 0;
    setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    {
        std::lock_guard<std::mutex> lock(ipMutex);
        if (blockedIPs.find(clientIP) != blockedIPs.end()) {
            auto now = std::chrono::system_clock::now();
            if (now < blockedIPs[clientIP]) {
                logEvent("Blocked IP attempted connection: " + clientIP, "WARNING");
                const char* blockMsg = "IP is temporarily blocked due to multiple failed attempts.";
                send(clientSocket, blockMsg, strlen(blockMsg), 0);
                close(clientSocket);
                delete client;
                return nullptr;
            } else {
                blockedIPs.erase(clientIP); 
                failedAttempts[clientIP] = 0;
            }
        }
    }

    logEvent("New connection handling started for IP: " + clientIP, "INFO");

    char buffer[1024] = {0};
    int bytesRead = read(clientSocket, buffer, sizeof(buffer));
    
    if (bytesRead > 0) {
        std::string credentials(buffer);
        size_t colonPos = credentials.find(':');
        
        if (colonPos != std::string::npos) {
            std::string username = credentials.substr(0, colonPos);
            std::string password = credentials.substr(colonPos + 1);
            std::string userRole = "";

            if (authenticateUser(username, password, userRole)) {
                logEvent("User [" + username + "] authenticated successfully. Role: " + userRole, "SUCCESS");
                
                {
                    std::lock_guard<std::mutex> lock(ipMutex);
                    failedAttempts[clientIP] = 0;
                }

                std::string successMsg = "Auth_Success:" + userRole;
                send(clientSocket, successMsg.c_str(), successMsg.length(), 0);
                
                while (true) {
                    memset(buffer, 0, sizeof(buffer));
                    int cmdBytes = read(clientSocket, buffer, sizeof(buffer));
                    
                    if (cmdBytes <= 0) {
                        logEvent("Client " + username + " disconnected or timed out.", "INFO");
                        break;
                    }

                    std::string cmd(buffer);
                    if (cmd == "exit") break;

                    logEvent("User [" + username + "] executed: " + cmd, "INFO");
                    
                    std::string response = evaluateCommand(cmd, userRole, clientIP);
                    
                    if (response == "HONEYPOT_TRIGGER") {
                        const char* alert = "\n\033[31m[!] SECURITY ALERT: Unauthorized access attempt detected. Disconnecting...\033[0m\n";
                        send(clientSocket, alert, strlen(alert), 0);
                        break; 
                    }

                    send(clientSocket, response.c_str(), response.length(), 0);
                }

            } else {
                std::lock_guard<std::mutex> lock(ipMutex);
                failedAttempts[clientIP]++;
                logEvent("Failed login attempt from IP: " + clientIP + " for user: " + username + " (Attempt " + std::to_string(failedAttempts[clientIP]) + ")", "WARNING");
                
                if (failedAttempts[clientIP] >= MAX_ATTEMPTS) {
                    blockedIPs[clientIP] = std::chrono::system_clock::now() + std::chrono::minutes(BLOCK_DURATION_MINUTES);
                    logEvent("IP " + clientIP + " BLOCKED for " + std::to_string(BLOCK_DURATION_MINUTES) + " minutes.", "CRITICAL");
                }

                const char* failMsg = "Authentication Failed.";
                send(clientSocket, failMsg, strlen(failMsg), 0);
            }
        }
    }

    close(clientSocket);
    delete client;
    return nullptr;
}

void handleShutdownSignal(int signum) {
    logEvent("Shutdown signal (" + std::to_string(signum) + ") received. Initiating graceful shutdown...", "WARNING");
    serverRunning = false;
    close(myServerFd);
}

int main() {
    signal(SIGINT, handleShutdownSignal);

    const int serverPort = 8080;
    myServerFd = socket(AF_INET, SOCK_STREAM, 0);

    int opt = 1;
    setsockopt(myServerFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in serverConfig;
    serverConfig.sin_family = AF_INET;
    serverConfig.sin_addr.s_addr = INADDR_ANY;
    serverConfig.sin_port = htons(serverPort);

    if (bind(myServerFd, (struct sockaddr*)&serverConfig, sizeof(serverConfig)) < 0) {
        logEvent("Failed to bind to port.", "ERROR");
        return 1;
    }
    
    listen(myServerFd, 10);
    logEvent("Bayezid Secure Server started on port " + std::to_string(serverPort), "INFO");

    while (serverRunning) {
        struct sockaddr_in clientConfig;
        int configSize = sizeof(clientConfig);
        
        int activeClientConnection = accept(myServerFd, (struct sockaddr*)&clientConfig, (socklen_t*)&configSize);
        
        if (activeClientConnection < 0) {
            if (!serverRunning) break;
            continue;
        }

        ClientInfo* newClient = new ClientInfo;
        newClient->socket = activeClientConnection;
        newClient->address = clientConfig;

        pthread_t clientThread;
        if (pthread_create(&clientThread, NULL, handleClient, (void*)newClient) != 0) {
            logEvent("Failed to create thread.", "ERROR");
            close(activeClientConnection);
            delete newClient;
        }
    }

    logEvent("Server shut down cleanly.", "INFO");
    return 0;
}