#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <string>
#include <csignal>
#include <fstream>
#include <chrono>
#include <atomic>
#include <pthread.h>
#include <sstream>
#include <iomanip>
#include <map>
#include <mutex>
#include <openssl/sha.h>
#include <cstdio>
#include <memory>
#include <array>
#include <vector>

std::atomic<bool> serverRunning(true);
int myServerFd;

std::mutex logMutex;
std::mutex ipMutex;

std::map<std::string, int> failedAttempts;
std::map<std::string, std::chrono::time_point<std::chrono::system_clock>> blockedIPs;
const int MAX_ATTEMPTS = 3;
const int BLOCK_DURATION_MINUTES = 5;

const auto logEvent = [](const std::string& message, const std::string& level = "INFO") {
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
};

const auto hashPassword = [](const std::string& password) -> std::string {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, password.c_str(), password.length());
    SHA256_Final(hash, &sha256);
    
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
};

const auto authenticateUser = [](const std::string& username, const std::string& plainPassword, std::string& outRole) -> bool {
    std::ifstream usersFile("users.txt");
    if (!usersFile.is_open()) return false;

    std::string hashedPassword = hashPassword(plainPassword);
    std::string fileUser, fileHash, fileRole;

    while (usersFile >> fileUser >> fileHash >> fileRole) {
        if (fileUser == username && fileHash == hashedPassword) {
            outRole = fileRole;
            return true;
        }
    }
    return false;
};

const auto execSysCommand = [](const std::string& cmd) -> std::string {
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
};

const auto evaluateCommand = [](const std::string& cmd, const std::string& role, const std::string& clientIP) -> std::string {
    if (cmd.find("passwords_backup.txt") != std::string::npos || cmd.find("admin_keys") != std::string::npos) {
        logEvent("HONEYPOT TRIGGERED by IP: " + clientIP + ". Attempted to access restricted bait file.", "CRITICAL");
        return "HONEYPOT_TRIGGER";
    }

    const std::vector<std::string> sysFiles = {
        "Server.cpp", "Client.cpp", "server", "client", "users.txt", "server.log"
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
};

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