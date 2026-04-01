#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <string>

const std::string RESET = "\033[0m";
const std::string GREEN = "\033[32m";
const std::string RED = "\033[31m";
const std::string CYAN = "\033[36m";
const std::string YELLOW = "\033[33m";

int main() {
    const int targetPort = 8080;
    int myClientSocket = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in targetServerConfig;
    targetServerConfig.sin_family = AF_INET;
    targetServerConfig.sin_port = htons(targetPort);
    inet_pton(AF_INET, "127.0.0.1", &targetServerConfig.sin_addr);

    if (connect(myClientSocket, (struct sockaddr*)&targetServerConfig, sizeof(targetServerConfig)) < 0) {
        std::cout << RED << "Connection Failed. Is the server running?" << RESET << std::endl;
        return 1;
    }

    std::cout << CYAN << "--- Welcome to Bayezid Secure Access ---" << RESET << "\n";
    
    std::string username, password;
    std::cout << "Username: ";
    std::getline(std::cin, username);
    std::cout << "Password: ";
    std::getline(std::cin, password);

    std::string credentials = username + ":" + password;
    send(myClientSocket, credentials.c_str(), credentials.length(), 0);

    char serverMessage[1024] = {0};
    int bytesRead = read(myClientSocket, serverMessage, sizeof(serverMessage));

    if (bytesRead > 0) {
        std::string response(serverMessage);
        
        if (response.find("Auth_Success:") == 0) {
            std::string role = response.substr(13); 
            std::cout << GREEN << "\n[+] Authenticated Successfully!" << RESET << "\n";
            std::cout << YELLOW << "Current Role: " << role << RESET << "\n\n";
            std::cout << "Type 'exit' to disconnect. Try commands like 'ls', 'cat file', 'cp file', 'rm file'.\n";

            while (true) {
                std::cout << CYAN << "Bayezid-Shell (" << role << ")> " << RESET;
                std::string cmd;
                std::getline(std::cin, cmd);

                if (cmd.empty()) continue;

                send(myClientSocket, cmd.c_str(), cmd.length(), 0);

                if (cmd == "exit") {
                    std::cout << "Disconnecting...\n";
                    break;
                }

                char responseBuffer[2048] = {0};
                int respBytes = read(myClientSocket, responseBuffer, sizeof(responseBuffer));
                
                if (respBytes <= 0) {
                    std::cout << RED << "\n[!] Connection closed by server (Timeout or Kicked)." << RESET << "\n";
                    break;
                }

                std::cout << responseBuffer << "\n";
            }
        } else {
            std::cout << RED << "\n[-] " << response << RESET << "\n";
        }
    }

    close(myClientSocket);
    return 0;
}
