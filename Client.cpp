#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <string>

void cipherData(char* data, int dataLen, const std::string& key) {
    int keyLen = key.length();
    for (int i = 0; i < dataLen; i++) {
        data[i] = data[i] ^ key[i % keyLen];
    }
}

int main() {
    const int targetPort = 8080;
    int myClientSocket = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in targetServerConfig;
    targetServerConfig.sin_family = AF_INET;
    targetServerConfig.sin_port = htons(targetPort);
    inet_pton(AF_INET, "127.0.0.1", &targetServerConfig.sin_addr);

    connect(myClientSocket, (struct sockaddr*)&targetServerConfig, sizeof(targetServerConfig));

    std::string userPsk;
    std::cout << "Server Password: ";
    std::cin >> userPsk;
    send(myClientSocket, userPsk.c_str(), userPsk.length(), 0);

    char serverMessage[1024] = {0};
    read(myClientSocket, serverMessage, 1024);
    std::cout << serverMessage << std::endl;

    if (strcmp(serverMessage, "Authenticated Successfully") == 0) {
        char choice;
        std::cout << "Do you want to secure the package (y/n): ";
        std::cin >> choice;
        send(myClientSocket, &choice, 1, 0);

        std::cin.ignore();
        
        std::string msg;
        std::cout << "Enter ur message: ";
        std::getline(std::cin, msg);

        char dataBuffer[1024] = {0};
        strcpy(dataBuffer, msg.c_str());
        int dataLength = msg.length();

        if (choice == 'y') {
            std::string cryptoKey;
            std::cout << "The encryption key pls: ";
            std::cin >> cryptoKey;
            
            cipherData(dataBuffer, dataLength, cryptoKey);
            send(myClientSocket, dataBuffer, dataLength, 0);
        } else {
            send(myClientSocket, dataBuffer, dataLength, 0);
        }
    }

    close(myClientSocket);
    
    return 0;
}