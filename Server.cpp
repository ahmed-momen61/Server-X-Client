#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
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
    const int serverPort = 8080;
    int myServerFd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in serverConfig;
    serverConfig.sin_family = AF_INET;
    serverConfig.sin_addr.s_addr = INADDR_ANY;
    serverConfig.sin_port = htons(serverPort);

    bind(myServerFd, (struct sockaddr*)&serverConfig, sizeof(serverConfig));
    
    listen(myServerFd, 3);

    int configSize = sizeof(serverConfig);
    int activeClientConnection = accept(myServerFd, (struct sockaddr*)&serverConfig, (socklen_t*)&configSize);

    char receivedKey[1024] = {0};
    read(activeClientConnection, receivedKey, 1024);

    const std::string CORRECT_PSK = "mo2needs2sleep";

    if (strcmp(receivedKey, CORRECT_PSK.c_str()) == 0) {
        const char* successMsg = "Authenticated Successfully";
        send(activeClientConnection, successMsg, strlen(successMsg), 0);

        char encryptionChoice = 0;
        read(activeClientConnection, &encryptionChoice, 1);

        char secureBuffer[1024] = {0};
        int bytesReceived = read(activeClientConnection, secureBuffer, 1024);

        if (encryptionChoice == 'y') {
            std::cout << "Received secure package. Waiting for key..." << std::endl;
            std::string cryptoKey;
            std::cout << "decryption key: ";
            std::cin >> cryptoKey;
            
            cipherData(secureBuffer, bytesReceived, cryptoKey);
            std::cout << "Decrypted Message: " << secureBuffer << std::endl;
        } else {
            std::cout << "Received OG package: " << secureBuffer << std::endl;
        }

    } else {
        const char* failMsg = "Authentication Failed. FO try ur luck with another server.";
        send(activeClientConnection, failMsg, strlen(failMsg), 0);
    }

    close(activeClientConnection);
    close(myServerFd);
    
    return 0;
}