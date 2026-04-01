#include "Security.h"
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <fstream>

std::string hashPassword(const std::string& password) {
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
}

bool authenticateUser(const std::string& username, const std::string& plainPassword, std::string& outRole) {
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
}