#include "Security.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <vector>

const unsigned char AES_KEY[] = "01234567890123456789012345678901"; // 32 bytes
const unsigned char AES_IV[]  = "0123456789012345"; // 16 bytes

std::string hashPassword(const std::string& password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, password.c_str(), password.length());
    SHA256_Final(hash, &sha256);
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
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

std::string encryptAES(const std::string& plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;
    std::vector<unsigned char> ciphertext(plaintext.length() + 32);
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, AES_KEY, AES_IV);
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (unsigned char*)plaintext.c_str(), (int)plaintext.length());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    std::stringstream ss;
    for(int i=0; i<ciphertext_len; i++) ss << std::hex << std::setw(2) << std::setfill('0') << (int)ciphertext[i];
    return ss.str();
}

std::string decryptAES(const std::string& hexCiphertext) {
    std::vector<unsigned char> ciphertext;
    for (size_t i = 0; i < hexCiphertext.length(); i += 2) {
        ciphertext.push_back((unsigned char)strtol(hexCiphertext.substr(i, 2).c_str(), NULL, 16));
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len;
    std::vector<unsigned char> plaintext(ciphertext.size() + 32);
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, AES_KEY, AES_IV);
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), (int)ciphertext.size());
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return std::string((char*)plaintext.data(), plaintext_len);
}