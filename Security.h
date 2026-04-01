#ifndef SECURITY_H
#define SECURITY_H
#include <string>

std::string hashPassword(const std::string& password);
bool authenticateUser(const std::string& username, const std::string& plainPassword, std::string& outRole);
std::string encryptAES(const std::string& plaintext);
std::string decryptAES(const std::string& hexCiphertext);
#endif