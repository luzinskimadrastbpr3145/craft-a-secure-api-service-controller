#include <iostream>
#include <string>
#include <algorithm>
#include <openssl/sha.h>
#include <openssl/aes.h>

class SecureAPIController {
public:
    SecureAPIController(std::string key) : encryptionKey(key) {}

    std::string hashPassword(std::string password) {
        unsigned char hashedPassword[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, password.c_str(), password.length());
        SHA256_Final(hashedPassword, &sha256);
        std::string hashedPasswordStr(hashedPassword, hashedPassword + SHA256_DIGEST_LENGTH);
        return hashedPasswordStr;
    }

    std::string encryptData(std::string data) {
        unsigned char encryptedData[data.length + AES_BLOCK_SIZE];
        AES_KEY aesKey;
        AES_set_encrypt_key((unsigned char*)encryptionKey.c_str(), encryptionKey.length() * 8, &aesKey);
        AES_cbc_encrypt((unsigned char*)data.c_str(), encryptedData, data.length(), &aesKey, (unsigned char*)encryptionKey.c_str(), AES_ENCRYPT);
        std::string encryptedDataStr(encryptedData, encryptedData + data.length + AES_BLOCK_SIZE);
        return encryptedDataStr;
    }

    std::string decryptData(std::string encryptedData) {
        unsigned char decryptedData[encryptedData.length - AES_BLOCK_SIZE];
        AES_KEY aesKey;
        AES_set_decrypt_key((unsigned char*)encryptionKey.c_str(), encryptionKey.length() * 8, &aesKey);
        AES_cbc_decrypt((unsigned char*)encryptedData.c_str(), decryptedData, encryptedData.length(), &aesKey, (unsigned char*)encryptionKey.c_str(), AES_DECRYPT);
        std::string decryptedDataStr(decryptedData, decryptedData + encryptedData.length - AES_BLOCK_SIZE);
        return decryptedDataStr;
    }

private:
    std::string encryptionKey;
};

int main() {
    SecureAPIController apiCtrl("my_secret_key");
    std::string password = "my_password";
    std::string hashedPassword = apiCtrl.hashPassword(password);
    std::cout << "Hashed Password: " << hashedPassword << std::endl;

    std::string data = "Hello, World!";
    std::string encryptedData = apiCtrl.encryptData(data);
    std::cout << "Encrypted Data: " << encryptedData << std::endl;

    std::string decryptedData = apiCtrl.decryptData(encryptedData);
    std::cout << "Decrypted Data: " << decryptedData << std::endl;

    return 0;
}