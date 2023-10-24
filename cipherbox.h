#ifndef CIPHERBOX_H
#define CIPHERBOX_H

#include <openssl/rsa.h>
#include <string>
#include <vector>

class Cipherbox {
public:
    Cipherbox();

    bool writeRSAKeysToFile(RSA* rsa_keypair);
    RSA* generateRSAKeys();
    std::vector<unsigned char> encryptWithRSAPublicKey(RSA* rsa_public_key, const unsigned char* data, size_t data_len);
    std::vector<unsigned char> decryptWithRSAPrivateKey(RSA* rsa_private_key, const unsigned char* encrypted_data, size_t encrypted_data_len);
    std::string generateRandomString(int length);
    std::string pbkdf2(const std::string& password, const std::vector<unsigned char>& salt, int iterations, int keyLength);
    std::string generateKey(const std::string& password);
    std::vector<unsigned char> generateIV();
    bool encryptFile(const std::string& inputFileName, const std::string& outputFileName, const std::string& key);
    bool decryptFile(const std::string& inputFileName, const std::string& outputFileName, const std::string& key);
};

#endif // CIPHERBOX_H

