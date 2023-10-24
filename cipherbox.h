/**
 * @file cipherbox.h
 * @brief A C++ library for encryption and decryption using OpenSSL.
 */

#ifndef CIPHERBOX_H
#define CIPHERBOX_H

#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <iomanip>
#include <random>
#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <cstring>
#include <algorithm>
using namespace std;

/**
 * @class Cipherbox
 * @brief A class that provides encryption and decryption methods using RSA and AES.
 */
class Cipherbox {
public:
    /**
     * Default constructor for the Cipherbox class.
     */
    Cipherbox() {}

    /**
     * Write the RSA key pair to PEM files.
     *
     * @param rsa_keypair The RSA key pair to be written to files.
     * @return true if successful, false otherwise.
     */
    bool writeRSAKeysToFile(RSA* rsa_keypair);

    /**
     * Generate an RSA key pair and write it to PEM files.
     *
     * @return The generated RSA key pair.
     */
    RSA* generateRSAKeys();

    /**
     * Encrypt data using an RSA public key.
     *
     * @param rsa_public_key The RSA public key for encryption.
     * @param data The data to be encrypted.
     * @param data_len The length of the data.
     * @return The encrypted data.
     */
    std::vector<unsigned char> encryptWithRSAPublicKey(RSA* rsa_public_key, const unsigned char* data, size_t data_len);

    /**
     * Decrypt data using an RSA private key.
     *
     * @param rsa_private_key The RSA private key for decryption.
     * @param encrypted_data The encrypted data to be decrypted.
     * @param encrypted_data_len The length of the encrypted data.
     * @return The decrypted data.
     */
    std::vector<unsigned char> decryptWithRSAPrivateKey(RSA* rsa_private_key, const unsigned char* encrypted_data, size_t encrypted_data_len);

    /**
     * Generate a random string of a specified length.
     *
     * @param length The length of the random string to generate.
     * @return The generated random string.
     */
    std::string generateRandomString(int length);

    /**
     * Perform PBKDF2 key derivation function for password-based encryption.
     *
     * @param password The input password.
     * @param salt The salt value.
     * @param iterations The number of iterations.
     * @param keyLength The length of the derived key.
     * @return The derived key as a string.
     */
    std::string pbkdf2(const std::string& password, const std::vector<unsigned char>& salt, int iterations, int keyLength);

    /**
     * Generate a hexadecimal encryption key from a password.
     *
     * @param password The input password.
     * @return The generated encryption key in hexadecimal format.
     */
    std::string generateKey(const std::string& password);

    /**
     * Generate a random Initialization Vector (IV) for AES encryption.
     *
     * @return The generated IV.
     */
    std::vector<unsigned char> generateIV();

    /**
     * Encrypt a file using AES encryption.
     *
     * @param inputFileName The name of the input file to be encrypted.
     * @param outputFileName The name of the output encrypted file.
     * @param key The encryption key.
     */
    void encryptFile(const std::string& inputFileName, const std::string& outputFileName, const std::string& key);

    /**
     * Decrypt a file previously encrypted with AES encryption.
     *
     * @param inputFileName The name of the input encrypted file to be decrypted.
     * @param outputFileName The name of the output decrypted file.
     * @param key The decryption key.
     */
    void decryptFile(const std::string& inputFileName, const std::string& outputFileName, const std::string& key);
};

#endif // CIPHERBOX_H

