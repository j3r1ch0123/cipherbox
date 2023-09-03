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

class Cipherbox {
public:
    Cipherbox() {}

    bool writeRSAKeysToFile(RSA* rsa_keypair) {
        string pubkey_file = "public.pem";
        string privkey_file = "private.pem";

        // Write the public key to the file
        FILE* pub_file = fopen(pubkey_file.c_str(), "wb");
        if (!pub_file) {
            cerr << "Error opening public key file" << endl;
            return false;
        }
        if (PEM_write_RSAPublicKey(pub_file, rsa_keypair) != 1) {
            cerr << "Error writing public key to file" << endl;
            fclose(pub_file);
            return false;
        }
        fclose(pub_file);

        // Write the private key to the file
        FILE* priv_file = fopen(privkey_file.c_str(), "wb");
        if (!priv_file) {
            cerr << "Error opening private key file" << endl;
            return false;
        }
        if (PEM_write_RSAPrivateKey(priv_file, rsa_keypair, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
            cerr << "Error writing private key to file" << endl;
            fclose(priv_file);
            return false;
        }
        fclose(priv_file);

        return true;
    }

    RSA* generateRSAKeys() {
        RSA* rsa_keypair = RSA_new();
        BIGNUM* exponent = BN_new();
        string pubkey = "public.pem";
        string privkey = "private.pem";

        BN_set_word(exponent, RSA_F4);

        if (RSA_generate_key_ex(rsa_keypair, 2048, exponent, nullptr) != 1) {
            return nullptr;
        }

        BN_free(exponent);
        writeRSAKeysToFile(rsa_keypair);

        return rsa_keypair;
    }

    vector<unsigned char> encryptWithRSAPublicKey(RSA* rsa_public_key, const unsigned char* data, size_t data_len) {
        vector<unsigned char> encrypted_data(RSA_size(rsa_public_key));

        int encrypted_size = RSA_public_encrypt(data_len, data, encrypted_data.data(), rsa_public_key, RSA_PKCS1_OAEP_PADDING);
        if (encrypted_size == -1) {
            return vector<unsigned char>();
        }

        encrypted_data.resize(encrypted_size);
        return encrypted_data;
    }

    vector<unsigned char> decryptWithRSAPrivateKey(RSA* rsa_private_key, const unsigned char* encrypted_data, size_t encrypted_data_len) {
        vector<unsigned char> decrypted_data(RSA_size(rsa_private_key));

        int decrypted_size;
        decrypted_size = RSA_private_decrypt(encrypted_data_len, encrypted_data, decrypted_data.data(), rsa_private_key, RSA_PKCS1_OAEP_PADDING);

        if (decrypted_size == -1) {
            return vector<unsigned char>();
        }

        decrypted_data.resize(decrypted_size);
        return decrypted_data;
    }

    string generateRandomString(int length) {
        static const std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=]/.><:;?'}{";
        string password;

        random_device rd;
        mt19937 generator(rd());
        uniform_int_distribution<int> distribution(0, charset.size() - 1);

        for (int i = 0; i < length; i++) {
            password += charset[distribution(generator)];
        }

        return password;
    }

    string pbkdf2(const string& password, const vector<unsigned char>& salt, int iterations, int keyLength) {
        vector<unsigned char> key(keyLength);
        PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt.data(), salt.size(), iterations, EVP_sha256(), keyLength, key.data());
        return string(reinterpret_cast<const char*>(key.data()), key.size());
    }

    string generateKey(const string& password) {
        constexpr int SALT_SIZE = 16;
        constexpr int KEY_SIZE = 32;
        constexpr int PBKDF2_ITERATIONS = 10000;

        // Generate a random salt
        vector<unsigned char> salt(SALT_SIZE);
        if (RAND_bytes(salt.data(), SALT_SIZE) != 1) {
            cerr << "Error generating salt..." << endl;
            return string();
        }

        // Perform PBKDF2 key derivation with the salt using SHA-256
        vector<unsigned char> key(KEY_SIZE);
        PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt.data(), salt.size(), PBKDF2_ITERATIONS, EVP_sha256(), KEY_SIZE, key.data());

        // Convert the key to a hexadecimal string
        stringstream hexKeyStream;
        for (const auto& byte : key) {
            hexKeyStream << hex << setfill('0') << setw(2) << static_cast<int>(byte);
        }
        string hexKey = hexKeyStream.str();

        // Remove any newline characters from the Base64 encoded key
        // Concatenate the salt and derived key and return as a single string
        string result;
        result.append(reinterpret_cast<const char*>(salt.data()), SALT_SIZE);
        return result;
    }


    vector<unsigned char> generateIV() {
        vector<unsigned char> iv(AES_BLOCK_SIZE);
        if (RAND_bytes(iv.data(), AES_BLOCK_SIZE) != 1) {
            cerr << "Error generating IV..." << endl;
            // Handle the error appropriately
        }
        return iv;
    }

    void encryptFile(const string& inputFileName, const string& outputFileName, const string& key) {
        ifstream inputFile(inputFileName, ios::binary);
        if (!inputFile) {
            cerr << "Error opening input file..." << endl;
            return;
        }

        ofstream outputFile(outputFileName, ios::binary);
        if (!outputFile) {
            cerr << "Error opening output file..." << endl;
            return;
        }

        AES_KEY aes_key;
        AES_set_encrypt_key(reinterpret_cast<const unsigned char*>(key.c_str()), 256, &aes_key);

        vector<unsigned char> inputBuffer(AES_BLOCK_SIZE);
        vector<unsigned char> outputBuffer(AES_BLOCK_SIZE);
        vector<unsigned char> iv = generateIV();
        outputFile.write(reinterpret_cast<char*>(iv.data()), AES_BLOCK_SIZE);
        
        while (!inputFile.eof()) {
            memset(inputBuffer.data(), 0, AES_BLOCK_SIZE); 
            inputFile.read(reinterpret_cast<char*>(inputBuffer.data()), AES_BLOCK_SIZE);

            int bytesRead = inputFile.gcount();
            int padding = AES_BLOCK_SIZE - bytesRead;
            if (bytesRead < AES_BLOCK_SIZE) {
                for (int i = bytesRead; i < AES_BLOCK_SIZE; ++i) {
                    inputBuffer[i] = padding;
                }
            }

            AES_encrypt(inputBuffer.data(), outputBuffer.data(), &aes_key);

            outputFile.write(reinterpret_cast<char*>(outputBuffer.data()), AES_BLOCK_SIZE);
        }

        inputFile.close();
        outputFile.close();
        cout << "Encryption Complete!!!" << endl;
    }
    
    void decryptFile(const string& inputFileName, const string& outputFileName, const string& key) {
        ifstream inputFile(inputFileName, ios::binary);
        if (!inputFile) {
            cerr << "Error opening input file..." << endl;
            return;
        }

        ofstream outputFile(outputFileName, ios::binary);
        if (!outputFile) {
            cerr << "Error opening output file..." << endl;
            return;
        }

        vector<unsigned char> iv(AES_BLOCK_SIZE);
        inputFile.read(reinterpret_cast<char*>(iv.data()), AES_BLOCK_SIZE);

        AES_KEY aes_key;
        AES_set_decrypt_key(reinterpret_cast<const unsigned char*>(key.c_str()), 256, &aes_key);

        vector<unsigned char> inputBuffer(AES_BLOCK_SIZE);
        vector<unsigned char> outputBuffer(AES_BLOCK_SIZE);

        bool lastBlock = false;
    
        while (true) {
            inputFile.read(reinterpret_cast<char*>(inputBuffer.data()), AES_BLOCK_SIZE);
            int bytesRead = inputFile.gcount();

            if (bytesRead == 0) {
                break;
            }

            if (inputFile.peek() == EOF) {
                lastBlock = true;
            }

            AES_decrypt(inputBuffer.data(), outputBuffer.data(), &aes_key);

            if (lastBlock) {
                int padding = outputBuffer[AES_BLOCK_SIZE - 1];
                int unpaddedBytes = AES_BLOCK_SIZE - padding;
                outputFile.write(reinterpret_cast<char*>(outputBuffer.data()), unpaddedBytes);
            }
            
            else {
                outputFile.write(reinterpret_cast<char*>(outputBuffer.data()), AES_BLOCK_SIZE);
            }
        }

        inputFile.close();
        outputFile.close();
        cout << "Decryption Complete!!!" << endl;
    }

};
