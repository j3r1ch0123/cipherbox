#include <openssl/aes.h>
#include <openssl/sha.h>
#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <cstring>
using namespace std;

class Cipherbox {
public:
    Cipherbox() {}

    string generateKey(const string& password) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(password.c_str()), password.length(), hash);
        return string(reinterpret_cast<const char*>(hash), SHA256_DIGEST_LENGTH);
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
            } else {
                outputFile.write(reinterpret_cast<char*>(outputBuffer.data()), AES_BLOCK_SIZE);
            }
        }

        inputFile.close();
        outputFile.close();
        cout << "Decryption Complete!!!" << endl;
    }

};