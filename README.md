# Cipherbox C++ Library

The Cipherbox C++ Library is a collection of functions and classes that allow you to perform encryption and decryption using RSA and AES algorithms with OpenSSL. It provides convenient methods for key generation, encryption, decryption, and more.

## Table of Contents
- [Installation](#installation)
- [Usage](#usage)

## Installation

Before using Cipherbox, you need to have OpenSSL installed on your system. You can install OpenSSL on Ubuntu using the following command:

```shell
sudo apt-get install libssl-dev
```

Then, you can include the `Cipherbox` class in your C++ project by adding the source file to your project or linking against the compiled library.

## Usage

Here are some common use cases for Cipherbox:

### Generating RSA Key Pair

```cpp
#include "cipherbox.h"

Cipherbox cipher;
RSA* rsa_keypair = cipher.generateRSAKeys();
```

### Encrypting Data with RSA Public Key

```cpp
#include "cipherbox.h"

Cipherbox cipher;
RSA* rsa_public_key = // Load your RSA public key
const unsigned char* data = // Your data to encrypt
size_t data_len = // Length of the data

std::vector<unsigned char> encrypted_data = cipher.encryptWithRSAPublicKey(rsa_public_key, data, data_len);
```

### Decrypting Data with RSA Private Key

```cpp
#include "cipherbox.h"

Cipherbox cipher;
RSA* rsa_private_key = // Load your RSA private key
const unsigned char* encrypted_data = // Your encrypted data
size_t encrypted_data_len = // Length of the encrypted data

std::vector<unsigned char> decrypted_data = cipher.decryptWithRSAPrivateKey(rsa_private_key, encrypted_data, encrypted_data_len);
```

### Encrypting and Decrypting Files with AES

```cpp
#include "cipherbox.h"

Cipherbox cipher;
std::string key = // Your AES encryption key
std::string inputFileName = // Input file name
std::string outputFileName = // Output file name

cipher.encryptFile(inputFileName, outputFileName, key); // To encrypt a file
cipher.decryptFile(inputFileName, outputFileName, key); // To decrypt a file
```
