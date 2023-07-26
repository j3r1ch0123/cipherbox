#include "cipherbox.h"
#include <iostream>
#include <string>
#include <fstream>

int main(void) {
    Cipherbox cipher;
    string password;
    cout << "Please enter the password for encryption/decryption: " << endl;
    cin >> password;

    string key = cipher.generateKey(password);
    cout << "Key: " << key << endl;

    char choice;
    cout << "Would you like to encrypt or decrypt? (e/d): " << endl;
    cin >> choice;

    if (choice == 'e') {

        string file;
        cout << "Enter the name of the file you want encrypted: " << endl;
        cin >> file;

        string outfile;
        cout << "What would you like to save the encrypted file as? " << endl;
        cin >> outfile;

        cipher.encryptFile(file, outfile, key);

        return 0;
    }
    
    else if (choice == 'd') {
        string file;
        cout << "Enter the name of the file you want to decrypt: " << endl;
        cin >> file;
        
        string outfile;
        cout << "What would you like to save the decrypted file as? " << endl;
        cin >> outfile;

        cipher.decryptFile(file, outfile, key);
        
        return 0;
    }

    else {
        cout << "Please enter either 'e' or 'd' " << endl;
    }
}
