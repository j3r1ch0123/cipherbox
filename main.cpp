#include "cipherbox.cpp"
#include <iostream>
#include <string>
#include <fstream>

using namespace std;
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
        cout << "What would you like to save the encrypted file as? " << endl; // Be sure to use a different file name, it doesn't save over well for some reason
        cin >> outfile;

        cipher.encryptFile(file, outfile, key);

        return 0;
    }
    
    else if (choice == 'd') {
        string file;
        cout << "Enter the name of the file you want to decrypt: " << endl;
        cin >> file;
        
        string outfile;
        cout << "What would you like to save the decrypted file as? " << endl; // See above comment
        cin >> outfile;

        cipher.decryptFile(file, outfile, key);
        
        return 0;
    }

    else {
        cout << "Please enter either 'e' or 'd' " << endl;
    }
    
    return 0;
}
