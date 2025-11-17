#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>

using namespace std;
using namespace CryptoPP;

// Функция чтобы сделать ключ из пароля
void makeKeyFromPassword(const string& password, byte* key, byte* iv) {
    byte salt[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    
    // Делаем ключ из пароля
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
    pbkdf.DeriveKey(key, AES::DEFAULT_KEYLENGTH, 0, 
                   (byte*)password.data(), password.size(),
                   salt, sizeof(salt), 1000);
    
    // И IV тоже из пароля
    pbkdf.DeriveKey(iv, AES::BLOCKSIZE, 0,
                   (byte*)password.data(), password.size(),
                   salt, sizeof(salt), 1000);
}

bool encryptFile(const string& inputFile, const string& outputFile, const string& password) {
    try {
        ifstream inFile(inputFile, ios::binary);
        if (!inFile) {
            cout << "Ошибка: не могу открыть файл " << inputFile << endl;
            return false;
        }
        
        // Читаем весь файл в строку
        string data;
        inFile.seekg(0, ios::end);
        long fileSize = inFile.tellg();
        data.reserve(fileSize);
        inFile.seekg(0, ios::beg);
        data.assign((istreambuf_iterator<char>(inFile)),
                    istreambuf_iterator<char>());
        inFile.close();
        
        byte key[AES::DEFAULT_KEYLENGTH];
        byte iv[AES::BLOCKSIZE];
        makeKeyFromPassword(password, key, iv);
        
        CBC_Mode<AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
        
        string encrypted;
        StringSource(data, true,
            new StreamTransformationFilter(encryptor,
                new StringSink(encrypted)
            )
        );
        
        // Сохраняем IV и зашифрованные данные
        ofstream outFile(outputFile, ios::binary);
        if (!outFile) {
            cout << "Ошибка: не могу создать файл " << outputFile << endl;
            return false;
        }
        
        // Пишем IV в начало
        outFile.write((char*)iv, sizeof(iv));
        outFile.write(encrypted.data(), encrypted.size());
        outFile.close();
        
        cout << "Файл зашифрован: " << outputFile << endl;
        cout << "Размер был: " << data.size() << " байт" << endl;
        cout << "Размер стал: " << (sizeof(iv) + encrypted.size()) << " байт" << endl;
        
        return true;
        
    } catch (exception& e) {
        cout << "Ошибка при шифровании: " << e.what() << endl;
        return false;
    }
}

// Расшифрование файла
bool decryptFile(const string& inputFile, const string& outputFile, const string& password) {
    try {
        // Читаем зашифрованный файл
        ifstream inFile(inputFile, ios::binary);
        if (!inFile) {
            cout << "Ошибка: не могу открыть файл " << inputFile << endl;
            return false;
        }
        
        byte iv[AES::BLOCKSIZE];
        inFile.read((char*)iv, sizeof(iv));
        
        // Читаем остальное - это зашифрованные данные
        string encrypted;
        inFile.seekg(0, ios::end);
        long fileSize = inFile.tellg();
        long encryptedSize = fileSize - sizeof(iv);
        encrypted.reserve(encryptedSize);
        inFile.seekg(sizeof(iv), ios::beg);
        encrypted.assign((istreambuf_iterator<char>(inFile)),
                        istreambuf_iterator<char>());
        inFile.close();
        
        // Делаем ключ из пароля
        byte key[AES::DEFAULT_KEYLENGTH];
        byte dummy_iv[AES::BLOCKSIZE];
        makeKeyFromPassword(password, key, dummy_iv);
        
        // Расшифровываем
        CBC_Mode<AES>::Decryption decryptor;
        decryptor.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
        
        string decrypted;
        StringSource(encrypted, true,
            new StreamTransformationFilter(decryptor,
                new StringSink(decrypted)
            )
        );
        
        // Сохраняем расшифрованное
        ofstream outFile(outputFile, ios::binary);
        if (!outFile) {
            cout << "Ошибка: не могу создать файл " << outputFile << endl;
            return false;
        }
        
        outFile.write(decrypted.data(), decrypted.size());
        outFile.close();
        
        cout << "Файл расшифрован: " << outputFile << endl;
        cout << "Размер: " << decrypted.size() << " байт" << endl;
        
        return true;
        
    } catch (exception& e) {
        cout << "Ошибка при расшифровании: " << e.what() << endl;
        return false;
    }
}

void showMenu() {
    cout << "\n=== Программа шифрования ===" << endl;
    cout << "1. Зашифровать файл" << endl;
    cout << "2. Расшифровать файл" << endl;
    cout << "3. Выход" << endl;
    cout << "Выберите: ";
}

int main() {
    cout << "Лабораторная работа по криптографии" << endl;
    cout << "Шифрование AES-CBC" << endl;
    
    while (true) {
        showMenu();
        
        int choice;
        cin >> choice;
        cin.ignore();
        
        if (choice == 3) {
            cout << "Выход..." << endl;
            break;
        }
        
        if (choice != 1 && choice != 2) {
            cout << "Неверный выбор!" << endl;
            continue;
        }
        
        string inputFile, outputFile, password;
        
        cout << "Входной файл: ";
        getline(cin, inputFile);
        
        cout << "Выходной файл: ";
        getline(cin, outputFile);
        
        cout << "Пароль: ";
        getline(cin, password);
        
        if (password.empty()) {
            cout << "Пароль не может быть пустым!" << endl;
            continue;
        }
        
        bool ok = false;
        if (choice == 1) {
            ok = encryptFile(inputFile, outputFile, password);
        } else {
            ok = decryptFile(inputFile, outputFile, password);
        }
        
        if (ok) {
            cout << "Успешно!" << endl;
        } else {
            cout << "Не получилось :(" << endl;
        }
    }
    
    return 0;
}
