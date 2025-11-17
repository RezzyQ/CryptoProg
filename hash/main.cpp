#include <iostream>
#include <fstream>
#include <string>
#include <iomanip>
#include <cryptopp/cryptlib.h>
#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>

using namespace std;
using namespace CryptoPP;

// Функция для вычисления хэша файла с использованием SHA-256
string calculate_file_hash(const string& filename) {
    try {
        SHA256 hash;
        string digest;
        
        // Чтение файла и вычисление хэша
        FileSource file(filename.c_str(), true, 
            new HashFilter(hash,
                new HexEncoder(
                    new StringSink(digest)
                )
            )
        );
        
        return digest;
    }
    catch(const exception& e) {
        cerr << "Error calculating hash: " << e.what() << endl;
        return "";
    }
}

// Функция для вычисления хэша строки (для тестирования)
string calculate_string_hash(const string& input) {
    try {
        SHA256 hash;
        string digest;
        
        StringSource ss(input, true,
            new HashFilter(hash,
                new HexEncoder(
                    new StringSink(digest)
                )
            )
        );
        
        return digest;
    }
    catch(const exception& e) {
        cerr << "Error calculating string hash: " << e.what() << endl;
        return "";
    }
}

int main(int argc, char* argv[]) {
    // Проверка аргументов командной строки
    if (argc != 2) {
        cerr << "Usage: " << argv[0] << " <filename>" << endl;
        cerr << "Calculates SHA-256 hash of the specified file" << endl;
        return 1;
    }
    
    string filename = argv[1];
    
    // Проверка существования файла
    ifstream file(filename, ios::binary);
    if (!file.is_open()) {
        cerr << "Error: Cannot open file '" << filename << "'" << endl;
        return 1;
    }
    file.close();
    
    // Вычисление хэша
    string hash_result = calculate_file_hash(filename);
    
    if (!hash_result.empty()) {
        cout << "SHA-256 hash of '" << filename << "':" << endl;
        cout << hash_result << endl;
        return 0;
    } else {
        cerr << "Failed to calculate hash" << endl;
        return 1;
    }
}
