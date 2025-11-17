#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/cryptlib.h>
#include <cryptopp/sha.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>

using namespace std;
using namespace CryptoPP;

int main(int argc, char* argv[]) {
    string filename;
    
    if (argc != 2) {
        cout << "Какой файл хочешь захэшировать? ";
        getline(cin, filename);
        
        if (filename.empty()) {
            cout << "Name: SHA-256" << endl;
            cout << "Digest size: " << SHA256::DIGESTSIZE << endl;
            cout << "Block size: " << SHA256::BLOCKSIZE << endl;
            
            string message = "walkin' through my castle";
            cout << "Message: " << message << endl;
            
            SHA256 hash;
            string result;
            StringSource(message, true,
                new HashFilter(hash,
                    new HexEncoder(
                        new StringSink(result),
                        false
                    )
                )
            );
            
            cout << "Digest: " << result << endl;
            return 0;
        }
    } else {
        filename = argv[1];
    }
    
    // проверяем что файл есть
    ifstream file(filename);
    if (!file) {
        cout << "Ой, файл '" << filename << "' не найден!" << endl;
        cout << "Может, опечатался?" << endl;
        return 1;
    }
    file.close();
    
    // вычисляем хэш файла
    try {
        SHA256 hash;
        string result;
        
        FileSource(filename.c_str(), true,
            new HashFilter(hash,
                new HexEncoder(
                    new StringSink(result),
                    false
                )
            )
        );
        
        cout << "Name: SHA-256" << endl;
        cout << "Digest size: " << SHA256::DIGESTSIZE << endl;
        cout << "Block size: " << SHA256::BLOCKSIZE << endl;
        cout << "File: " << filename << endl;
        cout << "Digest: " << result << endl;
        
    } catch(const exception& e) {
        cout << "Ошибка: " << e.what() << endl;
        return 1;
    }
    
    return 0;
}
