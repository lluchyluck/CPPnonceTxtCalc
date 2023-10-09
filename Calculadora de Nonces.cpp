#include <iostream>
#include <Windows.h>
#include <Wincrypt.h>
#include <fstream>
#include <vector>
#include <iomanip>
#include <sstream>
#include <regex>

#pragma comment(lib, "Crypt32.lib")

const DWORD SHA256_DIGEST_LENGTH = 32;  // Tamaño del hash SHA-256 en bytes

std::string calculateSHA256(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        std::cerr << "No se pudo abrir el archivo." << std::endl;
        return "";
    }

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE hash[SHA256_DIGEST_LENGTH];
    DWORD hashSize = SHA256_DIGEST_LENGTH;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "Error al adquirir el contexto de criptografía." << std::endl;
        file.close();
        return "";
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        std::cerr << "Error al crear el objeto hash." << std::endl;
        CryptReleaseContext(hProv, 0);
        file.close();
        return "";
    }

    // Leer todo el contenido del archivo
    std::ostringstream oss;
    oss << file.rdbuf();
    std::string fileContent = oss.str();

    CryptHashData(hHash, reinterpret_cast<const BYTE*>(fileContent.c_str()), static_cast<DWORD>(fileContent.size()), 0);

    file.close();

    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashSize, 0)) {
        std::cerr << "Error al obtener el valor del hash." << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    std::stringstream hashStream;
    hashStream << std::hex << std::setfill('0');
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        hashStream << std::setw(2) << static_cast<int>(hash[i]);
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return hashStream.str();
}

std::string generateUpdatedFileContent(const std::string& originalContent, int newNonce) {
    // Utilizamos una expresión regular para buscar y reemplazar el valor del nonce
    std::regex regexNonce("Nonce: (\\d+)");
    std::string replacement = "Nonce: " + std::to_string(newNonce);
    std::string updatedContent = std::regex_replace(originalContent, regexNonce, replacement);

    return updatedContent;
}

bool updateNonceInFile(const std::string& filename, int newNonce) {
    std::ifstream fileInput(filename);
    if (!fileInput.is_open()) {
        std::cerr << "No se pudo abrir el archivo." << std::endl;
        return false;
    }

    std::string fileContent((std::istreambuf_iterator<char>(fileInput)), (std::istreambuf_iterator<char>()));
    fileInput.close();

    // Generar el contenido actualizado con el nuevo nonce
    std::string updatedContent = generateUpdatedFileContent(fileContent, newNonce);

    std::ofstream fileOutput(filename);
    if (!fileOutput.is_open()) {
        std::cerr << "No se pudo abrir el archivo para escritura." << std::endl;
        return false;
    }

    // Escribir el contenido actualizado en el archivo
    fileOutput << updatedContent;
    fileOutput.close();

    std::cout << "Nonce actualizado en el archivo." << std::endl;

    return true;
}


int main() {
    std::string filename = "C:/Users/Lucas/Desktop/bloque9.txt";
    bool loop = true;
    int nonce = 0;

    updateNonceInFile(filename, nonce);

    std::cout << "Calculando el nonce del archivo '" << filename << "':" << std::endl;
    while (loop) {
        // Calcular el hash SHA-256
        std::string hash = calculateSHA256(filename);



        if (!hash.empty()) {
            if (hash.compare(0, 3, "03b") == 0) {
                
                loop = false;
                std::cout << "HASH ENCONTRADO!!: " << hash << std::endl;
                std::cout << "NONCE ENCONTRADO!!: " << nonce << std::endl;
                return 0;
            }         
            std::cout << hash << std::endl; 
            nonce++;
            updateNonceInFile(filename, nonce);
        }

             
    }
    std::cout << "[-]: NO SE HA ENCONTRADO EL NONCE SALIENDO!!!" << std::endl;
    return 0;
}
