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

//CREADO POR LUCAS CALZADA (mentira: chat gpt)
/*
* INSTRUCCIONES:
* 1.Crea un fichero que se llame como el bloque que te toque, ejemplo: bloque9.txt
* 2.Introduce la ruta del archivo en la variable constante de abajo
* 3.Introduce los demas datos
* 4.Voala!, solo te toca esperar a que te lo calcule, suerte!!!
*/
const std::string NOMBRE_APELLIDOS = "Lucas Calzada del Pozo";
const std::string HASH_PREVIO = "03b7855790895f440bd6b830b8155a5afe7d4cb6db1c7ba985f827add1923395";
const std::string EMPIEZA_POR = "03b";
const std::string RUTA_ARCHIVO = "C:/Users/Lucas/Desktop/bloque9.txt";


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
    // Utilizamos expresiones regulares para buscar y reemplazar el valor del nonce y los datos personales
    std::regex regexNonce("Nonce: (\\d+)");
    std::regex regexNombre("Nombre y Apellidos: (.+)");
    std::regex regexHashPrevio("Hash \\(previo\\): (.+)");

    std::string replacementNonce = "Nonce: " + std::to_string(newNonce);
    std::string replacementNombre = "Nombre y Apellidos: " + NOMBRE_APELLIDOS;
    std::string replacementHashPrevio = "Hash (previo): " + HASH_PREVIO;

    std::string updatedContent = std::regex_replace(originalContent, regexNonce, replacementNonce);
    updatedContent = std::regex_replace(updatedContent, regexNombre, replacementNombre);
    updatedContent = std::regex_replace(updatedContent, regexHashPrevio, replacementHashPrevio);

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

    return true;
}
bool readWholeFile(const std::string& filename, std::string& fileContent) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "No se pudo abrir el archivo." << std::endl;
        return false;
    }

    fileContent.assign((std::istreambuf_iterator<char>(file)), (std::istreambuf_iterator<char>()));
    file.close();
    return true;
}

bool writeToFile(const std::string& filename, const std::string& content) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        std::cerr << "No se pudo abrir el archivo para escritura." << std::endl;
        return false;
    }

    file << content;
    file.close();
    return true;
}


int main() {
    std::string filename = RUTA_ARCHIVO;
    bool loop = true;
    int nonce = 0;

    std::string fileContent;
    if (readWholeFile(filename, fileContent)) {
        std::cout << "Archivo leído exitosamente." << std::endl;
    }
    else {
        std::cerr << "Error al leer el archivo." << std::endl;
        return 1;
    }

    updateNonceInFile(filename, nonce);

    std::cout << "Calculando el nonce del archivo '" << filename << "':" << std::endl;
    while (loop) {
        // Calcular el hash SHA-256
        std::string hash = calculateSHA256(filename);

        if (!hash.empty()) {
            if (hash.compare(0, 3, EMPIEZA_POR) == 0) {
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

    std::cout << "[-]: NO SE HA ENCONTRADO EL NONCE, SALIENDO..." << std::endl;
    return 0;
}




