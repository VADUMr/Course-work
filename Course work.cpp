#include <iostream>
#include <string>
#include <map>
#include <stdexcept>
#include <memory>

// Crypto++ включення
#include <cryptopp/aes.h>
#include <cryptopp/des.h>
#include <cryptopp/blowfish.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#include <cryptopp/hex.h>
#include <cryptopp/gcm.h>
#include <cryptopp/dsa.h>
#include <cryptopp/base64.h>

using namespace std;
using namespace CryptoPP;

// Перелічення для режимів роботи AES
enum class AESMode {
    CBC,
    CTR,
    GCM
};

// Перелічення для алгоритмів хешування
enum class HashAlgorithm {
    SHA256,
    SHA3_256
};

// Перелічення для симетричних алгоритмів
enum class SymmetricAlgorithm {
    AES,
    DES,
    BLOWFISH
};

class Encryptor {
public:
    // Конструктор з розширеною ініціалізацією
    Encryptor() {
        AutoSeededRandomPool rng;

        // Ініціалізація ключів для різних алгоритмів
        rng.GenerateBlock(aesKey, AES::DEFAULT_KEYLENGTH);
        rng.GenerateBlock(desKey, DES::DEFAULT_KEYLENGTH);
        rng.GenerateBlock(blowfishKey, BLOWFISH_DEFAULT_KEYLENGTH);

        // Генерація RSA ключів
        RSA::PrivateKey privateKey;
        privateKey.GenerateRandomWithKeySize(rng, 3072);
        rsaPublicKey = RSA::PublicKey(privateKey);
        rsaPrivateKey = privateKey;

        // Генерація DSA ключів
        DSA::PrivateKey dsaPrivateKey;
        dsaPrivateKey.GenerateRandomWithKeySize(rng, 2048);
        dsaPublicKey = DSA::PublicKey(dsaPrivateKey);
        this->dsaPrivateKey = dsaPrivateKey;
    }

    // Методи для симетричного шифрування
    string encryptSymmetric(const string& plaintext, SymmetricAlgorithm algo, AESMode mode = AESMode::CBC) {
        switch (algo) {
        case SymmetricAlgorithm::AES:
            return encryptAES(plaintext, mode);
        case SymmetricAlgorithm::DES:
            return encryptDES(plaintext);
        case SymmetricAlgorithm::BLOWFISH:
            return encryptBlowfish(plaintext);
        default:
            throw runtime_error("Непідтримуваний алгоритм");
        }
    }

    string decryptSymmetric(const string& ciphertext, SymmetricAlgorithm algo, AESMode mode = AESMode::CBC) {
        switch (algo) {
        case SymmetricAlgorithm::AES:
            return decryptAES(ciphertext, mode);
        case SymmetricAlgorithm::DES:
            return decryptDES(ciphertext);
        case SymmetricAlgorithm::BLOWFISH:
            return decryptBlowfish(ciphertext);
        default:
            throw runtime_error("Непідтримуваний алгоритм");
        }
    }

    // RSA шифрування/дешифрування
    string encryptRSA(const string& plaintext) {
        return executeRSAEncryption(plaintext);
    }

    string decryptRSA(const string& ciphertext) {
        return executeRSADecryption(ciphertext);
    }

    // Методи хешування
    string calculateHash(const string& data, HashAlgorithm algo) {
        switch (algo) {
        case HashAlgorithm::SHA256:
            return calculateSHA256(data);
        case HashAlgorithm::SHA3_256:
            return calculateSHA3(data);
        default:
            throw runtime_error("Непідтримуваний алгоритм хешування");
        }
    }

    // Методи для цифрового підпису
    string signMessage(const string& message) {
        return createDigitalSignature(message);
    }

    bool verifySignature(const string& message, const string& signature) {
        return verifyDigitalSignature(message, signature);
    }

private:
    // Константи для розмірів ключів
    static const int BLOWFISH_DEFAULT_KEYLENGTH = 32;

    // Ключі для різних алгоритмів
    byte aesKey[AES::DEFAULT_KEYLENGTH];
    byte desKey[DES::DEFAULT_KEYLENGTH];
    byte blowfishKey[BLOWFISH_DEFAULT_KEYLENGTH];
    RSA::PublicKey rsaPublicKey;
    RSA::PrivateKey rsaPrivateKey;
    DSA::PublicKey dsaPublicKey;
    DSA::PrivateKey dsaPrivateKey;

    // AES шифрування з різними режимами
    string encryptAES(const string& plaintext, AESMode mode) {
        string ciphertext;
        AutoSeededRandomPool rng;
        byte iv[AES::BLOCKSIZE];
        rng.GenerateBlock(iv, AES::BLOCKSIZE);

        switch (mode) {
        case AESMode::CBC: {
            CBC_Mode<AES>::Encryption encryptor;
            encryptor.SetKeyWithIV(aesKey, sizeof(aesKey), iv);
            StringSource(plaintext, true,
                new StreamTransformationFilter(encryptor,
                    new StringSink(ciphertext)
                )
            );
            break;
        }
        case AESMode::CTR: {
            CTR_Mode<AES>::Encryption encryptor;
            encryptor.SetKeyWithIV(aesKey, sizeof(aesKey), iv);
            StringSource(plaintext, true,
                new StreamTransformationFilter(encryptor,
                    new StringSink(ciphertext)
                )
            );
            break;
        }
        case AESMode::GCM: {
            GCM<AES>::Encryption encryptor;
            encryptor.SetKeyWithIV(aesKey, sizeof(aesKey), iv, sizeof(iv));
            StringSource(plaintext, true,
                new AuthenticatedEncryptionFilter(encryptor,
                    new StringSink(ciphertext)
                )
            );
            break;
        }
        }
        return ciphertext;
    }

    string decryptAES(const string& ciphertext, AESMode mode) {
        string decryptedtext;
        switch (mode) {
        case AESMode::CBC: {
            CBC_Mode<AES>::Decryption decryptor;
            decryptor.SetKeyWithIV(aesKey, sizeof(aesKey), nullptr);
            StringSource(ciphertext, true,
                new StreamTransformationFilter(decryptor,
                    new StringSink(decryptedtext)
                )
            );
            break;
        }
        case AESMode::CTR: {
            CTR_Mode<AES>::Decryption decryptor;
            decryptor.SetKeyWithIV(aesKey, sizeof(aesKey), nullptr);
            StringSource(ciphertext, true,
                new StreamTransformationFilter(decryptor,
                    new StringSink(decryptedtext)
                )
            );
            break;
        }
        case AESMode::GCM: {
            GCM<AES>::Decryption decryptor;
            decryptor.SetKeyWithIV(aesKey, sizeof(aesKey), nullptr, 0);
            StringSource(ciphertext, true,
                new AuthenticatedDecryptionFilter(decryptor,
                    new StringSink(decryptedtext)
                )
            );
            break;
        }
        }
        return decryptedtext;
    }

    // DES шифрування
    string encryptDES(const string& plaintext) {
        string ciphertext;
        CBC_Mode<DES>::Encryption encryptor;
        encryptor.SetKey(desKey, sizeof(desKey));

        StringSource(plaintext, true,
            new StreamTransformationFilter(encryptor,
                new StringSink(ciphertext)
            )
        );
        return ciphertext;
    }

    string decryptDES(const string& ciphertext) {
        string decryptedtext;
        CBC_Mode<DES>::Decryption decryptor;
        decryptor.SetKey(desKey, sizeof(desKey));

        StringSource(ciphertext, true,
            new StreamTransformationFilter(decryptor,
                new StringSink(decryptedtext)
            )
        );
        return decryptedtext;
    }

    // Blowfish шифрування
    string encryptBlowfish(const string& plaintext) {
        string ciphertext;
        CBC_Mode<Blowfish>::Encryption encryptor;
        encryptor.SetKey(blowfishKey, sizeof(blowfishKey));

        StringSource(plaintext, true,
            new StreamTransformationFilter(encryptor,
                new StringSink(ciphertext)
            )
        );
        return ciphertext;
    }

    string decryptBlowfish(const string& ciphertext) {
        string decryptedtext;
        CBC_Mode<Blowfish>::Decryption decryptor;
        decryptor.SetKey(blowfishKey, sizeof(blowfishKey));

        StringSource(ciphertext, true,
            new StreamTransformationFilter(decryptor,
                new StringSink(decryptedtext)
            )
        );
        return decryptedtext;
    }

    // RSA шифрування/дешифрування
    string executeRSAEncryption(const string& plaintext) {
        string ciphertext;
        AutoSeededRandomPool rng;

        RSAES_OAEP_SHA_Encryptor encryptor(rsaPublicKey);
        StringSource(plaintext, true,
            new PK_EncryptorFilter(rng, encryptor,
                new StringSink(ciphertext)
            )
        );
        return ciphertext;
    }

    string executeRSADecryption(const string& ciphertext) {
        string decryptedtext;
        AutoSeededRandomPool rng;

        RSAES_OAEP_SHA_Decryptor decryptor(rsaPrivateKey);
        StringSource(ciphertext, true,
            new PK_DecryptorFilter(rng, decryptor,
                new StringSink(decryptedtext)
            )
        );
        return decryptedtext;
    }

    // Методи хешування
    string calculateSHA256(const string& data) {
        string digest;
        SHA256 hash;

        StringSource(data, true,
            new HashFilter(hash,
                new HexEncoder(
                    new StringSink(digest)
                )
            )
        );
        return digest;
    }

    string calculateSHA3(const string& data) {
        string digest;
        SHA3_256 hash;

        StringSource(data, true,
            new HashFilter(hash,
                new HexEncoder(
                    new StringSink(digest)
                )
            )
        );
        return digest;
    }

    // Цифровий підпис
    string createDigitalSignature(const string& message) {
        string signature;
        AutoSeededRandomPool rng;

        DSA::Signer signer(dsaPrivateKey);
        StringSource(message, true,
            new SignerFilter(rng, signer,
                new StringSink(signature)
            )
        );
        return signature;
    }

    bool verifyDigitalSignature(const string& message, const string& signature) {
        bool result = false;
        DSA::Verifier verifier(dsaPublicKey);

        StringSource(signature + message, true,
            new SignatureVerificationFilter(verifier,
                new ArraySink((byte*)&result, sizeof(result))
            )
        );
        return result;
    }
};

// Приклад використання
int main() {
    try {
        Encryptor encryptor;
        string message = "Тестове повідомлення для шифрування";

        cout << "Оригінальне повідомлення: " << message << endl << endl;

        // Тестування різних режимів AES
        cout << "=== AES Шифрування ===" << endl;
        string aesEncryptedCBC = encryptor.encryptSymmetric(message, SymmetricAlgorithm::AES, AESMode::CBC);
        string aesDecryptedCBC = encryptor.decryptSymmetric(aesEncryptedCBC, SymmetricAlgorithm::AES, AESMode::CBC);
        cout << "AES CBC режим - дешифроване: " << aesDecryptedCBC << endl;

        string aesEncryptedCTR = encryptor.encryptSymmetric(message, SymmetricAlgorithm::AES, AESMode::CTR);
        string aesDecryptedCTR = encryptor.decryptSymmetric(aesEncryptedCTR, SymmetricAlgorithm::AES, AESMode::CTR);
        cout << "AES CTR режим - дешифроване: " << aesDecryptedCTR << endl;

        // Тестування DES
        cout << "\n=== DES Шифрування ===" << endl;
        string desEncrypted = encryptor.encryptSymmetric(message, SymmetricAlgorithm::DES);
        string desDecrypted = encryptor.decryptSymmetric(desEncrypted, SymmetricAlgorithm::DES);
        cout << "DES - дешифроване: " << desDecrypted << endl;

        // Тестування Blowfish
        cout << "\n=== Blowfish Шифрування ===" << endl;
        string blowfishEncrypted = encryptor.encryptSymmetric(message, SymmetricAlgorithm::BLOWFISH);
        string blowfishDecrypted = encryptor.decryptSymmetric(blowfishEncrypted, SymmetricAlgorithm::BLOWFISH);
        cout << "Blowfish - дешифроване: " << blowfishDecrypted << endl;

        // Тестування хешування
        cout << "\n=== Хешування ===" << endl;
        string sha256Hash = enc