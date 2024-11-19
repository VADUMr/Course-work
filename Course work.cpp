#include <windows.h>
#include <iostream>
#include <string>
#include <map>
#include <stdexcept>
#include <memory>

#include <aes.h>
#include <des.h>
#include <blowfish.h>
#include <modes.h>
#include <filters.h>
#include <rsa.h>
#include <osrng.h>
#include <sha.h>
#include <sha3.h>
#include <hex.h>
#include <gcm.h>
#include <dsa.h>
#include <base64.h>
#include <dsa.h>
#include <hex.h>
#include <pem.h>

using namespace std;
using namespace CryptoPP;

// Listing for AES operating modes
enum class AESMode {
    CBC,
    CTR
};

// Enumeration for hashing algorithms
enum class HashAlgorithm {
    SHA256,
    SHA3_256
};

// Enumeration for symmetric algorithms
enum class SymmetricAlgorithm {
    AES,
    DES,
    BLOWFISH
};

class Encryptor {
public:
    Encryptor() {
        AutoSeededRandomPool rng;

        // Initializing keys for different algorithms
        rng.GenerateBlock(aesKey, AES::DEFAULT_KEYLENGTH);
        rng.GenerateBlock(desKey, DES::DEFAULT_KEYLENGTH);
        rng.GenerateBlock(blowfishKey, BLOWFISH_DEFAULT_KEYLENGTH);

        // IV generation for each algorithm
        rng.GenerateBlock(aesIV, AES::BLOCKSIZE);
        rng.GenerateBlock(desIV, DES::BLOCKSIZE);
        rng.GenerateBlock(blowfishIV, Blowfish::BLOCKSIZE);

        // Generation of additional IVs for different AES modes
        rng.GenerateBlock(aesCBCIV, AES::BLOCKSIZE);
        rng.GenerateBlock(aesCTRIV, AES::BLOCKSIZE);

        // RSA key generation
        RSA::PrivateKey privateKey;
        privateKey.GenerateRandomWithKeySize(rng, 3072);
        rsaPublicKey = RSA::PublicKey(privateKey);
        rsaPrivateKey = privateKey;

        // DSA key generation
        DSA::PrivateKey dsaPrivateKey;
        dsaPrivateKey.GenerateRandomWithKeySize(rng, 2048);
        this->dsaPrivateKey = dsaPrivateKey;
        DSA::PublicKey dsaPublicKey;
        dsaPublicKey.AssignFrom(dsaPrivateKey);
        this->dsaPublicKey = dsaPublicKey;
    }

    // Methods for symmetric encryption
    string encryptSymmetric(const string& plaintext, SymmetricAlgorithm algo, AESMode mode = AESMode::CBC) {
        switch (algo) {
        case SymmetricAlgorithm::AES:
            return encryptAES(plaintext, mode);
        case SymmetricAlgorithm::DES:
            return encryptDES(plaintext);
        case SymmetricAlgorithm::BLOWFISH:
            return encryptBlowfish(plaintext);
        default:
            throw runtime_error("Unsupported algorithm");
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
            throw runtime_error("Unsupported algorithm");
        }
    }

    string encryptRSA(const string& plaintext) {
        return executeRSAEncryption(plaintext);
    }

    string decryptRSA(const string& ciphertext) {
        return executeRSADecryption(ciphertext);
    }

    string calculateHash(const string& data, HashAlgorithm algo) {
        switch (algo) {
        case HashAlgorithm::SHA256:
            return calculateSHA256(data);
        case HashAlgorithm::SHA3_256:
            return calculateSHA3(data);
        default:
            throw runtime_error("Unsupported algorithm");
        }
    }

    string signMessage(const string& message) {
        return createDigitalSignature(message);
    }

    bool verifySignature(const string& message, const string& signature) {
        return verifyDigitalSignature(message, signature);
    }

private:
    static const int BLOWFISH_DEFAULT_KEYLENGTH = 32;

    // Keys for different algorithms
    byte aesKey[AES::DEFAULT_KEYLENGTH];
    byte desKey[DES::DEFAULT_KEYLENGTH];
    byte blowfishKey[BLOWFISH_DEFAULT_KEYLENGTH];

    // IV for each algorithm
    byte aesIV[AES::BLOCKSIZE];
    byte desIV[DES::BLOCKSIZE];
    byte blowfishIV[Blowfish::BLOCKSIZE];

    // Additional IVs for different AES modes
    byte aesCBCIV[AES::BLOCKSIZE];
    byte aesCTRIV[AES::BLOCKSIZE];

    RSA::PublicKey rsaPublicKey;
    RSA::PrivateKey rsaPrivateKey;
    DSA::PublicKey dsaPublicKey;
    DSA::PrivateKey dsaPrivateKey;

    string encryptAES(const string& plaintext, AESMode mode) {
        string ciphertext;
        AutoSeededRandomPool rng;

        switch (mode) {
        case AESMode::CBC: {
            CBC_Mode<AES>::Encryption encryptor;
            encryptor.SetKeyWithIV(aesKey, sizeof(aesKey), aesCBCIV);
            StringSource(plaintext, true,
                new StreamTransformationFilter(encryptor,
                    new StringSink(ciphertext),
                    StreamTransformationFilter::PKCS_PADDING // Додаємо паддинг
                )
            );
            break;
        }
        case AESMode::CTR: {
            CTR_Mode<AES>::Encryption encryptor;
            encryptor.SetKeyWithIV(aesKey, sizeof(aesKey), aesCTRIV);
            StringSource(plaintext, true,
                new StreamTransformationFilter(encryptor,
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
            decryptor.SetKeyWithIV(aesKey, sizeof(aesKey), aesCBCIV);
            StringSource(ciphertext, true,
                new StreamTransformationFilter(decryptor,
                    new StringSink(decryptedtext),
                    StreamTransformationFilter::PKCS_PADDING // Видаляємо паддинг при дешифруванні
                )
            );
            break;
        }
        case AESMode::CTR: {
            CTR_Mode<AES>::Decryption decryptor;
            decryptor.SetKeyWithIV(aesKey, sizeof(aesKey), aesCTRIV);
            StringSource(ciphertext, true,
                new StreamTransformationFilter(decryptor,
                    new StringSink(decryptedtext)
                )
            );
            break;
        }
        }
        return decryptedtext;
    }


    string encryptDES(const string& plaintext) {
        string ciphertext;
        CBC_Mode<DES>::Encryption encryptor;
        encryptor.SetKeyWithIV(desKey, sizeof(desKey), desIV);

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
        decryptor.SetKeyWithIV(desKey, sizeof(desKey), desIV);

        StringSource(ciphertext, true,
            new StreamTransformationFilter(decryptor,
                new StringSink(decryptedtext)
            )
        );

        return decryptedtext;
    }

    string encryptBlowfish(const string& plaintext) {
        string ciphertext;
        CBC_Mode<Blowfish>::Encryption encryptor;
        encryptor.SetKeyWithIV(blowfishKey, sizeof(blowfishKey), blowfishIV);

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
        decryptor.SetKeyWithIV(blowfishKey, sizeof(blowfishKey), blowfishIV);

        StringSource(ciphertext, true,
            new StreamTransformationFilter(decryptor,
                new StringSink(decryptedtext)
            )
        );
        return decryptedtext;
    }

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

    string wrapPEMFormat(const string& encodedKey, const string& keyType) const {
        std::stringstream ss;
        ss << "-----BEGIN " << keyType << "-----\n";

        // Insert line breaks every 64 characters
        for (size_t i = 0; i < encodedKey.length(); i += 64) {
            ss << encodedKey.substr(i, 64) << "\n";
        }

        ss << "-----END " << keyType << "-----\n";
        return ss.str();
    }
    public:
        
        const byte* getAESKey() const {
            return aesKey;
        }

        const byte* getDESKey() const {
            return desKey;
        }

        const byte* getBlowfishKey() const {
            return blowfishKey;
        }

        // Getters for IVs
        const byte* getAESIV() const {
            return aesIV;
        }

        const byte* getDESIV() const {
            return desIV;
        }

        const byte* getBlowfishIV() const {
            return blowfishIV;
        }

        const byte* getAESCBCIV() const {
            return aesCBCIV;
        }

        const byte* getAESCTRIV() const {
            return aesCTRIV;
        }

        // Setters for keys (with validation)
        void setAESKey(const byte* newKey) {
            if (newKey == nullptr || strlen((const char*)newKey) != AES::DEFAULT_KEYLENGTH) {
                throw std::invalid_argument("Invalid AES key length");
            }
            memcpy(aesKey, newKey, AES::DEFAULT_KEYLENGTH);
        }

        void setDESKey(const byte* newKey, size_t newKeyLength) {
            if (newKey == nullptr || newKeyLength != DES::DEFAULT_KEYLENGTH) {
                throw std::invalid_argument("Invalid DES key length");
            }
            memcpy(desKey, newKey, newKeyLength);
        }

        void setBlowfishKey(const byte* newKey, size_t newKeyLength) {
            if (newKey == nullptr || newKeyLength != BLOWFISH_DEFAULT_KEYLENGTH) {
                throw std::invalid_argument("Invalid Blowfish key length");
            }
            memcpy(blowfishKey, newKey, newKeyLength);
        }

        // Setters for IVs (with validation)
        void setAESIV(const byte* newIV) {
            if (newIV == nullptr || strlen((const char*)newIV) != AES::BLOCKSIZE) {
                throw std::invalid_argument("Invalid AES IV length");
            }
            memcpy(aesIV, newIV, AES::BLOCKSIZE);
        }

        void setDESIV(const byte* newIV, size_t newIVLength) {
            if (newIV == nullptr || newIVLength != DES::BLOCKSIZE) {
                throw std::invalid_argument("Invalid DES IV length");
            }
            memcpy(desIV, newIV, newIVLength);
        }

        void setBlowfishIV(const byte* newIV, size_t newIVLength) {
            if (newIV == nullptr || newIVLength != Blowfish::BLOCKSIZE) {
                throw std::invalid_argument("Invalid Blowfish IV length");
            }
            memcpy(blowfishIV, newIV, newIVLength);
        }

        void setAESCBCIV(const byte* newIV, size_t newIVLength) {
            if (newIV == nullptr || newIVLength != AES::BLOCKSIZE) {
                throw std::invalid_argument("Invalid AES IV length");
            }
            memcpy(aesCBCIV, newIV, newIVLength);
        }

        void setAESCTRIV(const byte* newIV, size_t newIVLength) {
            if (newIV == nullptr || newIVLength != AES::BLOCKSIZE) {
                throw std::invalid_argument("Invalid AES CTR IV length");
            }
            memcpy(aesCTRIV, newIV, newIVLength);
        }

        // Getters for RSA and DSA keys (consider security implications)
        const RSA::PublicKey& getRSAPublicKey() const {
            return rsaPublicKey;
        }

        const RSA::PrivateKey& getRSAPrivateKey() const {
            return rsaPrivateKey;
        }

        const DSA::PublicKey& getDSAPublicKey() const {
            return dsaPublicKey;
        }

        const DSA::PrivateKey& getDSAPrivateKey() const {
            return dsaPrivateKey;
        }

        string getRSAPublicKeyPEM() const {
            string pemKey;
            StringSink sink(pemKey);
            HexEncoder encoder(new Redirector(sink));

            // Save the public key to the encoder
            rsaPublicKey.Save(encoder);
            encoder.MessageEnd();

            // Wrap in PEM format
            return wrapPEMFormat(pemKey, "RSA PUBLIC KEY");
        }

        string getRSAPrivateKeyPEM() const {
            string pemKey;
            StringSink sink(pemKey);
            HexEncoder encoder(new Redirector(sink));

            // Save the private key to the encoder
            rsaPrivateKey.Save(encoder);
            encoder.MessageEnd();

            // Wrap in PEM format
            return wrapPEMFormat(pemKey, "RSA PRIVATE KEY");
        }

        string getDSAPublicKeyPEM() const {
            string pemKey;
            StringSink sink(pemKey);
            HexEncoder encoder(new Redirector(sink));

            // Save the public key to the encoder
            dsaPublicKey.Save(encoder);
            encoder.MessageEnd();

            // Wrap in PEM format
            return wrapPEMFormat(pemKey, "DSA PUBLIC KEY");
        }

        string getDSAPrivateKeyPEM() const {
            string pemKey;
            StringSink sink(pemKey);
            HexEncoder encoder(new Redirector(sink));

            // Save the private key to the encoder
            dsaPrivateKey.Save(encoder);
            encoder.MessageEnd();

            // Wrap in PEM format
            return wrapPEMFormat(pemKey, "DSA PRIVATE KEY");
        }

        void setRSAPublicKeyFromHex(const string& hexKey) {
            try {
                string decodedKey;
                // Decode the hex string directly
                StringSource ss(hexKey, true,
                    new HexDecoder(
                        new StringSink(decodedKey)
                    )
                );

                // Load the decoded key into a ByteQueue
                ByteQueue queue;
                queue.Put((const byte*)decodedKey.data(), decodedKey.size());
                queue.MessageEnd();

                // Load the key
                rsaPublicKey.Load(queue);

                // Validate the key
                AutoSeededRandomPool rng;
                if (!rsaPublicKey.Validate(rng, 3)) {
                    throw runtime_error("Invalid RSA public key");
                }
            }
            catch (const Exception& e) {
                throw runtime_error(string("Error setting RSA public key: ") + e.what());
            }
        }

        void setRSAPrivateKeyFromHex(const string& hexKey) {
            try {
                string decodedKey;
                // Decode the hex string directly
                StringSource ss(hexKey, true,
                    new HexDecoder(
                        new StringSink(decodedKey)
                    )
                );

                // Load the decoded key into a ByteQueue
                ByteQueue queue;
                queue.Put((const byte*)decodedKey.data(), decodedKey.size());
                queue.MessageEnd();

                // Load the key
                rsaPrivateKey.Load(queue);

                // Validate the key
                AutoSeededRandomPool rng;
                if (!rsaPrivateKey.Validate(rng, 3)) {
                    throw runtime_error("Invalid RSA private key");
                }
            }
            catch (const Exception& e) {
                throw runtime_error(string("Error setting RSA private key: ") + e.what());
            }
        }
};

enum elements_id {
    button_encrypt = 1,
    button_decrypt,
    edit_input,
    edit_output,
    combo_algorithm,
    combo_mode,
    combo_switch,
    combo_additional,
    edit_input_key,
    button_get_set_key
};

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    static HWND HWND_button_encrypt, HWND_button_decrypt, HWND_edit_input,
        HWND_edit_output, HWND_combo_algorithm, HWND_combo_mode,
        HWND_edit_input_key, HWND_combo_additional, HWND_combo_switch, HWND_button_get_set_key;
    static Encryptor encryptor;

    switch (uMsg) {
    case WM_CREATE: {
        
        HWND_edit_input = CreateWindowW(L"edit", L"Введіть повідомлення яке хочете зашифрувати",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL,
            10, 10, 600, 200, hwnd, (HMENU)edit_input, NULL, NULL);

        HWND_combo_algorithm = CreateWindowW(L"ComboBox", L"",
            CBS_DROPDOWNLIST | WS_CHILD | WS_VISIBLE,
            10, 220, 200, 200, hwnd, (HMENU)combo_algorithm, NULL, NULL);

        HWND_combo_mode = CreateWindowW(L"ComboBox", L"",
            CBS_DROPDOWNLIST | WS_CHILD | WS_VISIBLE,
            220, 220, 200, 200, hwnd, (HMENU)combo_mode, NULL, NULL);

        HWND_button_encrypt = CreateWindowW(L"button", L"Encrypt",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            10, 450, 150, 50, hwnd, (HMENU)button_encrypt, NULL, NULL);

        HWND_button_decrypt = CreateWindowW(L"button", L"Decrypt",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            170, 450, 150, 50, hwnd, (HMENU)button_decrypt, NULL, NULL);

        HWND_edit_output = CreateWindowW(L"edit", L"Тут виведеться зашифроване повідомлення у Hex форматі",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
            650, 10, 700, 200, hwnd, (HMENU)edit_output, NULL, NULL);

        HWND_combo_switch = CreateWindowW(L"ComboBox", L"",
            CBS_DROPDOWNLIST | WS_CHILD | WS_VISIBLE,
            500, 220, 200, 200, hwnd, (HMENU)combo_switch, NULL, NULL);

        HWND_combo_additional = CreateWindowW(L"ComboBox", L"",
            CBS_DROPDOWNLIST | WS_CHILD | WS_VISIBLE,
            500, 300, 200, 400, hwnd, (HMENU)combo_additional, NULL, NULL);

        HWND_edit_input_key = CreateWindowW(L"edit", L"Це вікно для управління ключами для шифрування",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL,
            730, 220, 650, 350, hwnd, (HMENU)edit_input_key, NULL, NULL);

        HWND_button_get_set_key = CreateWindowW(L"button", L"Get/Set Key",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            330, 450, 150, 50, hwnd, (HMENU)button_get_set_key, NULL, NULL);

        SendMessageW(HWND_combo_switch, CB_ADDSTRING, 0, (LPARAM)L"GET");
        SendMessageW(HWND_combo_switch, CB_ADDSTRING, 0, (LPARAM)L"SET");
        SendMessageW(HWND_combo_switch, CB_SETCURSEL, 0, 0);

        SendMessageW(HWND_combo_additional, CB_ADDSTRING, 0, (LPARAM)L"aesKey");
        SendMessageW(HWND_combo_additional, CB_ADDSTRING, 0, (LPARAM)L"desKey");
        SendMessageW(HWND_combo_additional, CB_ADDSTRING, 0, (LPARAM)L"blowfishKey");
        SendMessageW(HWND_combo_additional, CB_ADDSTRING, 0, (LPARAM)L"aesIV");
        SendMessageW(HWND_combo_additional, CB_ADDSTRING, 0, (LPARAM)L"desIV");
        SendMessageW(HWND_combo_additional, CB_ADDSTRING, 0, (LPARAM)L"blowfishIV");
        SendMessageW(HWND_combo_additional, CB_ADDSTRING, 0, (LPARAM)L"aesCBCIV");
        SendMessageW(HWND_combo_additional, CB_ADDSTRING, 0, (LPARAM)L"aesCTRIV");
        SendMessageW(HWND_combo_additional, CB_ADDSTRING, 0, (LPARAM)L"RSA_Private");
        SendMessageW(HWND_combo_additional, CB_ADDSTRING, 0, (LPARAM)L"RSA_Public");
        SendMessageW(HWND_combo_additional, CB_SETCURSEL, 0, 0);

        SendMessageW(HWND_combo_algorithm, CB_ADDSTRING, 0, (LPARAM)L"AES");
        SendMessageW(HWND_combo_algorithm, CB_ADDSTRING, 0, (LPARAM)L"DES");
        SendMessageW(HWND_combo_algorithm, CB_ADDSTRING, 0, (LPARAM)L"Blowfish");
        SendMessageW(HWND_combo_algorithm, CB_ADDSTRING, 0, (LPARAM)L"RSA");
        SendMessageW(HWND_combo_algorithm, CB_SETCURSEL, 0, 0);

        SendMessageW(HWND_combo_mode, CB_ADDSTRING, 0, (LPARAM)L"CBC");
        SendMessageW(HWND_combo_mode, CB_ADDSTRING, 0, (LPARAM)L"CTR");
        SendMessageW(HWND_combo_mode, CB_SETCURSEL, 0, 0);
        break;
    }
    case WM_COMMAND: {
        if (HIWORD(wParam) == CBN_SELCHANGE && LOWORD(wParam) == combo_algorithm) {
            // Get selected index in algorithm combo box
            int index = SendMessageW(HWND_combo_algorithm, CB_GETCURSEL, 0, 0);

            // If "AES" is selected, show the mode combo box
            if (index == 0) { // AES is at index 0
                ShowWindow(HWND_combo_mode, SW_SHOW);
            }
            else {
                // Hide the mode combo box for other algorithms
                ShowWindow(HWND_combo_mode, SW_HIDE);
            }
        }
        if (LOWORD(wParam) == button_get_set_key) {
            int algIndex = SendMessageW(HWND_combo_switch, CB_GETCURSEL, 0, 0);
            int algorithmType = SendMessageW(HWND_combo_additional, CB_GETCURSEL, 0, 0);

            if (algIndex == 1) {  // "SET"
                // Отримання тексту з поля введення
                int textLength = GetWindowTextLengthW(HWND_edit_input_key);
                std::wstring inputText(textLength + 1, L'\0');
                GetWindowTextW(HWND_edit_input_key, &inputText[0], textLength + 1);

                // Конвертація з UTF-16 в UTF-8
                std::string inputStr;
                int utf8Length = WideCharToMultiByte(CP_UTF8, 0, inputText.c_str(), -1, nullptr, 0, nullptr, nullptr);
                if (utf8Length > 0) {
                    std::vector<char> utf8Str(utf8Length);
                    WideCharToMultiByte(CP_UTF8, 0, inputText.c_str(), -1, utf8Str.data(), utf8Length, nullptr, nullptr);
                    inputStr = std::string(utf8Str.data());
                }

                if (!inputStr.empty()) {

                    std::string decodedInput;
                    StringSource(inputStr, true,
                        new HexDecoder(
                            new StringSink(decodedInput)
                        )
                    );
                    switch (algorithmType) {
                    case 0:  // aesKey
                        encryptor.setAESKey((const byte*)decodedInput.c_str());
                        break;
                    case 1:  // desKey
                        encryptor.setDESKey((const byte*)decodedInput.c_str(), decodedInput.size());
                        break;
                    case 2:  // blowfishKey
                        encryptor.setBlowfishKey((const byte*)decodedInput.c_str(), decodedInput.size());
                        break;
                    case 3:  // aesIV
                        encryptor.setAESIV((const byte*)decodedInput.c_str());
                        break;
                    case 4:  // desIV
                        encryptor.setDESIV((const byte*)decodedInput.c_str(), decodedInput.size());
                        break;
                    case 5:  // blowfishIV
                        encryptor.setBlowfishIV((const byte*)decodedInput.c_str(), decodedInput.size());
                        break;
                    case 6:  // aesCBCIV
                        encryptor.setAESCBCIV((const byte*)decodedInput.c_str(), decodedInput.size());
                        break;
                    case 7:  // aesCTRIV
                        encryptor.setAESCTRIV((const byte*)decodedInput.c_str(), decodedInput.size());
                        break;
                    case 8:  // RSA_Private_key
                        encryptor.setRSAPrivateKeyFromHex(decodedInput.c_str());
                        break;
                    case 9:  // RSA_Public_key
                        encryptor.setRSAPublicKeyFromHex(decodedInput.c_str());
                        break;
                    }
                }
            }
            else if (algIndex == 0) {  // "GET"
                std::string result;

                switch (algorithmType) {
                case 0:  // aesKey
                    result = std::string((char*)encryptor.getAESKey(), AES::DEFAULT_KEYLENGTH);
                    break;
                case 1:  // desKey
                    result = std::string((char*)encryptor.getDESKey(), DES::DEFAULT_KEYLENGTH);
                    break;
                case 2:  // blowfishKey
                    result = std::string((char*)encryptor.getBlowfishKey(), 32);
                    break;
                case 3:  // aesIV
                    result = std::string((char*)encryptor.getAESIV(), AES::BLOCKSIZE);
                    break;
                case 4:  // desIV
                    result = std::string((char*)encryptor.getDESIV(), DES::BLOCKSIZE);
                    break;
                case 5:  // blowfishIV
                    result = std::string((char*)encryptor.getBlowfishIV(), Blowfish::BLOCKSIZE);
                    break;
                case 6:  // aesCBCIV
                    result = std::string((char*)encryptor.getAESCBCIV(), AES::BLOCKSIZE);
                    break;
                case 7:  // aesCTRIV
                    result = std::string((char*)encryptor.getAESCTRIV(), AES::BLOCKSIZE);
                    break;
                case 8:  // RSA_Private_key
                    result = std::string(encryptor.getRSAPrivateKeyPEM());
                    break;
                case 9:  // RSA_Public_key
                    result = std::string(encryptor.getRSAPublicKeyPEM());
                    break;
                }

                std::string hexResult;
                StringSource(result, true,
                    new HexEncoder(
                        new StringSink(hexResult)
                    )
                );

                // Конвертація hex string в wide string для відображення
                std::wstring wResult(hexResult.begin(), hexResult.end());
                SetWindowTextW(HWND_edit_input_key, wResult.c_str());
            }
        }
        if (LOWORD(wParam) == button_encrypt || LOWORD(wParam) == button_decrypt) {
            // Отримання тексту з вхідного поля
            int textLength = GetWindowTextLengthW(HWND_edit_input);
            std::wstring inputText(textLength + 1, L'\0');
            GetWindowTextW(HWND_edit_input, &inputText[0], textLength + 1);

            //Перетворення з UTF-16 (wstring) в UTF-8 (string)
            std::string inputStr;
            int utf8Length = WideCharToMultiByte(CP_UTF8, 0, inputText.c_str(), -1, nullptr, 0, nullptr, nullptr);
            if (utf8Length > 0) {
                std::vector<char> utf8Str(utf8Length);
                WideCharToMultiByte(CP_UTF8, 0, inputText.c_str(), -1, utf8Str.data(), utf8Length, nullptr, nullptr);
                inputStr = std::string(utf8Str.data());
            }

            // Отримання вибраного алгоритму
            int algIndex = SendMessageW(HWND_combo_algorithm, CB_GETCURSEL, 0, 0);

            // Отримання вибраного режиму (для AES)
            AESMode mode = AESMode::CBC;
            if (algIndex == 0) { // AES
                int modeIndex = SendMessageW(HWND_combo_mode, CB_GETCURSEL, 0, 0);
                mode = (modeIndex == 0) ? AESMode::CBC : AESMode::CTR;
            }

            try {
                std::string result;
                if (LOWORD(wParam) == button_encrypt) {
                    switch (algIndex) {
                    case 0: // AES
                    case 1: // DES
                    case 2: // BLOWFISH
                        result = encryptor.encryptSymmetric(inputStr, static_cast<SymmetricAlgorithm>(algIndex), mode);
                        break;
                    case 3: // RSA
                        result = encryptor.encryptRSA(inputStr);
                        break;
                    }
                    // Конвертація зашифрованих даних в hex для відображення
                    std::string hexResult;
                    StringSource(result, true,
                        new HexEncoder(
                            new StringSink(hexResult)
                        )
                    );

                    // Конвертація hex string в wide string для відображення
                    std::wstring wResult(hexResult.begin(), hexResult.end());
                    SetWindowTextW(HWND_edit_output, wResult.c_str());
                }
                else {
                    // Перед дешифруванням, конвертуємо hex назад у бінарні дані
                    std::string decodedInput;
                    StringSource(inputStr, true,
                        new HexDecoder(
                            new StringSink(decodedInput)
                        )
                    );

                    switch (algIndex) {
                    case 0: // AES
                    case 1: // DES
                    case 2: // BLOWFISH
                        result = encryptor.decryptSymmetric(decodedInput, static_cast<SymmetricAlgorithm>(algIndex), mode);
                        break;
                    case 3: // RSA
                        result = encryptor.decryptRSA(decodedInput);
                        break;
                    }
                    // Після дешифрування, конвертуємо результат в wide string
                    std::wstring wResult;
                    int wideLength = MultiByteToWideChar(CP_UTF8, 0, result.c_str(), -1, nullptr, 0);
                    if (wideLength > 0) {
                        std::vector<wchar_t> wideStr(wideLength);
                        MultiByteToWideChar(CP_UTF8, 0, result.c_str(), -1, wideStr.data(), wideLength);
                        wResult = std::wstring(wideStr.data());
                    }
                    SetWindowTextW(HWND_edit_output, wResult.c_str());
                }            
            }
            catch (const std::exception& e) {
                // Обробка помилок
                std::string errorMsg = "Error: ";
                errorMsg += e.what();
                std::wstring wErrorMsg(errorMsg.begin(), errorMsg.end());
                SetWindowTextW(HWND_edit_output, wErrorMsg.c_str());
            }
        }
        break;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

int main() {
   
    WNDCLASSW wc;
    memset(&wc, 0, sizeof(WNDCLASSA));
    wc.lpfnWndProc = WindowProc;
    wc.lpszClassName = L"EncryptionToolClass";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClassW(&wc);

    HWND hwnd = CreateWindowW(L"EncryptionToolClass", L"Encryption Tool",
        WS_OVERLAPPEDWINDOW, 0, 0, 1400, 700,
        NULL, NULL, NULL, NULL);

    ShowWindow(hwnd, SW_SHOWNORMAL);
    UpdateWindow(hwnd);

    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}