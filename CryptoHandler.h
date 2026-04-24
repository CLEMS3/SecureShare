#ifndef CRYPTO_HANDLER_H
#define CRYPTO_HANDLER_H

#include <vector>
#include <string>
#include <cstdint>
#include <openssl/evp.h>

class CryptoHandler {
public:
    CryptoHandler();
    ~CryptoHandler();

    // DH Key Exchange (ECDH)
    bool generateECDHKeyPair();
    std::vector<uint8_t> getPublicKey() const;
    bool computeSharedSecret(const std::vector<uint8_t>& peerPublicKeyDER);

    // Symmetric Encryption (AES-256-GCM)
    // The shared secret is automatically used as the key if it was computed.
    // IV (12 bytes) is prepended, and the GCM authentication tag (16 bytes) is appended to the ciphertext.
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext);
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext);

    // Identity Verification
    std::string getFingerprint() const;

private:
    EVP_PKEY* pkey;
    std::vector<uint8_t> sharedSecret;
    std::vector<uint8_t> aesKey; // Derived 32-byte key

    void deriveAESKey();
};

#endif // CRYPTO_HANDLER_H
