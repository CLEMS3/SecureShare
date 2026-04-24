#include "CryptoHandler.h"
#include <iostream>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <cstring>
#include <openssl/x509.h>
#include <iomanip>
#include <sstream>

CryptoHandler::CryptoHandler() : pkey(nullptr) {}

CryptoHandler::~CryptoHandler() {
    if (pkey) EVP_PKEY_free(pkey);
}

bool CryptoHandler::generateECDHKeyPair() {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) return false;

    if (EVP_PKEY_paramgen_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }

    EVP_PKEY *params = NULL;
    if (EVP_PKEY_paramgen(pctx, &params) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }
    EVP_PKEY_CTX_free(pctx);

    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new(params, NULL);
    EVP_PKEY_free(params);

    if (!kctx) return false;

    if (EVP_PKEY_keygen_init(kctx) <= 0) {
        EVP_PKEY_CTX_free(kctx);
        return false;
    }

    if (EVP_PKEY_keygen(kctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(kctx);
        return false;
    }

    EVP_PKEY_CTX_free(kctx);
    return true;
}

std::vector<uint8_t> CryptoHandler::getPublicKey() const {
    if (!pkey) return {};
    unsigned char* out = NULL;
    int len = i2d_PUBKEY(pkey, &out);
    if (len <= 0) return {};

    std::vector<uint8_t> pubKey(out, out + len);
    OPENSSL_free(out);
    return pubKey;
}

bool CryptoHandler::computeSharedSecret(const std::vector<uint8_t>& peerPublicKeyDER) {
    const unsigned char* p = peerPublicKeyDER.data();
    EVP_PKEY* peerKey = d2i_PUBKEY(NULL, &p, peerPublicKeyDER.size());
    if (!peerKey) {
        std::cerr << "Failed to parse peer public key.\n";
        return false;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(peerKey);
        return false;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peerKey);
        return false;
    }

    if (EVP_PKEY_derive_set_peer(ctx, peerKey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peerKey);
        return false;
    }

    size_t secretLen;
    if (EVP_PKEY_derive(ctx, NULL, &secretLen) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peerKey);
        return false;
    }

    sharedSecret.resize(secretLen);
    if (EVP_PKEY_derive(ctx, sharedSecret.data(), &secretLen) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peerKey);
        return false;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peerKey);

    deriveAESKey();
    return true;
}

void CryptoHandler::deriveAESKey() {
    aesKey.resize(SHA256_DIGEST_LENGTH);
    SHA256(sharedSecret.data(), sharedSecret.size(), aesKey.data());
}

std::string CryptoHandler::getFingerprint() const {
    if (sharedSecret.empty()) return "No shared secret established.";
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(sharedSecret.data(), sharedSecret.size(), hash);
    
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        if (i < SHA256_DIGEST_LENGTH - 1) ss << ":";
    }
    return ss.str();
}

std::vector<uint8_t> CryptoHandler::encrypt(const std::vector<uint8_t>& plaintext) {
    if (aesKey.empty()) throw std::runtime_error("Key not established.");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create context");

    // GCM standard IV size is 12 bytes
    std::vector<uint8_t> iv(12);
    RAND_bytes(iv.data(), iv.size());

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, aesKey.data(), iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EncryptInit failed");
    }

    std::vector<uint8_t> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int len = 0;
    int ciphertext_len = 0;

    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EncryptUpdate failed");
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EncryptFinal failed");
    }
    ciphertext_len += len;
    
    // Get the GCM tag
    std::vector<uint8_t> tag(16);
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to get GCM tag");
    }

    ciphertext.resize(ciphertext_len);
    EVP_CIPHER_CTX_free(ctx);

    std::vector<uint8_t> result;
    result.reserve(iv.size() + ciphertext.size() + tag.size());
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    result.insert(result.end(), tag.begin(), tag.end());
    return result;
}

std::vector<uint8_t> CryptoHandler::decrypt(const std::vector<uint8_t>& ciphertext_with_iv_and_tag) {
    if (aesKey.empty()) throw std::runtime_error("Key not established.");
    // 12 bytes IV + 16 bytes tag = 28 bytes minimum
    if (ciphertext_with_iv_and_tag.size() < 28) throw std::runtime_error("Ciphertext too short.");

    std::vector<uint8_t> iv(ciphertext_with_iv_and_tag.begin(), ciphertext_with_iv_and_tag.begin() + 12);
    std::vector<uint8_t> tag(ciphertext_with_iv_and_tag.end() - 16, ciphertext_with_iv_and_tag.end());
    std::vector<uint8_t> ciphertext(ciphertext_with_iv_and_tag.begin() + 12, ciphertext_with_iv_and_tag.end() - 16);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create context");

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, aesKey.data(), iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("DecryptInit failed");
    }

    std::vector<uint8_t> plaintext(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);
    int len = 0;
    int plaintext_len = 0;

    if (!ciphertext.empty()) {
        if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size())) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("DecryptUpdate failed");
        }
        plaintext_len = len;
    }

    // Set expected tag value
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set GCM tag");
    }

    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    if (ret <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("DecryptFinal failed (authentication tag mismatch or corrupted data)");
    }
    plaintext_len += len;

    plaintext.resize(plaintext_len);
    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}
