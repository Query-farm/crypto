#include "crypto_hash.hpp"
#include "duckdb/common/string_util.hpp"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <cstring>
#include <unordered_map>
#include <functional>
#include "blake3.h"

namespace duckdb
{
    // Shared digest map accessible to all translation units
    const std::unordered_map<std::string, std::function<const EVP_MD *()>>& GetDigestMap()
    {
        static const std::unordered_map<std::string, std::function<const EVP_MD *()>> digest_map = {
            {"blake2b-512", []() { return EVP_blake2b512(); }},
            {"md4", []() { return EVP_md4(); }},
            {"md5", []() { return EVP_md5(); }},
            {"sha1", []() { return EVP_sha1(); }},
            {"sha2-224", []() { return EVP_sha224(); }},
            {"sha2-256", []() { return EVP_sha256(); }},
            {"sha2-384", []() { return EVP_sha384(); }},
            {"sha2-512", []() { return EVP_sha512(); }},
            {"sha3-224", []() { return EVP_sha3_224(); }},
            {"sha3-256", []() { return EVP_sha3_256(); }},
            {"sha3-384", []() { return EVP_sha3_384(); }},
            {"sha3-512", []() { return EVP_sha3_512(); }},
            {"keccak224", []() { return EVP_sha3_224(); }},
            {"keccak256", []() { return EVP_sha3_256(); }},
            {"keccak384", []() { return EVP_sha3_384(); }},
            {"keccak512", []() { return EVP_sha3_512(); }}
        };
        return digest_map;
    }

    namespace
    {
        std::string getAvailableAlgorithms()
        {
            std::string result = "blake3";
            for (const auto &entry : GetDigestMap())
            {
                result += ", " + entry.first;
            }
            return result;
        }

        const EVP_MD *getDigestByName(const std::string &algorithm)
        {
            std::string algo_lower = StringUtil::Lower(algorithm);

            if (algo_lower == "blake3")
            {
                return nullptr;
            }

            auto it = GetDigestMap().find(algo_lower);
            if (it != GetDigestMap().end())
            {
                return it->second();
            }

            return nullptr;
        }
    }

    void CryptoHash(const std::string &algorithm, const char *data, size_t data_len, unsigned char *result, unsigned int &result_len)
    {
        std::string algo_lower = StringUtil::Lower(algorithm);

        // Handle Blake3 separately since it doesn't use OpenSSL
        if (algo_lower == "blake3")
        {
            blake3_hasher hasher;
            blake3_hasher_init(&hasher);
            blake3_hasher_update(&hasher, data, data_len);
            blake3_hasher_finalize(&hasher, result, BLAKE3_OUT_LEN);
            result_len = BLAKE3_OUT_LEN;
            return;
        }

        const EVP_MD *md = getDigestByName(algo_lower);

        if (md == nullptr)
        {
            throw InvalidInputException(
                "Invalid hash algorithm '" + algorithm + "'. " +
                "Available algorithms are: " + getAvailableAlgorithms());
        }

        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (ctx == nullptr)
        {
            throw InternalException("Failed to create hash context");
        }

        if (EVP_DigestInit_ex(ctx, md, nullptr) != 1 ||
            EVP_DigestUpdate(ctx, data, data_len) != 1 ||
            EVP_DigestFinal_ex(ctx, result, &result_len) != 1)
        {
            EVP_MD_CTX_free(ctx);
            throw InternalException("Failed to compute hash");
        }

        EVP_MD_CTX_free(ctx);
    }

    void CryptoHash(const std::string &algorithm, const std::string &data, unsigned char *result, unsigned int &result_len)
    {
        CryptoHash(algorithm, data.data(), data.size(), result, result_len);
    }

    void CryptoHmac(const std::string &algorithm, const std::string &key, const std::string &data, unsigned char *result, unsigned int &result_len)
    {
        std::string algo_lower = StringUtil::Lower(algorithm);

        // Handle Blake3 HMAC separately
        if (algo_lower == "blake3")
        {
            // Blake3 keyed mode requires exactly 32 bytes for the key
            if (key.size() != BLAKE3_KEY_LEN)
            {
                throw InvalidInputException(
                    "Blake3 keyed mode requires a key of exactly " + std::to_string(BLAKE3_KEY_LEN) + " bytes");
            }
            blake3_hasher hasher;
            blake3_hasher_init_keyed(&hasher, reinterpret_cast<const uint8_t *>(key.data()));
            blake3_hasher_update(&hasher, data.data(), data.size());
            blake3_hasher_finalize(&hasher, result, BLAKE3_OUT_LEN);
            result_len = BLAKE3_OUT_LEN;
            return;
        }

        const EVP_MD *md = getDigestByName(algo_lower);

        if (md == nullptr)
        {
            throw InvalidInputException(
                "Invalid hash algorithm '" + algorithm + "'. " +
                "Available algorithms are: " + getAvailableAlgorithms());
        }

        unsigned char *hmac_result = HMAC(
            md,
            key.data(), key.size(),
            reinterpret_cast<const unsigned char *>(data.data()), data.size(),
            result, &result_len);

        if (hmac_result == nullptr)
        {
            throw InternalException("Failed to compute HMAC");
        }
    }

} // namespace duckdb
