#pragma once

#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include <string>
#include <unordered_map>
#include <functional>

typedef struct evp_md_st EVP_MD;

namespace duckdb {

// Maximum size for random bytes (DuckDB BLOB max is 4GB - 1)
constexpr int64_t CRYPTO_MAX_RANDOM_BYTES = 4294967295LL;

// Get the shared digest map for algorithm name lookups
const std::unordered_map<std::string, std::function<const EVP_MD *()>>& GetDigestMap();

// Lookup algorithm by name - returns nullptr for blake3, throws on invalid algorithm
const EVP_MD* LookupAlgorithm(const std::string& algorithm);

// Validate random bytes length - throws InvalidInputException if invalid
void ValidateRandomBytesLength(int64_t length);

// Compute a cryptographic hash of the input data
void CryptoHash(const std::string& algorithm, const std::string& data, unsigned char* result, unsigned int& result_len);

// Compute a cryptographic hash of the input binary data
void CryptoHash(const std::string& algorithm, const char* data, size_t data_len, unsigned char* result, unsigned int& result_len);

// Compute an HMAC (Hash-based Message Authentication Code)
void CryptoHmac(const std::string& algorithm, const std::string& key, const std::string& data, unsigned char* result, unsigned int& result_len);

// Generate cryptographically secure random bytes
void CryptoRandomBytes(int64_t length, unsigned char* result);

} // namespace duckdb
