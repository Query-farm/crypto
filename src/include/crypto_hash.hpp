#pragma once

#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include <string>
#include <unordered_map>
#include <functional>

typedef struct evp_md_st EVP_MD;

namespace duckdb {

// Get the shared digest map for algorithm name lookups
const std::unordered_map<std::string, std::function<const EVP_MD *()>>& GetDigestMap();

// Compute a cryptographic hash of the input data
void CryptoHash(const std::string& algorithm, const std::string& data, unsigned char* result, unsigned int& result_len);

// Compute a cryptographic hash of the input binary data
void CryptoHash(const std::string& algorithm, const char* data, size_t data_len, unsigned char* result, unsigned int& result_len);

// Compute an HMAC (Hash-based Message Authentication Code)
void CryptoHmac(const std::string& algorithm, const std::string& key, const std::string& data, unsigned char* result, unsigned int& result_len);

} // namespace duckdb
