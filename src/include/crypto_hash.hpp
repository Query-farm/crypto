#pragma once

#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/allocator.hpp"
#include "duckdb/common/vector/unified_vector_format.hpp"
#include <string>
#include <vector>
#include "blake3.h"

typedef struct evp_md_st EVP_MD;
typedef struct evp_md_ctx_st EVP_MD_CTX;
typedef struct evp_mac_ctx_st EVP_MAC_CTX;

namespace duckdb
{

    // Maximum size of a BLOB in DuckDB (4GB - 1)
    constexpr int64_t CRYPTO_MAX_BLOB_BYTES = 4294967295LL;
    // Maximum size for random bytes
    constexpr int64_t CRYPTO_MAX_RANDOM_BYTES = CRYPTO_MAX_BLOB_BYTES;

    enum class CryptoHashBackend : uint8_t
    {
        BLAKE3,
        OPENSSL
    };

    struct CryptoHashAlgorithm
    {
        //! Name used in SQL (lowercase)
        std::string name;
        //! Algorithm family, reported by crypto_algorithms()
        std::string family;
        //! Name passed to EVP_MD_fetch (empty for blake3)
        std::string openssl_name;
        CryptoHashBackend backend;
        //! Output length in bytes produced by crypto_hash()
        idx_t digest_length;
        //! Extendable-output function: crypto_hash_xof() accepts any output length
        bool is_xof;
        //! Usable with crypto_hmac()
        bool supports_hmac;
        //! False when the linked OpenSSL does not provide the algorithm
        bool available;
        //! Fetched once and kept for the lifetime of the process
        const EVP_MD *md;
    };

    //! All known hash algorithms, in a stable order
    const std::vector<CryptoHashAlgorithm> &GetHashAlgorithms();

    //! Case-insensitive lookup; throws InvalidInputException for unknown or unavailable algorithms
    const CryptoHashAlgorithm &LookupAlgorithm(const std::string &algorithm);
    const CryptoHashAlgorithm &LookupAlgorithm(const char *data, idx_t len);

    //! Caches the last algorithm resolved from a per-row algorithm name, so constant names are looked up once
    class CryptoAlgorithmCache
    {
    public:
        const CryptoHashAlgorithm &Lookup(const string_t &name);

    private:
        std::string last_name;
        optional_ptr<const CryptoHashAlgorithm> last_algorithm;
    };

    //! Incremental hasher that keeps its OpenSSL context alive across Init() calls
    class CryptoHasher
    {
    public:
        CryptoHasher();
        ~CryptoHasher();
        CryptoHasher(const CryptoHasher &) = delete;
        CryptoHasher &operator=(const CryptoHasher &) = delete;

        void Init(const CryptoHashAlgorithm &algorithm);
        void Update(const void *data, idx_t len);
        //! Writes the algorithm's digest_length bytes
        void Finalize(data_ptr_t out);
        //! Writes len bytes of output; the algorithm must be an XOF
        void FinalizeXof(data_ptr_t out, idx_t len);

        const CryptoHashAlgorithm &Algorithm() const
        {
            return *algorithm;
        }

    private:
        optional_ptr<const CryptoHashAlgorithm> algorithm;
        blake3_hasher b3;
        EVP_MD_CTX *ctx;
    };

    //! Reusable HMAC state; reuses the key schedule when consecutive rows share a key
    class CryptoHmacContext
    {
    public:
        CryptoHmacContext();
        ~CryptoHmacContext();
        CryptoHmacContext(const CryptoHmacContext &) = delete;
        CryptoHmacContext &operator=(const CryptoHmacContext &) = delete;

        //! Computes the MAC into out (at least algorithm.digest_length bytes)
        void Compute(const CryptoHashAlgorithm &algorithm, const char *key, idx_t key_len, const char *data,
                     idx_t data_len, data_ptr_t out);

    private:
        EVP_MAC_CTX *ctx;
        optional_ptr<const CryptoHashAlgorithm> ctx_algorithm;
        std::string ctx_key;
    };

    //! Feeds the canonical encoding of the value at idx into the hasher.
    //! Strings are written raw at the top level, and as [uint64 length][bytes] inside lists and aggregates.
    struct CryptoValueEncoder
    {
        //! Throws InvalidInputException when the type cannot be hashed. Lists and arrays are allowed when allow_nested.
        static void Validate(const LogicalType &type, bool allow_nested);

        template <class HASHER>
        static void Encode(HASHER &hasher, const LogicalType &type, const UnifiedVectorFormat &format, idx_t idx,
                           bool length_prefix_strings);
    };

    //! Writes a BLOB result; outputs of at least TRACKED_THRESHOLD bytes are allocated through DuckDB's
    //! buffer allocator, so they count against memory_limit
    class CryptoBlobWriter
    {
    public:
        static constexpr idx_t TRACKED_THRESHOLD = 4096;

        CryptoBlobWriter(Vector &result, Allocator &tracked_allocator);
        //! Returns a writable buffer of len bytes for the next result
        data_ptr_t Reserve(idx_t len);
        //! Turns the buffer returned by the last Reserve() into a string_t
        string_t Finish();

    private:
        Vector &result;
        Allocator &tracked_allocator;
        idx_t pending_len;
        data_ptr_t pending_data;
        string_t pending_string;
        bool pending_is_heap;
        char inline_buffer[string_t::INLINE_LENGTH];
    };

    //! Holds a memory reservation against DuckDB's buffer pool for memory OpenSSL allocates itself
    class CryptoMemoryReservation
    {
    public:
        CryptoMemoryReservation(ClientContext &context, idx_t size);
        ~CryptoMemoryReservation();
        CryptoMemoryReservation(const CryptoMemoryReservation &) = delete;
        CryptoMemoryReservation &operator=(const CryptoMemoryReservation &) = delete;

    private:
        ClientContext &context;
        idx_t size;
    };

    //! Validate random bytes length - throws InvalidInputException if invalid
    void ValidateRandomBytesLength(int64_t length);

    //! Fill result with cryptographically secure random bytes
    void CryptoRandomBytes(int64_t length, unsigned char *result);

    //! Constant-time comparison; false when the lengths differ
    bool CryptoConstantTimeEquals(const char *a, idx_t a_len, const char *b, idx_t b_len);

    //! Registers crypto_pbkdf2, crypto_hkdf, crypto_scrypt and crypto_argon2
    void RegisterKdfFunctions(ExtensionLoader &loader);

} // namespace duckdb

#include "crypto_value_encoder.hpp"
