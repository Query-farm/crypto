#include "crypto_hash.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/vector/string_vector.hpp"
#include "duckdb/storage/buffer_manager.hpp"
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <climits>
#include <cstring>

namespace duckdb
{
    namespace
    {
        struct AlgorithmSpec
        {
            const char *name;
            const char *family;
            const char *openssl_name;
            idx_t xof_default_length;
        };

        // openssl_name == nullptr means BLAKE3; a non-zero xof_default_length marks an extendable-output function
        const AlgorithmSpec ALGORITHM_SPECS[] = {
            {"blake2b-512", "blake2", "BLAKE2B-512", 0},
            {"blake2s-256", "blake2", "BLAKE2S-256", 0},
            {"blake3", "blake3", nullptr, BLAKE3_OUT_LEN},
            {"keccak224", "keccak", "KECCAK-224", 0},
            {"keccak256", "keccak", "KECCAK-256", 0},
            {"keccak384", "keccak", "KECCAK-384", 0},
            {"keccak512", "keccak", "KECCAK-512", 0},
            {"md4", "md", "MD4", 0},
            {"md5", "md", "MD5", 0},
            {"ripemd160", "ripemd", "RIPEMD-160", 0},
            {"sha1", "sha1", "SHA1", 0},
            {"sha2-224", "sha2", "SHA2-224", 0},
            {"sha2-256", "sha2", "SHA2-256", 0},
            {"sha2-384", "sha2", "SHA2-384", 0},
            {"sha2-512", "sha2", "SHA2-512", 0},
            {"sha2-512/224", "sha2", "SHA2-512/224", 0},
            {"sha2-512/256", "sha2", "SHA2-512/256", 0},
            {"sha3-224", "sha3", "SHA3-224", 0},
            {"sha3-256", "sha3", "SHA3-256", 0},
            {"sha3-384", "sha3", "SHA3-384", 0},
            {"sha3-512", "sha3", "SHA3-512", 0},
            {"shake128", "shake", "SHAKE-128", 32},
            {"shake256", "shake", "SHAKE-256", 64},
            {"sm3", "sm3", "SM3", 0},
        };

        std::vector<CryptoHashAlgorithm> BuildAlgorithms()
        {
            std::vector<CryptoHashAlgorithm> result;
            for (auto &spec : ALGORITHM_SPECS)
            {
                CryptoHashAlgorithm algorithm;
                algorithm.name = spec.name;
                algorithm.family = spec.family;
                algorithm.is_xof = spec.xof_default_length > 0;
                algorithm.md = nullptr;
                if (!spec.openssl_name)
                {
                    algorithm.backend = CryptoHashBackend::BLAKE3;
                    algorithm.digest_length = BLAKE3_OUT_LEN;
                    algorithm.supports_hmac = true;
                    algorithm.available = true;
                }
                else
                {
                    algorithm.backend = CryptoHashBackend::OPENSSL;
                    algorithm.openssl_name = spec.openssl_name;
                    // Pre-fetching avoids an implicit provider lookup on every EVP_DigestInit_ex
                    algorithm.md = EVP_MD_fetch(nullptr, spec.openssl_name, nullptr);
                    algorithm.available = algorithm.md != nullptr;
                    algorithm.digest_length =
                        algorithm.is_xof ? spec.xof_default_length : (algorithm.md ? EVP_MD_get_size(algorithm.md) : 0);
                    algorithm.supports_hmac = !algorithm.is_xof;
                }
                result.push_back(std::move(algorithm));
            }
            // A failed fetch leaves an error on the OpenSSL error queue
            ERR_clear_error();
            return result;
        }

        std::string AvailableAlgorithmNames()
        {
            std::string result;
            for (auto &algorithm : GetHashAlgorithms())
            {
                if (!algorithm.available)
                {
                    continue;
                }
                if (!result.empty())
                {
                    result += ", ";
                }
                result += algorithm.name;
            }
            return result;
        }

        // Keeps an allocation made through DuckDB's buffer allocator alive for as long as the result vector
        struct TrackedBlobHolder : public AuxiliaryDataHolder
        {
            explicit TrackedBlobHolder(AllocatedData data_p) : data(std::move(data_p))
            {
            }

            idx_t GetAllocationSize() const override
            {
                return data.GetSize();
            }

            AllocatedData data;
        };
    } // namespace

    const std::vector<CryptoHashAlgorithm> &GetHashAlgorithms()
    {
        static const std::vector<CryptoHashAlgorithm> algorithms = BuildAlgorithms();
        return algorithms;
    }

    const CryptoHashAlgorithm &LookupAlgorithm(const char *data, idx_t len)
    {
        for (auto &algorithm : GetHashAlgorithms())
        {
            if (algorithm.name.size() == len && StringUtil::CIEquals(algorithm.name, std::string(data, len)))
            {
                if (!algorithm.available)
                {
                    throw InvalidInputException("Hash algorithm '%s' is not available in the linked OpenSSL library",
                                                algorithm.name);
                }
                return algorithm;
            }
        }
        auto lower = StringUtil::Lower(std::string(data, len));
        throw InvalidInputException("Invalid hash algorithm '%s'. Available algorithms are: %s", lower,
                                    AvailableAlgorithmNames());
    }

    const CryptoHashAlgorithm &LookupAlgorithm(const std::string &algorithm)
    {
        return LookupAlgorithm(algorithm.data(), algorithm.size());
    }

    const CryptoHashAlgorithm &CryptoAlgorithmCache::Lookup(const string_t &name)
    {
        if (last_algorithm && name.GetSize() == last_name.size() &&
            memcmp(name.GetData(), last_name.data(), last_name.size()) == 0)
        {
            return *last_algorithm;
        }
        last_algorithm = &LookupAlgorithm(name.GetData(), name.GetSize());
        last_name.assign(name.GetData(), name.GetSize());
        return *last_algorithm;
    }

    CryptoHasher::CryptoHasher() : ctx(nullptr)
    {
    }

    CryptoHasher::~CryptoHasher()
    {
        if (ctx)
        {
            EVP_MD_CTX_free(ctx);
        }
    }

    void CryptoHasher::Init(const CryptoHashAlgorithm &algorithm_p)
    {
        algorithm = &algorithm_p;
        if (algorithm->backend == CryptoHashBackend::BLAKE3)
        {
            blake3_hasher_init(&b3);
            return;
        }
        if (!ctx)
        {
            ctx = EVP_MD_CTX_new();
            if (!ctx)
            {
                throw InternalException("Failed to create hash context");
            }
        }
        if (EVP_DigestInit_ex(ctx, algorithm->md, nullptr) != 1)
        {
            throw InternalException("Failed to initialize hash context for '%s'", algorithm->name);
        }
    }

    void CryptoHasher::Update(const void *data, idx_t len)
    {
        if (algorithm->backend == CryptoHashBackend::BLAKE3)
        {
            blake3_hasher_update(&b3, data, len);
            return;
        }
        if (EVP_DigestUpdate(ctx, data, len) != 1)
        {
            throw InternalException("Failed to update hash");
        }
    }

    void CryptoHasher::Finalize(data_ptr_t out)
    {
        if (algorithm->is_xof)
        {
            FinalizeXof(out, algorithm->digest_length);
            return;
        }
        unsigned int len = 0;
        if (EVP_DigestFinal_ex(ctx, out, &len) != 1)
        {
            throw InternalException("Failed to finalize hash");
        }
        D_ASSERT(len == algorithm->digest_length);
    }

    void CryptoHasher::FinalizeXof(data_ptr_t out, idx_t len)
    {
        D_ASSERT(algorithm->is_xof);
        if (algorithm->backend == CryptoHashBackend::BLAKE3)
        {
            blake3_hasher_finalize(&b3, out, len);
            return;
        }
        if (EVP_DigestFinalXOF(ctx, out, len) != 1)
        {
            throw InternalException("Failed to finalize hash");
        }
    }

    CryptoHmacContext::CryptoHmacContext() : ctx(nullptr)
    {
    }

    CryptoHmacContext::~CryptoHmacContext()
    {
        if (ctx)
        {
            EVP_MAC_CTX_free(ctx);
        }
    }

    void CryptoHmacContext::Compute(const CryptoHashAlgorithm &algorithm, const char *key, idx_t key_len,
                                    const char *data, idx_t data_len, data_ptr_t out)
    {
        if (!algorithm.supports_hmac)
        {
            throw InvalidInputException("Hash algorithm '%s' cannot be used with crypto_hmac", algorithm.name);
        }
        if (algorithm.backend == CryptoHashBackend::BLAKE3)
        {
            if (key_len != BLAKE3_KEY_LEN)
            {
                throw InvalidInputException("Blake3 keyed mode requires a key of exactly %d bytes", BLAKE3_KEY_LEN);
            }
            blake3_hasher hasher;
            blake3_hasher_init_keyed(&hasher, const_data_ptr_cast(key));
            blake3_hasher_update(&hasher, data, data_len);
            blake3_hasher_finalize(&hasher, out, BLAKE3_OUT_LEN);
            return;
        }

        if (!ctx)
        {
            static EVP_MAC *hmac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
            if (!hmac)
            {
                throw InternalException("HMAC is not available in the linked OpenSSL library");
            }
            ctx = EVP_MAC_CTX_new(hmac);
            if (!ctx)
            {
                throw InternalException("Failed to create HMAC context");
            }
        }

        const bool same_algorithm = ctx_algorithm.get() == &algorithm;
        const bool same_key =
            same_algorithm && ctx_key.size() == key_len && memcmp(ctx_key.data(), key, key_len) == 0;
        int rc;
        if (same_key)
        {
            // A NULL key makes OpenSSL reuse the already expanded key
            rc = EVP_MAC_init(ctx, nullptr, 0, nullptr);
        }
        else
        {
            OSSL_PARAM params[2];
            params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                         const_cast<char *>(algorithm.openssl_name.c_str()), 0);
            params[1] = OSSL_PARAM_construct_end();
            // OpenSSL treats a NULL key as "reuse", so an empty key needs a non-NULL pointer
            static const unsigned char empty_key = 0;
            auto key_ptr = key_len == 0 ? &empty_key : const_data_ptr_cast(key);
            rc = EVP_MAC_init(ctx, key_ptr, key_len, same_algorithm ? nullptr : params);
            ctx_algorithm = nullptr;
            if (rc == 1)
            {
                ctx_algorithm = &algorithm;
                ctx_key.assign(key, key_len);
            }
        }
        size_t out_len = 0;
        if (rc != 1 || EVP_MAC_update(ctx, const_data_ptr_cast(data), data_len) != 1 ||
            EVP_MAC_final(ctx, out, &out_len, algorithm.digest_length) != 1)
        {
            ctx_algorithm = nullptr;
            throw InternalException("Failed to compute HMAC");
        }
        D_ASSERT(out_len == algorithm.digest_length);
    }

    void CryptoValueEncoder::Validate(const LogicalType &type, bool allow_nested)
    {
        switch (type.id())
        {
        case LogicalTypeId::LIST:
        case LogicalTypeId::ARRAY:
        {
            if (!allow_nested)
            {
                throw InvalidInputException("Unsupported type for crypto_hash: nested types inside of lists are not supported");
            }
            auto &child = type.id() == LogicalTypeId::LIST ? ListType::GetChildType(type) : ArrayType::GetChildType(type);
            if (child.IsNested())
            {
                throw InvalidInputException("Unsupported type for crypto_hash: nested types inside of lists are not supported");
            }
            Validate(child, false);
            return;
        }
        case LogicalTypeId::UUID:
        case LogicalTypeId::DECIMAL:
        case LogicalTypeId::ENUM:
            return;
        case LogicalTypeId::SQLNULL:
        case LogicalTypeId::UNKNOWN:
        case LogicalTypeId::ANY:
        case LogicalTypeId::INVALID:
            throw InvalidInputException("Unsupported type for crypto_hash: %s", type.ToString());
        default:
            break;
        }
        if (type.IsNested())
        {
            throw InvalidInputException("Unsupported type for crypto_hash: %s", type.ToString());
        }
        auto physical = type.InternalType();
        if (physical != PhysicalType::VARCHAR && !TypeIsConstantSize(physical))
        {
            throw InvalidInputException("Unsupported type for crypto_hash: %s", type.ToString());
        }
    }

    CryptoBlobWriter::CryptoBlobWriter(Vector &result_p, Allocator &tracked_allocator_p)
        : result(result_p), tracked_allocator(tracked_allocator_p), pending_len(0), pending_data(nullptr),
          pending_is_heap(false)
    {
    }

    data_ptr_t CryptoBlobWriter::Reserve(idx_t len)
    {
        pending_len = len;
        if (len <= string_t::INLINE_LENGTH)
        {
            pending_is_heap = false;
            pending_data = data_ptr_cast(inline_buffer);
        }
        else if (len < TRACKED_THRESHOLD)
        {
            pending_is_heap = true;
            pending_string = StringVector::EmptyString(result, len);
            pending_data = data_ptr_cast(pending_string.GetDataWriteable());
        }
        else
        {
            pending_is_heap = false;
            auto data = tracked_allocator.Allocate(len);
            pending_data = data.get();
            StringVector::AddAuxiliaryData(result, make_uniq<TrackedBlobHolder>(std::move(data)));
        }
        return pending_data;
    }

    string_t CryptoBlobWriter::Finish()
    {
        if (pending_is_heap)
        {
            pending_string.Finalize();
            return pending_string;
        }
        // string_t copies inline data and points at the tracked allocation otherwise
        return string_t(const_char_ptr_cast(pending_data), UnsafeNumericCast<uint32_t>(pending_len));
    }

    CryptoMemoryReservation::CryptoMemoryReservation(ClientContext &context_p, idx_t size_p)
        : context(context_p), size(0)
    {
        BufferManager::GetBufferManager(context).ReserveMemory(size_p);
        size = size_p;
    }

    CryptoMemoryReservation::~CryptoMemoryReservation()
    {
        BufferManager::GetBufferManager(context).FreeReservedMemory(size);
    }

    void ValidateRandomBytesLength(int64_t length)
    {
        if (length <= 0)
        {
            throw InvalidInputException("Random bytes length must be greater than 0");
        }

        if (length > CRYPTO_MAX_RANDOM_BYTES)
        {
            throw InvalidInputException(
                "Random bytes length must be less than or equal to " +
                std::to_string(CRYPTO_MAX_RANDOM_BYTES) + " bytes (4GB)");
        }
    }

    void CryptoRandomBytes(int64_t length, unsigned char *result)
    {
        ValidateRandomBytesLength(length);

        // RAND_bytes takes an int, so lengths beyond INT_MAX are filled in chunks
        idx_t remaining = static_cast<idx_t>(length);
        while (remaining > 0)
        {
            auto chunk = MinValue<idx_t>(remaining, INT_MAX);
            if (RAND_bytes(result, static_cast<int>(chunk)) != 1)
            {
                throw InternalException("Failed to generate random bytes");
            }
            result += chunk;
            remaining -= chunk;
        }
    }

    bool CryptoConstantTimeEquals(const char *a, idx_t a_len, const char *b, idx_t b_len)
    {
        // The length is not secret; only the contents are compared in constant time
        if (a_len != b_len)
        {
            return false;
        }
        return CRYPTO_memcmp(a, b, a_len) == 0;
    }

} // namespace duckdb
