#include "crypto_hash.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/vector/flat_vector.hpp"
#include "duckdb/common/vector/unified_vector_format.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include <duckdb/parser/parsed_data/create_scalar_function_info.hpp>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

namespace duckdb
{
    namespace
    {
        // Derived keys longer than this are not useful, and PBKDF2's cost grows with the output length
        constexpr int64_t CRYPTO_MAX_KDF_BYTES = 1048576;

        //! Unified view over all KDF arguments for one chunk
        class KdfArguments
        {
        public:
            explicit KdfArguments(DataChunk &args) : formats(args.ColumnCount())
            {
                all_constant = true;
                for (idx_t col = 0; col < args.ColumnCount(); col++)
                {
                    args.data[col].ToUnifiedFormat(formats[col]);
                    all_constant = all_constant && args.data[col].GetVectorType() == VectorType::CONSTANT_VECTOR;
                }
                count = all_constant ? 1 : args.size();
            }

            //! Selects row i; false when any argument is NULL
            bool SetRow(idx_t i)
            {
                indexes.resize(formats.size());
                for (idx_t col = 0; col < formats.size(); col++)
                {
                    indexes[col] = formats[col].sel->get_index(i);
                    if (!formats[col].validity.RowIsValid(indexes[col]))
                    {
                        return false;
                    }
                }
                return true;
            }

            const string_t &Bytes(idx_t col) const
            {
                return UnifiedVectorFormat::GetData<string_t>(formats[col])[indexes[col]];
            }

            int64_t Integer(idx_t col) const
            {
                return UnifiedVectorFormat::GetData<int64_t>(formats[col])[indexes[col]];
            }

            idx_t count;
            bool all_constant;

        private:
            vector<UnifiedVectorFormat> formats;
            vector<idx_t> indexes;
        };

        int64_t CheckRange(const char *function, const char *name, int64_t value, int64_t min, int64_t max)
        {
            if (value < min || value > max)
            {
                throw InvalidInputException("%s: %s must be between %lld and %lld, got %lld", function, name,
                                            static_cast<long long>(min), static_cast<long long>(max),
                                            static_cast<long long>(value));
            }
            return value;
        }

        OSSL_PARAM OctetParam(const char *key, const string_t &value)
        {
            // OpenSSL rejects a NULL pointer even for an empty string
            static unsigned char empty = 0;
            auto data = value.GetSize() == 0 ? &empty : reinterpret_cast<unsigned char *>(
                                                            const_cast<char *>(value.GetData()));
            return OSSL_PARAM_construct_octet_string(key, data, value.GetSize());
        }

        const CryptoHashAlgorithm &LookupKdfDigest(const char *function, const string_t &name)
        {
            auto &algorithm = LookupAlgorithm(name.GetData(), name.GetSize());
            if (algorithm.backend != CryptoHashBackend::OPENSSL || algorithm.is_xof)
            {
                throw InvalidInputException("%s does not support hash algorithm '%s'", function, algorithm.name);
            }
            return algorithm;
        }

        EVP_KDF *FetchKdf(const char *name)
        {
            auto kdf = EVP_KDF_fetch(nullptr, name, nullptr);
            ERR_clear_error();
            return kdf;
        }

        void Derive(const char *function, EVP_KDF *kdf, const char *kdf_name, OSSL_PARAM *params, data_ptr_t out,
                    idx_t len)
        {
            if (!kdf)
            {
                throw InvalidInputException("%s is not available: the linked OpenSSL library does not provide %s",
                                            function, kdf_name);
            }
            auto ctx = EVP_KDF_CTX_new(kdf);
            if (!ctx)
            {
                throw InternalException("Failed to create %s context", kdf_name);
            }
            auto rc = EVP_KDF_derive(ctx, out, len, params);
            EVP_KDF_CTX_free(ctx);
            if (rc != 1)
            {
                char error[256] = {0};
                ERR_error_string_n(ERR_get_error(), error, sizeof(error));
                ERR_clear_error();
                throw InvalidInputException("%s failed: %s", function, error);
            }
        }

        template <class FUNC>
        void ExecuteKdf(const char *function, DataChunk &args, ExpressionState &state, Vector &result,
                        idx_t length_col, FUNC &&derive)
        {
            KdfArguments arguments(args);
            CryptoBlobWriter writer(result, BufferAllocator::Get(state.GetContext()));
            auto results = FlatVector::GetDataMutable<string_t>(result);
            for (idx_t i = 0; i < arguments.count; i++)
            {
                if (!arguments.SetRow(i))
                {
                    FlatVector::SetNull(result, i, true);
                    continue;
                }
                auto length = CheckRange(function, "length", arguments.Integer(length_col), 1, CRYPTO_MAX_KDF_BYTES);
                auto out = writer.Reserve(static_cast<idx_t>(length));
                derive(arguments, out, static_cast<idx_t>(length));
                results[i] = writer.Finish();
            }
            if (arguments.all_constant)
            {
                result.SetVectorType(VectorType::CONSTANT_VECTOR);
            }
        }
    } // namespace

    // crypto_pbkdf2(algorithm, password, salt, iterations, length)
    static void CryptoPbkdf2Fun(DataChunk &args, ExpressionState &state, Vector &result)
    {
        static EVP_KDF *kdf = FetchKdf("PBKDF2");
        ExecuteKdf("crypto_pbkdf2", args, state, result, 4, [&](KdfArguments &a, data_ptr_t out, idx_t len) {
            const char *fn = "crypto_pbkdf2";
            auto &algorithm = LookupKdfDigest(fn, a.Bytes(0));
            uint64_t iterations = CheckRange(fn, "iterations", a.Integer(3), 1, NumericLimits<uint32_t>::Maximum());
            OSSL_PARAM params[5];
            params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                         const_cast<char *>(algorithm.openssl_name.c_str()), 0);
            params[1] = OctetParam(OSSL_KDF_PARAM_PASSWORD, a.Bytes(1));
            params[2] = OctetParam(OSSL_KDF_PARAM_SALT, a.Bytes(2));
            params[3] = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_ITER, &iterations);
            params[4] = OSSL_PARAM_construct_end();
            Derive(fn, kdf, "PBKDF2", params, out, len);
        });
    }

    // crypto_hkdf(algorithm, key, salt, info, length)
    static void CryptoHkdfFun(DataChunk &args, ExpressionState &state, Vector &result)
    {
        static EVP_KDF *kdf = FetchKdf("HKDF");
        ExecuteKdf("crypto_hkdf", args, state, result, 4, [&](KdfArguments &a, data_ptr_t out, idx_t len) {
            const char *fn = "crypto_hkdf";
            auto &algorithm = LookupKdfDigest(fn, a.Bytes(0));
            // RFC 5869 limits the output to 255 blocks of the digest
            CheckRange(fn, "length", static_cast<int64_t>(len), 1,
                       static_cast<int64_t>(255 * algorithm.digest_length));
            OSSL_PARAM params[5];
            params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                         const_cast<char *>(algorithm.openssl_name.c_str()), 0);
            params[1] = OctetParam(OSSL_KDF_PARAM_KEY, a.Bytes(1));
            params[2] = OctetParam(OSSL_KDF_PARAM_SALT, a.Bytes(2));
            params[3] = OctetParam(OSSL_KDF_PARAM_INFO, a.Bytes(3));
            params[4] = OSSL_PARAM_construct_end();
            Derive(fn, kdf, "HKDF", params, out, len);
        });
    }

    // crypto_scrypt(password, salt, n, r, p, length)
    static void CryptoScryptFun(DataChunk &args, ExpressionState &state, Vector &result)
    {
        static EVP_KDF *kdf = FetchKdf("SCRYPT");
        auto &context = state.GetContext();
        ExecuteKdf("crypto_scrypt", args, state, result, 5, [&](KdfArguments &a, data_ptr_t out, idx_t len) {
            const char *fn = "crypto_scrypt";
            uint64_t n = CheckRange(fn, "n", a.Integer(2), 2, int64_t(1) << 40);
            if ((n & (n - 1)) != 0)
            {
                throw InvalidInputException("%s: n must be a power of 2, got %llu", fn,
                                            static_cast<unsigned long long>(n));
            }
            uint32_t r = CheckRange(fn, "r", a.Integer(3), 1, NumericLimits<int32_t>::Maximum());
            uint32_t p = CheckRange(fn, "p", a.Integer(4), 1, NumericLimits<int32_t>::Maximum());
            // Working memory as computed by OpenSSL: 128 * r * p for B plus 128 * r * (n + 2) for V
            hugeint_t memory = hugeint_t(128) * hugeint_t(r) * (hugeint_t(p) + hugeint_t(n) + hugeint_t(2));
            if (memory > hugeint_t(NumericLimits<int64_t>::Maximum()))
            {
                throw InvalidInputException("%s: parameters require too much memory", fn);
            }
            uint64_t max_memory = Hugeint::Cast<uint64_t>(memory);
            CryptoMemoryReservation reservation(context, max_memory);

            OSSL_PARAM params[7];
            params[0] = OctetParam(OSSL_KDF_PARAM_PASSWORD, a.Bytes(0));
            params[1] = OctetParam(OSSL_KDF_PARAM_SALT, a.Bytes(1));
            params[2] = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_N, &n);
            params[3] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_R, &r);
            params[4] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_P, &p);
            params[5] = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_MAXMEM, &max_memory);
            params[6] = OSSL_PARAM_construct_end();
            Derive(fn, kdf, "SCRYPT", params, out, len);
        });
    }

    // crypto_argon2(variant, password, salt, iterations, memory_kib, parallelism, length)
    static void CryptoArgon2Fun(DataChunk &args, ExpressionState &state, Vector &result)
    {
        static EVP_KDF *argon2d = FetchKdf("ARGON2D");
        static EVP_KDF *argon2i = FetchKdf("ARGON2I");
        static EVP_KDF *argon2id = FetchKdf("ARGON2ID");
        auto &context = state.GetContext();
        ExecuteKdf("crypto_argon2", args, state, result, 6, [&](KdfArguments &a, data_ptr_t out, idx_t len) {
            const char *fn = "crypto_argon2";
            auto variant = StringUtil::Lower(a.Bytes(0).GetString());
            EVP_KDF *kdf;
            const char *kdf_name;
            if (variant == "argon2id")
            {
                kdf = argon2id;
                kdf_name = "ARGON2ID";
            }
            else if (variant == "argon2i")
            {
                kdf = argon2i;
                kdf_name = "ARGON2I";
            }
            else if (variant == "argon2d")
            {
                kdf = argon2d;
                kdf_name = "ARGON2D";
            }
            else
            {
                throw InvalidInputException("%s: variant must be 'argon2id', 'argon2i' or 'argon2d', got '%s'", fn,
                                            variant);
            }
            CheckRange(fn, "length", static_cast<int64_t>(len), 4, CRYPTO_MAX_KDF_BYTES);
            uint32_t iterations = CheckRange(fn, "iterations", a.Integer(3), 1, NumericLimits<uint32_t>::Maximum());
            uint32_t lanes = CheckRange(fn, "parallelism", a.Integer(5), 1, (1 << 24) - 1);
            uint32_t memory_kib =
                CheckRange(fn, "memory_kib", a.Integer(4), 8 * int64_t(lanes), NumericLimits<uint32_t>::Maximum());
            uint32_t threads = 1;
            CryptoMemoryReservation reservation(context, idx_t(memory_kib) * 1024);

            OSSL_PARAM params[8];
            params[0] = OctetParam(OSSL_KDF_PARAM_PASSWORD, a.Bytes(1));
            params[1] = OctetParam(OSSL_KDF_PARAM_SALT, a.Bytes(2));
            params[2] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iterations);
            params[3] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &memory_kib);
            params[4] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &lanes);
            params[5] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, &threads);
            params[6] = OSSL_PARAM_construct_end();
            Derive(fn, kdf, kdf_name, params, out, len);
        });
    }

    namespace
    {
        struct KdfParameter
        {
            const char *name;
            //! Byte-string parameters get VARCHAR and BLOB overloads
            bool is_bytes;
            LogicalType type;
        };

        //! Registers one overload per VARCHAR/BLOB combination of the byte-string parameters
        void RegisterKdf(ExtensionLoader &loader, const char *name, const vector<KdfParameter> &parameters,
                         scalar_function_t function, const char *description, const vector<string> &examples)
        {
            idx_t byte_params = 0;
            for (auto &param : parameters)
            {
                byte_params += param.is_bytes;
            }
            ScalarFunctionSet set(name);
            for (idx_t mask = 0; mask < (idx_t(1) << byte_params); mask++)
            {
                vector<LogicalType> arguments;
                idx_t byte_idx = 0;
                for (auto &param : parameters)
                {
                    auto type = param.type;
                    if (param.is_bytes)
                    {
                        type = (mask >> byte_idx++) & 1 ? LogicalType::BLOB : LogicalType::VARCHAR;
                    }
                    arguments.push_back(type);
                }
                ScalarFunction fun(std::move(arguments), LogicalType::BLOB, function);
                // Name the positional parameters, so duckdb_functions() reports them instead of col<N>.
                for (idx_t i = 0; i < parameters.size(); i++)
                {
                    fun.GetSignature().GetParameter(i).SetName(parameters[i].name);
                }
                fun.SetFallible();
                set.AddFunction(fun);
            }
            CreateScalarFunctionInfo info(set);
            FunctionDescription desc;
            for (auto &param : parameters)
            {
                desc.parameter_types.push_back(param.is_bytes ? LogicalType::BLOB : param.type);
                desc.parameter_names.push_back(param.name);
            }
            desc.description = description;
            desc.examples = examples;
            desc.categories = {"cryptography", "kdf"};
            info.descriptions.push_back(std::move(desc));
            loader.RegisterFunction(info);
        }
    } // namespace

    void RegisterKdfFunctions(ExtensionLoader &loader)
    {
        auto bytes = LogicalType::BLOB;
        auto integer = LogicalType::BIGINT;

        RegisterKdf(loader, "crypto_pbkdf2",
                    {{"algorithm", false, LogicalType::VARCHAR},
                     {"password", true, bytes},
                     {"salt", true, bytes},
                     {"iterations", false, integer},
                     {"length", false, integer}},
                    CryptoPbkdf2Fun,
                    "Derives a key of length bytes from a password with PBKDF2-HMAC (RFC 8018) using the "
                    "specified hash algorithm.",
                    {"crypto_pbkdf2('sha2-256', 'password', 'salt', 600000, 32)"});

        RegisterKdf(loader, "crypto_hkdf",
                    {{"algorithm", false, LogicalType::VARCHAR},
                     {"key", true, bytes},
                     {"salt", true, bytes},
                     {"info", true, bytes},
                     {"length", false, integer}},
                    CryptoHkdfFun,
                    "Derives length bytes of key material with HKDF extract-and-expand (RFC 5869) using the "
                    "specified hash algorithm.",
                    {"crypto_hkdf('sha2-256', input_key, 'salt', 'context info', 32)"});

        RegisterKdf(loader, "crypto_scrypt",
                    {{"password", true, bytes},
                     {"salt", true, bytes},
                     {"n", false, integer},
                     {"r", false, integer},
                     {"p", false, integer},
                     {"length", false, integer}},
                    CryptoScryptFun,
                    "Derives a key of length bytes from a password with scrypt (RFC 7914). n must be a power of 2. "
                    "The working memory (about 128 * n * r bytes) counts against memory_limit.",
                    {"crypto_scrypt('password', 'salt', 16384, 8, 1, 32)"});

        RegisterKdf(loader, "crypto_argon2",
                    {{"variant", false, LogicalType::VARCHAR},
                     {"password", true, bytes},
                     {"salt", true, bytes},
                     {"iterations", false, integer},
                     {"memory_kib", false, integer},
                     {"parallelism", false, integer},
                     {"length", false, integer}},
                    CryptoArgon2Fun,
                    "Derives a key of length bytes from a password with Argon2 (RFC 9106). variant is 'argon2id', "
                    "'argon2i' or 'argon2d'. The working memory (memory_kib KiB) counts against memory_limit.",
                    {"crypto_argon2('argon2id', 'password', 'somesalt', 3, 65536, 4, 32)"});
    }

} // namespace duckdb
