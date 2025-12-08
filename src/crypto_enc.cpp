

#include "crypto_extension.hpp"
#include "crypto_enc.hpp"
#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/scalar_function.hpp"
#include <duckdb/parser/parsed_data/create_scalar_function_info.hpp>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <algorithm>
#include <cctype>
#include <unordered_map>
#include <functional>

namespace duckdb
{

    constexpr int MODE_ENCRYPT = 1;
    constexpr int MODE_DECRYPT = 0;
    constexpr size_t GCM_TAG_SIZE = 16;

    void throwOpensslError(const std::string &prefix)
    {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        std::string error_msg = prefix + ": " + err_buf;
        throw InternalException(error_msg);
    }

    std::string generate_random_string(size_t len)
    {
        std::string out(len, '\0'); // allocate len bytes
        if (RAND_bytes(reinterpret_cast<unsigned char *>(&out[0]), len) != 1)
        {
            throwOpensslError("RAND_bytes failed");
        }
        return out;
    }

    class EvpCipherContext
    {
    public:
        EvpCipherContext(const EVP_CIPHER *cipher_) : cipher(cipher_), ctx(EVP_CIPHER_CTX_new(),
                                                                           [](EVP_CIPHER_CTX *p)
                                                                           {
                                                                               if (p)
                                                                               {
                                                                                   EVP_CIPHER_CTX_free(p);
                                                                               }
                                                                           })
        {
        }

        bool NeedsTag()
        {
            return (EVP_CIPHER_get_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER) != 0;
        }

        int IvLength() const
        {
            return EVP_CIPHER_iv_length(cipher);
        }

        void SetIv(const unsigned char *iv_)
        {
            iv = iv_;
        }

        void SetKey(const unsigned char *key_)
        {
            key = key_;
        }

        void SetTag(unsigned char *tag_)
        {
            in_tag = tag_;
        }

        std::string GetTag()
        {

            std::string tag;
            tag.resize(GCM_TAG_SIZE);
            if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, GCM_TAG_SIZE, reinterpret_cast<unsigned char *>(&tag[0])))
            {
                throwOpensslError("Failed to get tag");
            }
            return tag;
        }

        void Init(int mode)
        {

            if (!EVP_CipherInit_ex(ctx.get(), cipher, nullptr, nullptr, nullptr, mode))
            {
                throwOpensslError("Failed to initialize cipher");
            }

            if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, IvLength(), nullptr))
            {
                throwOpensslError("Failed to set iv length");
            }

            if (!EVP_CipherInit_ex(ctx.get(), cipher, nullptr, key, iv, mode))
            {
                throwOpensslError("Failed to initialize cipher");
            }

            if (NeedsTag() && mode == MODE_DECRYPT)
            {
                if (in_tag == nullptr)
                {
                    throw InvalidInputException("Decryption mode for AEAD cipher requires a tag to be set");
                }
                // Decryption mode, set expected tag
                if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, 16, in_tag))
                {
                    throwOpensslError("Failed to set expected tag");
                }
            }
        }

        std::string Update(const std::string &data)
        {
            return Update(reinterpret_cast<const unsigned char *>(data.data()), data.size());
        }

        std::string Update(const unsigned char *data, size_t size)
        {
            int outlen = 0;
            std::string out;
            out.resize(size + EVP_CIPHER_block_size(cipher));
            if (EVP_CipherUpdate(ctx.get(), reinterpret_cast<unsigned char *>(&out[0]), &outlen,
                                 data, size) != 1)
            {
                throwOpensslError("Failed to update cipher");
            }
            out.resize(outlen);
            return out;
        }

        std::string Finalize()
        {

            std::string result;
            result.resize(EVP_CIPHER_block_size(cipher));
            int result_len = 0;
            if (EVP_CipherFinal_ex(ctx.get(), reinterpret_cast<unsigned char *>(&result[0]), &result_len) != 1)
            {
                throwOpensslError("Failed to finalize cipher");
            }

            result.resize(result_len);
            return result;
        }

        EvpCipherContext(const EvpCipherContext &) = delete;
        EvpCipherContext &operator=(const EvpCipherContext &) = delete;

        // Enable move operations (needed because copy is deleted)
        EvpCipherContext(EvpCipherContext &&) = default;
        EvpCipherContext &operator=(EvpCipherContext &&) = default;

    private:
        // We don't own these
        const EVP_CIPHER *cipher = nullptr;
        const unsigned char *iv = nullptr;
        const unsigned char *key = nullptr;
        unsigned char *in_tag = nullptr;

        std::unique_ptr<EVP_CIPHER_CTX, void (*)(EVP_CIPHER_CTX *)> ctx;
    };

    // This is dramatically simplefied wrapper for an encrypted text blob
    // It expects to be used with the Plaintext class
    // It will do AES AEAD
    class CipherText
    {

    public:
        /// @brief
        /// @param cipher
        /// @param ciphertext - this is the raw ciphertext bytes, it will be iv + encrypted bytes + tag
        CipherText(const EVP_CIPHER *cipher, std::string ciphertext_) : ciphertext(ciphertext_), ctx(cipher)
        {
        }

        static CipherText Encrypt(const EVP_CIPHER *cipher, const unsigned char *key, const std::string &plaintext)
        {
            EvpCipherContext ctx(cipher);

            std::string iv = generate_random_string(ctx.IvLength());

            ctx.SetKey(key);
            ctx.SetIv(reinterpret_cast<const unsigned char *>(iv.data()));
            ctx.Init(MODE_ENCRYPT); // 1 for encrypt

            std::string encrypted = ctx.Update(plaintext);
            encrypted += ctx.Finalize();

            std::string ciphertext = iv + encrypted;
            if (ctx.NeedsTag())
            {
                std::string tag = ctx.GetTag();
                ciphertext += tag;
            }

            return CipherText(cipher, ciphertext);
        }

        const char *GetTag() const
        {
            // Tag is last 16 bytes
            return ciphertext.data() + ciphertext.size() - 16;
        }

        const char *GetIv() const
        {
            // IV is first iv_length bytes
            return ciphertext.data();
        }

        const char *GetEncryptedData() const
        {
            // Encrypted data is between iv and tag
            return ciphertext.data() + ctx.IvLength();
        }

        // std::string Update(const unsigned char *data, size_t size)

        std::string Decrypt(const unsigned char *key)
        {
            ctx.SetKey(key);
            ctx.SetIv(reinterpret_cast<const unsigned char *>(GetIv()));
            ctx.SetTag(reinterpret_cast<unsigned char *>(const_cast<char *>(GetTag())));
            ctx.Init(MODE_DECRYPT);
            std::string decrypted = ctx.Update(reinterpret_cast<const unsigned char *>(GetEncryptedData()),
                                               ciphertext.size() - ctx.IvLength() - 16);
            decrypted += ctx.Finalize();
            return decrypted;
        }

        std::string &GetValue()
        {
            return ciphertext;
        }

        CipherText(const CipherText &) = delete;
        CipherText &operator=(const CipherText &) = delete;

        // Enable move operations (needed because copy is deleted)
        CipherText(CipherText &&) = default;
        CipherText &operator=(CipherText &&) = default;

        std::string ciphertext;
        EvpCipherContext ctx;
        std::string tag = "";
    };

    //     // TODO: handle key and iv size checks
    //     // TODO: handle padding if necessary
    //     // TODO: handle output buffer size
    //     // TODO: handle different modes of operation
    //     evp_ctx.Init(cipher, key, iv);
    //     evp_ctx.Update(data, data_len);
    //     evp_ctx.Finalize();
    // }

    inline void CryptoScalarFun(DataChunk &args, ExpressionState &state, Vector &result, int mode)
    {
        // This is called with three arguments:
        // 1. The cipher name
        // 2. The key
        // 3. The value
        //

        auto &hash_function_name_vector = args.data[0];
        auto &key_vector = args.data[1];
        auto &value_vector = args.data[2];

        TernaryExecutor::Execute<string_t, string_t, string_t, string_t>(
            hash_function_name_vector, key_vector, value_vector, result, args.size(),
            [&](string_t cipher_name, string_t key, string_t value)
            {
                string algorithm(cipher_name.GetData(), cipher_name.GetSize());
                string key_str(key.GetData(), key.GetSize());
                string value_str(value.GetData(), value.GetSize());

                // TODO: handle iv properly
                // TODO: only allow the algorithm to be set once  instead of per row
                std::string algo_lower = StringUtil::Lower(algorithm);
                const EVP_CIPHER *cipher = EVP_get_cipherbyname(algo_lower.c_str());

                if (!cipher)
                {
                    throw InvalidInputException("Invalid ciphername '" + algorithm + "'");
                }

                if (mode == 0)
                { // decrypt
                    CipherText ct(cipher, value_str);
                    std::string decrypted = ct.Decrypt(reinterpret_cast<const unsigned char *>(key_str.data()));
                    return StringVector::AddStringOrBlob(result, string_t(decrypted.data(), decrypted.size()));
                }
                else if (mode == 1)
                { // encrypt
                    CipherText ct = CipherText::Encrypt(cipher, reinterpret_cast<const unsigned char *>(key_str.data()), value_str);
                    return StringVector::AddStringOrBlob(result, string_t(ct.GetValue().data(), ct.GetValue().size()));
                }
                else
                {
                    throw InternalException("Invalid mode for CryptoScalarFun");
                }
            });
    }

    inline void CryptoScalarEncryptFun(DataChunk &args, ExpressionState &state, Vector &result)
    {
        CryptoScalarFun(args, state, result, MODE_ENCRYPT);
    }

    inline void CryptoScalarDecryptFun(DataChunk &args, ExpressionState &state, Vector &result)
    {
        CryptoScalarFun(args, state, result, MODE_DECRYPT);
    }

    void LoadCipherInternal(ExtensionLoader &loader)
    {
        // crypto_hash accepts VARCHAR for algorithm name and ANY type for the data to hash
        auto crypto_encrypt_scalar_function = ScalarFunction("crypto_encrypt", {LogicalType::VARCHAR, LogicalType::BLOB, LogicalType::ANY}, LogicalType::BLOB, CryptoScalarEncryptFun);
        loader.RegisterFunction(crypto_encrypt_scalar_function);

        auto crypto_decrypt_scalar_function = ScalarFunction("crypto_decrypt", {LogicalType::VARCHAR, LogicalType::BLOB, LogicalType::ANY}, LogicalType::BLOB, CryptoScalarDecryptFun);
        loader.RegisterFunction(crypto_decrypt_scalar_function);
    }

};