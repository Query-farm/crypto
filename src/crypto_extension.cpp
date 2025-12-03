#define DUCKDB_EXTENSION_MAIN

#include "crypto_extension.hpp"
#include "crypto_hash.hpp"
#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/scalar_function.hpp"
#include <duckdb/parser/parsed_data/create_scalar_function_info.hpp>
#include <openssl/evp.h>
#include <algorithm>
#include <cctype>
#include <unordered_map>
#include <functional>
#include "blake3.h"

#include "query_farm_telemetry.hpp"

namespace duckdb
{
    namespace
    {
        // RAII wrapper for EVP_MD_CTX
        class EVPContext
        {
        public:
            EVPContext()
            {
                ctx = EVP_MD_CTX_new();
                if (ctx == nullptr)
                {
                    throw InternalException("Failed to create hash context");
                }
            }

            ~EVPContext()
            {
                if (ctx)
                {
                    EVP_MD_CTX_free(ctx);
                }
            }

            EVPContext(const EVPContext &) = delete;
            EVPContext &operator=(const EVPContext &) = delete;

            void Init(const EVP_MD *md)
            {
                if (EVP_DigestInit_ex(ctx, md, nullptr) != 1)
                {
                    throw InternalException("Failed to initialize hash context");
                }
            }

            void Update(const void *data, size_t len)
            {
                if (EVP_DigestUpdate(ctx, data, len) != 1)
                {
                    throw InternalException("Failed to update hash");
                }
            }

            void Finalize(unsigned char *result, unsigned int &result_len)
            {
                if (EVP_DigestFinal_ex(ctx, result, &result_len) != 1)
                {
                    throw InternalException("Failed to finalize hash");
                }
            }

            EVP_MD_CTX *Get() { return ctx; }

        private:
            EVP_MD_CTX *ctx;
        };

        // Helper to hash a single list element with Blake3
        void HashListElementBlake3(blake3_hasher &hasher, const LogicalType &child_type,
                                   UnifiedVectorFormat &child_format, idx_t child_idx)
        {
            if (child_type == LogicalType::VARCHAR || child_type == LogicalType::BLOB)
            {
                auto child_strings = UnifiedVectorFormat::GetData<string_t>(child_format);
                auto &str_val = child_strings[child_idx];
                auto str_len = str_val.GetSize();

                uint64_t len_val = static_cast<uint64_t>(str_len);
                blake3_hasher_update(&hasher, &len_val, sizeof(len_val));
                blake3_hasher_update(&hasher, str_val.GetData(), str_len);
            }
            else if (child_type.IsValid() && child_type.InternalType() != PhysicalType::INVALID)
            {
                auto type_size = GetTypeIdSize(child_type.InternalType());
                auto data_ptr = reinterpret_cast<const char *>(child_format.data) + (child_idx * type_size);
                blake3_hasher_update(&hasher, data_ptr, type_size);
            }
            else
            {
                throw InvalidInputException("Unsupported child type in list for crypto_hash");
            }
        }

        // Helper to hash a single list element with EVP
        void HashListElementEVP(EVPContext &evp_ctx, const LogicalType &child_type,
                                UnifiedVectorFormat &child_format, idx_t child_idx)
        {
            if (child_type == LogicalType::VARCHAR || child_type == LogicalType::BLOB)
            {
                auto child_strings = UnifiedVectorFormat::GetData<string_t>(child_format);
                auto &str_val = child_strings[child_idx];
                auto str_len = str_val.GetSize();

                uint64_t len_val = static_cast<uint64_t>(str_len);
                evp_ctx.Update(&len_val, sizeof(len_val));
                evp_ctx.Update(str_val.GetData(), str_len);
            }
            else if (child_type.IsValid() && child_type.InternalType() != PhysicalType::INVALID)
            {
                auto type_size = GetTypeIdSize(child_type.InternalType());
                auto data_ptr = reinterpret_cast<const char *>(child_format.data) + (child_idx * type_size);
                evp_ctx.Update(data_ptr, type_size);
            }
            else
            {
                throw InvalidInputException("Unsupported child type in list for crypto_hash");
            }
        }

        // Helper to lookup algorithm - returns nullptr for blake3, throws on invalid algorithm
        const EVP_MD *LookupAlgorithm(const std::string &hash_name_str)
        {
            if (hash_name_str == "blake3")
            {
                return nullptr;
            }

            auto it = GetDigestMap().find(hash_name_str);
            if (it != GetDigestMap().end())
            {
                return it->second();
            }

            throw InvalidInputException("Invalid hash algorithm '" + hash_name_str + "'");
        }
    }

    inline void CryptoScalarHashFun(DataChunk &args, ExpressionState &state, Vector &result)
    {
        auto &hash_name_vector = args.data[0];
        auto &value_vector = args.data[1];
        auto count = args.size();

        // Get unified format for both vectors
        UnifiedVectorFormat hash_name_data;
        UnifiedVectorFormat value_data;
        hash_name_vector.ToUnifiedFormat(count, hash_name_data);
        value_vector.ToUnifiedFormat(count, value_data);

        auto hash_names = UnifiedVectorFormat::GetData<string_t>(hash_name_data);
        auto &value_type = value_vector.GetType();

        auto results = FlatVector::GetData<string_t>(result);

        // Process each row
        for (idx_t i = 0; i < count; i++)
        {
            auto hash_idx = hash_name_data.sel->get_index(i);
            auto value_idx = value_data.sel->get_index(i);

            if (!hash_name_data.validity.RowIsValid(hash_idx) || !value_data.validity.RowIsValid(value_idx))
            {
                FlatVector::SetNull(result, i, true);
                continue;
            }

            string hash_name_str = StringUtil::Lower(hash_names[hash_idx].GetString());

            unsigned char hash_result[EVP_MAX_MD_SIZE];
            unsigned int hash_len = 0;

            const EVP_MD *md = LookupAlgorithm(hash_name_str);

            // Handle different input types
            if (value_type == LogicalType::VARCHAR || value_type == LogicalType::BLOB)
            {
                // Handle VARCHAR and BLOB
                auto values = UnifiedVectorFormat::GetData<string_t>(value_data);
                auto data_ptr = values[value_idx].GetData();
                auto data_len = values[value_idx].GetSize();
                CryptoHash(hash_name_str, data_ptr, data_len, hash_result, hash_len);
            }
            else if (value_type.IsNested() && value_type.InternalType() == PhysicalType::LIST)
            {
                // Handle LIST types
                const auto &list_child_type = ListType::GetChildType(value_type);

                // Validate child type - no nested lists, structs, or maps
                if (list_child_type.IsNested())
                {
                    throw InvalidInputException("Unsupported type for crypto_hash: nested types inside of lists are not supported");
                }

                // Get list data
                auto list_data = UnifiedVectorFormat::GetData<list_entry_t>(value_data);
                auto &list_entry = list_data[value_idx];

                // Get the child vector
                auto &child_vector = ListVector::GetEntry(value_vector);
                UnifiedVectorFormat child_format;
                child_vector.ToUnifiedFormat(ListVector::GetListSize(value_vector), child_format);

                if (hash_name_str == "blake3")
                {
                    blake3_hasher hasher;
                    blake3_hasher_init(&hasher);

                    for (idx_t list_idx = 0; list_idx < list_entry.length; list_idx++)
                    {
                        auto child_idx = child_format.sel->get_index(list_entry.offset + list_idx);
                        if (!child_format.validity.RowIsValid(child_idx))
                        {
                            throw InvalidInputException("Unsupported type for crypto_hash: NULL elements inside lists are not supported");
                        }
                        HashListElementBlake3(hasher, list_child_type, child_format, child_idx);
                    }

                    blake3_hasher_finalize(&hasher, hash_result, BLAKE3_OUT_LEN);
                    hash_len = BLAKE3_OUT_LEN;
                }
                else
                {
                    EVPContext evp_ctx;
                    evp_ctx.Init(md);

                    for (idx_t list_idx = 0; list_idx < list_entry.length; list_idx++)
                    {
                        auto child_idx = child_format.sel->get_index(list_entry.offset + list_idx);
                        if (!child_format.validity.RowIsValid(child_idx))
                        {
                            throw InvalidInputException("Unsupported type for crypto_hash: NULL elements inside lists are not supported");
                        }
                        HashListElementEVP(evp_ctx, list_child_type, child_format, child_idx);
                    }

                    evp_ctx.Finalize(hash_result, hash_len);
                }
            }
            else if (value_type.id() == LogicalTypeId::STRUCT || value_type.id() == LogicalTypeId::MAP)
            {
                // Explicitly reject STRUCT and MAP types
                throw InvalidInputException("Unsupported type for crypto_hash");
            }
            else if (value_type.IsValid() && value_type.InternalType() != PhysicalType::INVALID)
            {
                // Handle fixed-length types by getting their raw binary representation
                auto data = value_data.data;
                auto type_size = GetTypeIdSize(value_type.InternalType());
                auto data_ptr = reinterpret_cast<const char *>(data) + (value_idx * type_size);
                CryptoHash(hash_name_str, data_ptr, type_size, hash_result, hash_len);
            }
            else
            {
                throw InvalidInputException("Unsupported type for crypto_hash");
            }

            results[i] = StringVector::AddStringOrBlob(result, string_t(reinterpret_cast<const char *>(hash_result), hash_len));
        }

        if (count == 1)
        {
            result.SetVectorType(VectorType::CONSTANT_VECTOR);
        }
    }

    inline void CryptoScalarHmacFun(DataChunk &args, ExpressionState &state, Vector &result)
    {
        // This is called with three arguments:
        // 1. The hash function name
        // 2. The key
        // 3. The value
        //
        // The return value is the binary HMAC.
        auto &hash_function_name_vector = args.data[0];
        auto &key_vector = args.data[1];
        auto &value_vector = args.data[2];

        TernaryExecutor::Execute<string_t, string_t, string_t, string_t>(
            hash_function_name_vector, key_vector, value_vector, result, args.size(),
            [&](string_t hash_function_name, string_t key, string_t value)
            {
                string hash_name_str(hash_function_name.GetData(), hash_function_name.GetSize());
                string key_str(key.GetData(), key.GetSize());
                string value_str(value.GetData(), value.GetSize());

                unsigned char hmac_result[EVP_MAX_MD_SIZE];
                unsigned int hmac_len = 0;
                CryptoHmac(hash_name_str, key_str, value_str, hmac_result, hmac_len);

                return StringVector::AddStringOrBlob(result, string_t(reinterpret_cast<const char *>(hmac_result), hmac_len));
            });
    }

    struct HashAggregateState
    {
        bool is_touched;
        blake3_hasher b3_hasher;
        EVP_MD_CTX *ctx;

        HashAggregateState()
        {
            is_touched = false;
            blake3_hasher_init(&b3_hasher);
            ctx = nullptr;
        }
    };

    struct HashAggregateBindData : public FunctionData
    {
        explicit HashAggregateBindData(bool is_blake_3, const EVP_MD *md) : is_blake3(is_blake_3), md(md)
        {
        }

        unique_ptr<FunctionData> Copy() const override
        {
            return make_uniq<HashAggregateBindData>(is_blake3, md);
        }

        bool Equals(const FunctionData &other_p) const override
        {
            auto &other = other_p.Cast<HashAggregateBindData>();
            return md == other.md && is_blake3 == other.is_blake3;
        }

        const bool is_blake3;
        const EVP_MD *md;
    };

    template <class STATE_DATA_TYPE>
    struct HashAggregateOperation
    {
        template <class STATE>
        static void Initialize(STATE &state)
        {
            // So this may fill the state with random garbage
            state.ctx = nullptr;
            state.is_touched = false;
            blake3_hasher_init(&state.b3_hasher);
        }

        template <class STATE>
        static void Destroy(STATE &state, AggregateInputData &aggr_input_data)
        {
            if (state.ctx)
            {
                EVP_MD_CTX_free(state.ctx);
                state.ctx = nullptr;
            }
        }

        static bool IgnoreNull()
        {
            return false;
        }

        template <class A_TYPE, class STATE, class OP>
        static void Operation(STATE &state, const A_TYPE &a_data, AggregateUnaryInput &idata)
        {
            // So determine the bind data.
            auto &bind_data = idata.input.bind_data->Cast<HashAggregateBindData>();

            if (bind_data.is_blake3)
            {
                if (!state.is_touched)
                {
                    blake3_hasher_init(&state.b3_hasher);
                    state.is_touched = true;
                }

                // hash the record length as well to prevent length extension attacks
                if constexpr (std::is_same_v<A_TYPE, string_t>)
                {
                    const uint64_t size = a_data.GetSize();
                    blake3_hasher_update(&state.b3_hasher, &size, sizeof(uint64_t));
                    blake3_hasher_update(&state.b3_hasher, a_data.GetDataUnsafe(), size);
                }
                else
                {
                    blake3_hasher_update(&state.b3_hasher, &a_data, sizeof(a_data));
                }
            }
            else
            {
                if (!state.is_touched)
                {
                    state.ctx = EVP_MD_CTX_new();
                    if (EVP_DigestInit_ex(state.ctx, bind_data.md, nullptr) != 1)
                    {
                        throw InternalException("Failed to initialize hash context");
                    }
                    state.is_touched = true;
                }

                if constexpr (std::is_same_v<A_TYPE, string_t>)
                {
                    const uint64_t size = a_data.GetSize();
                    if (EVP_DigestUpdate(state.ctx, &size, sizeof(uint64_t)) != 1)
                    {
                        throw InternalException("Failed to update hash");
                    }

                    if (EVP_DigestUpdate(state.ctx, a_data.GetDataUnsafe(), size) != 1)
                    {
                        throw InternalException("Failed to update hash");
                    }
                }
                else
                {
                    if (EVP_DigestUpdate(state.ctx, &a_data, sizeof(a_data)) != 1)
                    {
                        throw InternalException("Failed to update hash");
                    }
                }
            }
        }

        template <class INPUT_TYPE, class STATE, class OP>
        static void ConstantOperation(STATE &state, const INPUT_TYPE &input, AggregateUnaryInput &unary_input,
                                      idx_t count)
        {
            for (idx_t i = 0; i < count; i++)
            {
                Operation<INPUT_TYPE, STATE, OP>(state, input, unary_input);
            }
        }

        template <class STATE, class OP>
        static void Combine(const STATE &source, STATE &target, AggregateInputData &aggr_input_data)
        {
            auto &bind_data = aggr_input_data.bind_data->Cast<HashAggregateBindData>();
            const bool source_used = source.is_touched;
            const bool target_used = target.is_touched;

            if (source_used && !target_used)
            {
                if (bind_data.is_blake3)
                {
                    target.b3_hasher = source.b3_hasher;
                }
                else
                {
                    target.ctx = EVP_MD_CTX_new();
                    EVP_MD_CTX_copy_ex(target.ctx, source.ctx);
                }
                target.is_touched = true;
            }
            else if (!source_used)
            {
                // nothing to do
                return;
            }
            throw InvalidInputException("Hash aggregation requires a distinct total ordering, example: crypto_hash_agg('blake3', data ORDER BY "
                                        "data) columns in group by clauses are not sufficient");
        }

        template <class T, class STATE>
        static void Finalize(STATE &state, T &target, AggregateFinalizeData &finalize_data)
        {
            auto &bind_data = finalize_data.input.bind_data->Cast<HashAggregateBindData>();
            if (bind_data.is_blake3)
            {
                if (!state.is_touched)
                {
                    finalize_data.ReturnNull();
                    return;
                }
                char output[BLAKE3_OUT_LEN];
                blake3_hasher_finalize(&state.b3_hasher, reinterpret_cast<uint8_t *>(&output), BLAKE3_OUT_LEN);
                target = StringVector::AddStringOrBlob(finalize_data.result, reinterpret_cast<const char *>(&output),
                                                       BLAKE3_OUT_LEN);
            }
            else
            {
                if (!state.ctx)
                {
                    finalize_data.ReturnNull();
                    return;
                }

                unsigned char hash_result[EVP_MAX_MD_SIZE];
                unsigned int hash_len = 0;
                // Finalize the hash
                if (EVP_DigestFinal_ex(state.ctx, hash_result, &hash_len) != 1)
                {
                    throw InternalException("Failed to finalize hash");
                }
                target = StringVector::AddStringOrBlob(finalize_data.result, reinterpret_cast<const char *>(&hash_result),
                                                       hash_len);
            }
        }
    };

    unique_ptr<FunctionData> HashAggregateBind(ClientContext &context, AggregateFunction &function,
                                               vector<unique_ptr<Expression>> &arguments)
    {
        // The first argument is the hash algorithm name
        bool is_blake3 = false;
        const EVP_MD *md = nullptr;

        if (arguments.size() == 1)
        {
            // The bind has already happened, return nullptr to indicate no further binding is needed
            return nullptr;
        }

        if (arguments.size() != 2)
        {
            throw InvalidInputException("crypto_hash_agg requires at least two arguments: algorithm name and data");
        }

        if (arguments[0]->HasParameter())
        {
            throw ParameterNotResolvedException();
        }
        if (!arguments[0]->IsFoldable())
        {
            throw BinderException("crypto_hash_agg can only take a constant hash algorithm name as its first argument");
        }
        Value hash_algo_value = ExpressionExecutor::EvaluateScalar(context, *arguments[0]);
        if (hash_algo_value.IsNull())
        {
            throw BinderException("crypto_hash_agg hash algorithm name cannot be NULL");
        }

        auto cached_hash_name = hash_algo_value.GetValue<std::string>();
        std::transform(cached_hash_name.begin(), cached_hash_name.end(), cached_hash_name.begin(), ::tolower);

        md = LookupAlgorithm(cached_hash_name);
        is_blake3 = (md == nullptr);

        Function::EraseArgument(function, arguments, 0);
        return make_uniq<HashAggregateBindData>(is_blake3, md);
    }

    // Helper function to register a variable-size type aggregate (VARCHAR, BLOB)
    template <typename CPP_TYPE>
    static void RegisterHashAggType(AggregateFunctionSet &agg_set, const LogicalType &logical_type)
    {
        auto agg_func =
            AggregateFunction::UnaryAggregateDestructor<HashAggregateState, CPP_TYPE, string_t, HashAggregateOperation<HashAggregateState>>(
                logical_type, LogicalType::BLOB);
        agg_func.order_dependent = AggregateOrderDependent::ORDER_DEPENDENT;
        agg_func.distinct_dependent = AggregateDistinctDependent::DISTINCT_DEPENDENT;
        agg_func.bind = HashAggregateBind;
        // Add the argument for the algorithm name
        agg_func.arguments.insert(agg_func.arguments.begin(), LogicalType::VARCHAR);
        agg_set.AddFunction(agg_func);
    }

    static void LoadInternal(ExtensionLoader &loader)
    {
        // crypto_hash accepts VARCHAR for algorithm name and ANY type for the data to hash
        auto crypto_hash_scalar_function = ScalarFunction("crypto_hash", {LogicalType::VARCHAR, LogicalType::ANY}, LogicalType::BLOB, CryptoScalarHashFun);
        loader.RegisterFunction(crypto_hash_scalar_function);

        auto crypto_hmac_scalar_function = ScalarFunction("crypto_hmac", {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR}, LogicalType::BLOB, CryptoScalarHmacFun);
        loader.RegisterFunction(crypto_hmac_scalar_function);

        auto agg_set = AggregateFunctionSet("crypto_hash_agg");

        // Variable-size types (include size prefix to prevent length extension attacks)
        RegisterHashAggType<string_t>(agg_set, LogicalType::VARCHAR);
        RegisterHashAggType<string_t>(agg_set, LogicalType::BLOB);

        // Fixed-size integer types
        RegisterHashAggType<int8_t>(agg_set, LogicalType::TINYINT);
        RegisterHashAggType<int16_t>(agg_set, LogicalType::SMALLINT);
        RegisterHashAggType<int32_t>(agg_set, LogicalType::INTEGER);
        RegisterHashAggType<int64_t>(agg_set, LogicalType::BIGINT);
        RegisterHashAggType<uint8_t>(agg_set, LogicalType::UTINYINT);
        RegisterHashAggType<uint16_t>(agg_set, LogicalType::USMALLINT);
        RegisterHashAggType<uint32_t>(agg_set, LogicalType::UINTEGER);
        RegisterHashAggType<uint64_t>(agg_set, LogicalType::UBIGINT);
        RegisterHashAggType<hugeint_t>(agg_set, LogicalType::HUGEINT);
        RegisterHashAggType<uhugeint_t>(agg_set, LogicalType::UHUGEINT);

        // // Fixed-size floating point types
        RegisterHashAggType<float>(agg_set, LogicalType::FLOAT);
        RegisterHashAggType<double>(agg_set, LogicalType::DOUBLE);

        loader.RegisterFunction(agg_set);

        QueryFarmSendTelemetry(loader, "crypto", "2025120201");
    }

    void CryptoExtension::Load(ExtensionLoader &loader)
    {
        LoadInternal(loader);
    }
    std::string CryptoExtension::Name()
    {
        return "crypto";
    }

} // namespace duckdb

extern "C"
{

    DUCKDB_CPP_EXTENSION_ENTRY(crypto, loader)
    {
        duckdb::LoadInternal(loader);
    }
}
