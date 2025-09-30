#define DUCKDB_EXTENSION_MAIN

#include "crypto_extension.hpp"
#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/scalar_function.hpp"
#include <duckdb/parser/parsed_data/create_scalar_function_info.hpp>

// Include the declarations of things from Rust.
#include "rust.h"
#include "query_farm_telemetry.hpp"

namespace duckdb
{
    // Helper function to free memory allocated by Rust functions
    // Both Ok and Err cases allocate memory that must be freed after use
    // DuckDB's StringVector::AddString copies the string but does NOT take ownership
    static void FreeResultCString(ResultCString &result) {
        if (result.tag == ResultCString::Tag::Ok && result.ok._0 != nullptr) {
            duckdb_free(result.ok._0);
        } else if (result.tag == ResultCString::Tag::Err && result.err._0 != nullptr) {
            duckdb_free(result.err._0);
        }
    }

    inline void CryptoScalarHashFun(DataChunk &args, ExpressionState &state, Vector &result)
    {
        auto &hash_name_vector = args.data[0];
        auto &value_vector = args.data[1];

        BinaryExecutor::Execute<string_t, string_t, string_t>(
            hash_name_vector, value_vector, result, args.size(),
            [&](string_t hash_name, string_t value)
            {
                // Call Rust function - this allocates memory that we must free
                auto hash_result = hashing_varchar(hash_name.GetData(), hash_name.GetSize(), value.GetData(), value.GetSize());

                if (hash_result.tag == ResultCString::Tag::Err)
                {
                    // Copy error message before freeing Rust memory
                    std::string error_msg(hash_result.err._0);
                    FreeResultCString(hash_result);
                    throw InvalidInputException(error_msg);
                }

                // Copy string to DuckDB memory, then free Rust memory
                auto output = StringVector::AddString(result, hash_result.ok._0);
                FreeResultCString(hash_result);
                return output;
            });
    }

    inline void CryptoScalarHmacFun(DataChunk &args, ExpressionState &state, Vector &result)
    {
        // This is called with three arguments:
        // 1. The hash function name
        // 2. The key
        // 3. The value
        //
        // The return value is the hex-encoded HMAC.
        auto &hash_function_name_vector = args.data[0];
        auto &key_vector = args.data[1];
        auto &value_vector = args.data[2];

        TernaryExecutor::Execute<string_t, string_t, string_t, string_t>(
            hash_function_name_vector, key_vector, value_vector, result, args.size(),
            [&](string_t hash_function_name, string_t key, string_t value)
            {
                // Call Rust function - this allocates memory that we must free
                auto hmac_result = hmac_varchar(hash_function_name.GetData(), hash_function_name.GetSize(),
                                                key.GetData(), key.GetSize(),
                                                value.GetData(), value.GetSize());

                if (hmac_result.tag == ResultCString::Tag::Err)
                {
                    // Copy error message before freeing Rust memory
                    std::string error_msg(hmac_result.err._0);
                    FreeResultCString(hmac_result);
                    throw InvalidInputException(error_msg);
                }

                // Copy string to DuckDB memory, then free Rust memory
                auto output = StringVector::AddString(result, hmac_result.ok._0);
                FreeResultCString(hmac_result);
                return output;
            });
    }

    static void LoadInternal(ExtensionLoader &loader)
    {
        // Pass the allocation functions to Rust so that it can call duckdb_malloc and duckdb_free
        init_memory_allocation(duckdb_malloc, duckdb_free);

        auto crypto_hash_scalar_function = ScalarFunction("crypto_hash", {LogicalType::VARCHAR, LogicalType::VARCHAR}, LogicalType::VARCHAR, CryptoScalarHashFun);
        loader.RegisterFunction(crypto_hash_scalar_function);

        auto crypto_hmac_scalar_function = ScalarFunction("crypto_hmac", {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR}, LogicalType::VARCHAR, CryptoScalarHmacFun);
        loader.RegisterFunction(crypto_hmac_scalar_function);

        // QueryFarmSendTelemetry(loader, "crypto", "2025092301"); // Disabled for DuckDB 1.4.0 compatibility
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
