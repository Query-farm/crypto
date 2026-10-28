#define DUCKDB_EXTENSION_MAIN

#include "crypto_extension.hpp"
#include "crypto_hash.hpp"
#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/function/table_function.hpp"
#include <duckdb/parser/parsed_data/create_scalar_function_info.hpp>
#include <duckdb/parser/parsed_data/create_aggregate_function_info.hpp>
#include <duckdb/parser/parsed_data/create_table_function_info.hpp>
#include "duckdb/common/vector/flat_vector.hpp"
#include "duckdb/common/vector/list_vector.hpp"
#include "duckdb/common/vector/array_vector.hpp"
#include "duckdb/common/vector/string_vector.hpp"
#include "duckdb/common/vector/unified_vector_format.hpp"
#include "duckdb/execution/expression_executor.hpp"
#include "duckdb/execution/expression_executor_state.hpp"
#include "duckdb/storage/buffer_manager.hpp"
#include "duckdb/optimizer/aggregate_rewrite.hpp"
#include "duckdb/planner/expression/bound_aggregate_expression.hpp"
#include <openssl/evp.h>
#include "blake3.h"

#include "query_farm_telemetry.hpp"

namespace duckdb
{
    namespace
    {
        // Upper bound on the memory OpenSSL allocates for one digest context, reserved against memory_limit
        constexpr idx_t EVP_CONTEXT_RESERVATION = 512;

        constexpr const char *HASH_AGG_ORDER_ERROR =
            "Hash aggregation requires a distinct total ordering, example: crypto_hash_agg('blake3', data ORDER BY "
            "data) columns in group by clauses are not sufficient";

        bool IsStringType(const LogicalType &type)
        {
            return type.InternalType() == PhysicalType::VARCHAR;
        }

        //! Prepares a crypto_hash() value argument (scalar, LIST or ARRAY) and hashes one row of it
        class HashValueInput
        {
        public:
            explicit HashValueInput(Vector &vector) : type(vector.GetType())
            {
                CryptoValueEncoder::Validate(type, true);
                vector.ToUnifiedFormat(data);
                if (type.id() == LogicalTypeId::LIST)
                {
                    child_type = &ListType::GetChildType(type);
                    ListVector::GetChild(vector).ToUnifiedFormat(child_data);
                }
                else if (type.id() == LogicalTypeId::ARRAY)
                {
                    child_type = &ArrayType::GetChildType(type);
                    array_size = ArrayType::GetSize(type);
                    ArrayVector::GetChild(vector).ToUnifiedFormat(child_data);
                }
            }

            //! Returns the unified index of row i, or invalid when the row is NULL
            optional_idx RowIndex(idx_t i) const
            {
                auto idx = data.sel->get_index(i);
                if (!data.validity.RowIsValid(idx))
                {
                    return optional_idx();
                }
                return idx;
            }

            template <class HASHER>
            void Hash(HASHER &hasher, idx_t idx) const
            {
                if (!child_type)
                {
                    CryptoValueEncoder::Encode(hasher, type, data, idx, false);
                    return;
                }
                idx_t offset;
                idx_t length;
                if (type.id() == LogicalTypeId::LIST)
                {
                    auto &entry = UnifiedVectorFormat::GetData<list_entry_t>(data)[idx];
                    offset = entry.offset;
                    length = entry.length;
                }
                else
                {
                    offset = idx * array_size;
                    length = array_size;
                }
                for (idx_t j = 0; j < length; j++)
                {
                    auto child_idx = child_data.sel->get_index(offset + j);
                    if (!child_data.validity.RowIsValid(child_idx))
                    {
                        throw InvalidInputException(
                            "Unsupported type for crypto_hash: NULL elements inside lists are not supported");
                    }
                    CryptoValueEncoder::Encode(hasher, *child_type, child_data, child_idx, true);
                }
            }

        private:
            const LogicalType &type;
            UnifiedVectorFormat data;
            optional_ptr<const LogicalType> child_type;
            UnifiedVectorFormat child_data;
            idx_t array_size = 0;
        };

        struct CryptoHashLocalState : public FunctionLocalState
        {
            CryptoAlgorithmCache algorithms;
            CryptoHasher hasher;
        };

        struct CryptoHmacLocalState : public FunctionLocalState
        {
            CryptoAlgorithmCache algorithms;
            CryptoHmacContext hmac;
        };

        template <class STATE>
        unique_ptr<FunctionLocalState> InitLocalState(ExpressionState &state, const BoundFunctionExpression &expr,
                                                      FunctionData *bind_data)
        {
            return make_uniq<STATE>();
        }

        template <class STATE>
        STATE &GetLocalState(ExpressionState &state)
        {
            return ExecuteFunctionState::GetFunctionState(state)->Cast<STATE>();
        }

        bool AllConstant(DataChunk &args)
        {
            for (auto &vector : args.data)
            {
                if (vector.GetVectorType() != VectorType::CONSTANT_VECTOR)
                {
                    return false;
                }
            }
            return true;
        }

        //! Evaluates only the first row when every argument is constant
        void FinishResult(DataChunk &args, Vector &result, bool all_constant)
        {
            if (all_constant)
            {
                result.SetVectorType(VectorType::CONSTANT_VECTOR);
            }
        }
    } // namespace

    inline void CryptoScalarHashFun(DataChunk &args, ExpressionState &state, Vector &result)
    {
        auto &lstate = GetLocalState<CryptoHashLocalState>(state);
        auto &hasher = lstate.hasher;
        const bool all_constant = AllConstant(args);
        const idx_t count = all_constant ? 1 : args.size();

        UnifiedVectorFormat hash_name_data;
        args.data[0].ToUnifiedFormat(hash_name_data);
        auto hash_names = UnifiedVectorFormat::GetData<string_t>(hash_name_data);
        HashValueInput input(args.data[1]);

        auto results = FlatVector::GetDataMutable<string_t>(result);
        for (idx_t i = 0; i < count; i++)
        {
            auto hash_idx = hash_name_data.sel->get_index(i);
            auto value_idx = input.RowIndex(i);
            if (!hash_name_data.validity.RowIsValid(hash_idx) || !value_idx.IsValid())
            {
                FlatVector::SetNull(result, i, true);
                continue;
            }

            auto &algorithm = lstate.algorithms.Lookup(hash_names[hash_idx]);
            hasher.Init(algorithm);
            input.Hash(hasher, value_idx.GetIndex());

            auto output = StringVector::EmptyString(result, algorithm.digest_length);
            hasher.Finalize(data_ptr_cast(output.GetDataWriteable()));
            output.Finalize();
            results[i] = output;
        }
        FinishResult(args, result, all_constant);
    }

    inline void CryptoScalarHashXofFun(DataChunk &args, ExpressionState &state, Vector &result)
    {
        auto &lstate = GetLocalState<CryptoHashLocalState>(state);
        auto &hasher = lstate.hasher;
        const bool all_constant = AllConstant(args);
        const idx_t count = all_constant ? 1 : args.size();

        UnifiedVectorFormat hash_name_data;
        UnifiedVectorFormat length_data;
        args.data[0].ToUnifiedFormat(hash_name_data);
        args.data[2].ToUnifiedFormat(length_data);
        auto hash_names = UnifiedVectorFormat::GetData<string_t>(hash_name_data);
        auto lengths = UnifiedVectorFormat::GetData<int64_t>(length_data);
        HashValueInput input(args.data[1]);

        CryptoBlobWriter writer(result, BufferAllocator::Get(state.GetContext()));
        auto results = FlatVector::GetDataMutable<string_t>(result);
        for (idx_t i = 0; i < count; i++)
        {
            auto hash_idx = hash_name_data.sel->get_index(i);
            auto length_idx = length_data.sel->get_index(i);
            auto value_idx = input.RowIndex(i);
            if (!hash_name_data.validity.RowIsValid(hash_idx) || !length_data.validity.RowIsValid(length_idx) ||
                !value_idx.IsValid())
            {
                FlatVector::SetNull(result, i, true);
                continue;
            }

            auto &algorithm = lstate.algorithms.Lookup(hash_names[hash_idx]);
            if (!algorithm.is_xof)
            {
                throw InvalidInputException(
                    "crypto_hash_xof requires an extendable-output algorithm (blake3, shake128, shake256), got '%s'",
                    algorithm.name);
            }
            auto length = lengths[length_idx];
            if (length <= 0 || length > CRYPTO_MAX_BLOB_BYTES)
            {
                throw InvalidInputException("crypto_hash_xof length must be between 1 and %lld bytes",
                                            static_cast<long long>(CRYPTO_MAX_BLOB_BYTES));
            }

            hasher.Init(algorithm);
            input.Hash(hasher, value_idx.GetIndex());
            auto out = writer.Reserve(static_cast<idx_t>(length));
            hasher.FinalizeXof(out, static_cast<idx_t>(length));
            results[i] = writer.Finish();
        }
        FinishResult(args, result, all_constant);
    }

    inline void CryptoScalarHmacFun(DataChunk &args, ExpressionState &state, Vector &result)
    {
        auto &lstate = GetLocalState<CryptoHmacLocalState>(state);

        TernaryExecutor::Execute<string_t, string_t, string_t, string_t>(
            args.data[0], args.data[1], args.data[2], result,
            [&](string_t hash_function_name, string_t key, string_t value)
            {
                auto &algorithm = lstate.algorithms.Lookup(hash_function_name);
                auto output = StringVector::EmptyString(result, algorithm.digest_length);
                lstate.hmac.Compute(algorithm, key.GetData(), key.GetSize(), value.GetData(), value.GetSize(),
                                    data_ptr_cast(output.GetDataWriteable()));
                output.Finalize();
                return output;
            });
    }

    inline void CryptoScalarEqualsFun(DataChunk &args, ExpressionState &state, Vector &result)
    {
        BinaryExecutor::Execute<string_t, string_t, bool>(
            args.data[0], args.data[1], result,
            [&](string_t a, string_t b)
            { return CryptoConstantTimeEquals(a.GetData(), a.GetSize(), b.GetData(), b.GetSize()); });
    }

    inline void CryptoScalarRandomBytesFun(DataChunk &args, ExpressionState &state, Vector &result)
    {
        auto &length_vector = args.data[0];
        auto count = args.size();

        UnifiedVectorFormat length_data;
        length_vector.ToUnifiedFormat(length_data);
        auto lengths = UnifiedVectorFormat::GetData<int64_t>(length_data);

        // Large outputs go through DuckDB's buffer allocator so they count against memory_limit
        CryptoBlobWriter writer(result, BufferAllocator::Get(state.GetContext()));
        auto results = FlatVector::GetDataMutable<string_t>(result);

        for (idx_t i = 0; i < count; i++)
        {
            auto length_idx = length_data.sel->get_index(i);

            if (!length_data.validity.RowIsValid(length_idx))
            {
                FlatVector::SetNull(result, i, true);
                continue;
            }

            int64_t length = lengths[length_idx];
            ValidateRandomBytesLength(length);

            auto out = writer.Reserve(static_cast<idx_t>(length));
            CryptoRandomBytes(length, out);
            results[i] = writer.Finish();
        }

        if (count == 1 && length_vector.GetVectorType() == VectorType::CONSTANT_VECTOR)
        {
            result.SetVectorType(VectorType::CONSTANT_VECTOR);
        }
    }

    struct HashAggregateState
    {
        //! Kept inline: ordered aggregates re-initialize one state per group, so allocating would accumulate
        blake3_hasher b3_hasher;
        //! Allocated by OpenSSL, with EVP_CONTEXT_RESERVATION bytes reserved against memory_limit
        EVP_MD_CTX *ctx;
        bool is_touched;
    };

    struct HashAggregateBindData : public FunctionData
    {
        HashAggregateBindData(const CryptoHashAlgorithm &algorithm, LogicalType value_type,
                              BufferManager &buffer_manager)
            : algorithm(algorithm), value_type(std::move(value_type)), buffer_manager(buffer_manager)
        {
        }

        unique_ptr<FunctionData> Copy() const override
        {
            return make_uniq<HashAggregateBindData>(algorithm, value_type, buffer_manager);
        }

        bool Equals(const FunctionData &other_p) const override
        {
            auto &other = other_p.Cast<HashAggregateBindData>();
            return &algorithm == &other.algorithm && value_type == other.value_type;
        }

        bool IsBlake3() const
        {
            return algorithm.backend == CryptoHashBackend::BLAKE3;
        }

        const CryptoHashAlgorithm &algorithm;
        const LogicalType value_type;
        BufferManager &buffer_manager;
    };

    //! Adapts an aggregate state to the Update() interface used by CryptoValueEncoder
    struct HashAggregateUpdater
    {
        HashAggregateUpdater(HashAggregateState &state, const HashAggregateBindData &bind_data)
            : state(state), is_blake3(bind_data.IsBlake3())
        {
            if (state.is_touched)
            {
                return;
            }
            if (is_blake3)
            {
                blake3_hasher_init(&state.b3_hasher);
            }
            else
            {
                bind_data.buffer_manager.ReserveMemory(EVP_CONTEXT_RESERVATION);
                state.ctx = EVP_MD_CTX_new();
                if (!state.ctx)
                {
                    bind_data.buffer_manager.FreeReservedMemory(EVP_CONTEXT_RESERVATION);
                    throw InternalException("Failed to create hash context");
                }
                if (EVP_DigestInit_ex(state.ctx, bind_data.algorithm.md, nullptr) != 1)
                {
                    throw InternalException("Failed to initialize hash context");
                }
            }
            state.is_touched = true;
        }

        void Update(const void *data, idx_t len)
        {
            if (is_blake3)
            {
                blake3_hasher_update(&state.b3_hasher, data, len);
            }
            else if (EVP_DigestUpdate(state.ctx, data, len) != 1)
            {
                throw InternalException("Failed to update hash");
            }
        }

        HashAggregateState &state;
        const bool is_blake3;
    };

    struct HashAggregateOperation
    {
        template <class STATE>
        static void Initialize(STATE &state)
        {
            state.ctx = nullptr;
            state.is_touched = false;
        }

        template <class STATE>
        static void Destroy(STATE &state, AggregateInputData &aggr_input_data)
        {
            if (state.ctx)
            {
                EVP_MD_CTX_free(state.ctx);
                state.ctx = nullptr;
                aggr_input_data.bind_data->Cast<HashAggregateBindData>().buffer_manager.FreeReservedMemory(
                    EVP_CONTEXT_RESERVATION);
            }
        }

        static bool IgnoreNull()
        {
            return false;
        }

        template <class STATE, class OP>
        static void Combine(const STATE &source, STATE &target, AggregateInputData &aggr_input_data)
        {
            if (!source.is_touched)
            {
                return;
            }
            if (target.is_touched)
            {
                // Two partial hashes cannot be merged: the input must arrive in one ordered stream
                throw InvalidInputException(HASH_AGG_ORDER_ERROR);
            }
            auto &bind_data = aggr_input_data.bind_data->Cast<HashAggregateBindData>();
            if (bind_data.IsBlake3())
            {
                target.b3_hasher = source.b3_hasher;
            }
            else
            {
                bind_data.buffer_manager.ReserveMemory(EVP_CONTEXT_RESERVATION);
                target.ctx = EVP_MD_CTX_new();
                if (!target.ctx)
                {
                    bind_data.buffer_manager.FreeReservedMemory(EVP_CONTEXT_RESERVATION);
                    throw InternalException("Failed to create hash context");
                }
                if (EVP_MD_CTX_copy_ex(target.ctx, source.ctx) != 1)
                {
                    throw InternalException("Failed to copy hash context");
                }
            }
            target.is_touched = true;
        }

        template <class T, class STATE>
        static void Finalize(STATE &state, T &target, AggregateFinalizeData &finalize_data)
        {
            if (!state.is_touched)
            {
                finalize_data.ReturnNull();
                return;
            }
            auto &bind_data = finalize_data.input.bind_data->Cast<HashAggregateBindData>();
            auto &algorithm = bind_data.algorithm;
            target = StringVector::EmptyString(finalize_data.result, algorithm.digest_length);
            auto out = data_ptr_cast(target.GetDataWriteable());
            if (bind_data.IsBlake3())
            {
                // Finalizing does not modify the hasher, so window frames can finalize repeatedly
                blake3_hasher_finalize(&state.b3_hasher, out, BLAKE3_OUT_LEN);
            }
            else
            {
                // Finalize a copy so the state stays usable if it is finalized again
                auto copy = EVP_MD_CTX_new();
                if (!copy || EVP_MD_CTX_copy_ex(copy, state.ctx) != 1)
                {
                    EVP_MD_CTX_free(copy);
                    throw InternalException("Failed to copy hash context");
                }
                int rc;
                if (algorithm.is_xof)
                {
                    rc = EVP_DigestFinalXOF(copy, out, algorithm.digest_length);
                }
                else
                {
                    unsigned int len = 0;
                    rc = EVP_DigestFinal_ex(copy, out, &len);
                }
                EVP_MD_CTX_free(copy);
                if (rc != 1)
                {
                    throw InternalException("Failed to finalize hash");
                }
            }
            target.Finalize();
        }
    };

    static void HashAggScatterUpdate(Vector inputs[], AggregateInputData &aggr_input_data, idx_t input_count,
                                     Vector &states, idx_t count)
    {
        D_ASSERT(input_count == 2);
        auto &bind_data = aggr_input_data.bind_data->Cast<HashAggregateBindData>();

        UnifiedVectorFormat input_data;
        UnifiedVectorFormat state_data;
        inputs[1].ToUnifiedFormat(input_data);
        states.ToUnifiedFormat(state_data);
        auto state_ptrs = UnifiedVectorFormat::GetData<HashAggregateState *>(state_data);

        for (idx_t i = 0; i < count; i++)
        {
            auto input_idx = input_data.sel->get_index(i);
            if (!input_data.validity.RowIsValid(input_idx))
            {
                throw InvalidInputException("crypto_hash_agg does not support NULL values, filter them out with "
                                            "FILTER (WHERE value IS NOT NULL)");
            }
            auto &state = *state_ptrs[state_data.sel->get_index(i)];
            HashAggregateUpdater updater(state, bind_data);
            CryptoValueEncoder::Encode(updater, bind_data.value_type, input_data, input_idx, true);
        }
    }

    unique_ptr<FunctionData> HashAggregateBind(BindAggregateFunctionInput &input)
    {
        auto &context = input.GetClientContext();
        auto &arguments = input.GetArguments();

        if (arguments.size() != 2)
        {
            throw InvalidInputException("crypto_hash_agg requires two arguments: algorithm name and data");
        }

        if (arguments[0]->HasParameter() || arguments[1]->HasParameter())
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

        auto &algorithm = LookupAlgorithm(hash_algo_value.GetValue<std::string>());
        auto value_type = arguments[1]->GetReturnType();
        if (value_type.id() == LogicalTypeId::LIST || value_type.id() == LogicalTypeId::ARRAY)
        {
            throw InvalidInputException("Unsupported type for crypto_hash_agg: %s", value_type.ToString());
        }
        CryptoValueEncoder::Validate(value_type, false);

        // The algorithm argument stays part of the argument list (DuckDB 2.0 no longer allows erasing
        // arguments); the update callback skips it and reads the data from the second argument.
        return make_uniq<HashAggregateBindData>(algorithm, std::move(value_type),
                                                BufferManager::GetBufferManager(context));
    }

    //! Rejects crypto_hash_agg without ORDER BY; runs from the optimizer, which sees the bound ORDER BY clause
    static unique_ptr<Expression> HashAggregateRequireOrder(AggregateRewriteInput &input)
    {
        if (!input.aggregate.GetOrderBys())
        {
            throw InvalidInputException(HASH_AGG_ORDER_ERROR);
        }
        return nullptr;
    }

    static AggregateFunction GetHashAggregateFunction()
    {
        using OP = HashAggregateOperation;
        AggregateFunction agg_func({LogicalType::VARCHAR, LogicalType::ANY}, LogicalType::BLOB,
                                   AggregateFunction::StateSize<HashAggregateState>,
                                   AggregateFunction::StateInitialize<HashAggregateState, OP>, HashAggScatterUpdate,
                                   AggregateFunction::StateCombine<HashAggregateState, OP>,
                                   AggregateFunction::StateFinalize<HashAggregateState, string_t, OP>,
                                   FunctionNullHandling::DEFAULT_NULL_HANDLING);
        // Name the positional parameters, so duckdb_functions() reports them instead of col<N>.
        agg_func.GetSignature().GetParameter(0).SetName("algorithm");
        agg_func.GetSignature().GetParameter(1).SetName("value");
        agg_func.SetStateDestructorCallback(AggregateFunction::StateDestroy<HashAggregateState, OP>);
        agg_func.SetOrderDependent(AggregateOrderDependent::ORDER_DEPENDENT);
        agg_func.SetDistinctDependent(AggregateDistinctDependent::DISTINCT_DEPENDENT);
        agg_func.SetBindCallback(HashAggregateBind);
        agg_func.SetDirectRewriteCallback(HashAggregateRequireOrder);
        // Partial hashes cannot be merged, so window frames must not be built from a segment tree
        agg_func.SetIsHolistic(true);
        agg_func.SetFallible();
        return agg_func;
    }

    struct CryptoAlgorithmsState : public GlobalTableFunctionState
    {
        idx_t offset = 0;
    };

    static unique_ptr<FunctionData> CryptoAlgorithmsBind(ClientContext &context, TableFunctionBindInput &input,
                                                         vector<LogicalType> &return_types, vector<Identifier> &names)
    {
        names.emplace_back("name");
        return_types.emplace_back(LogicalType::VARCHAR);
        names.emplace_back("family");
        return_types.emplace_back(LogicalType::VARCHAR);
        names.emplace_back("implementation");
        return_types.emplace_back(LogicalType::VARCHAR);
        names.emplace_back("digest_length");
        return_types.emplace_back(LogicalType::INTEGER);
        names.emplace_back("is_xof");
        return_types.emplace_back(LogicalType::BOOLEAN);
        names.emplace_back("supports_hmac");
        return_types.emplace_back(LogicalType::BOOLEAN);
        names.emplace_back("available");
        return_types.emplace_back(LogicalType::BOOLEAN);
        return nullptr;
    }

    static unique_ptr<GlobalTableFunctionState> CryptoAlgorithmsInit(ClientContext &context,
                                                                     TableFunctionInitInput &input)
    {
        return make_uniq<CryptoAlgorithmsState>();
    }

    static void CryptoAlgorithmsFunction(ClientContext &context, TableFunctionInput &data_p, DataChunk &output)
    {
        auto &state = data_p.global_state->Cast<CryptoAlgorithmsState>();
        auto &algorithms = GetHashAlgorithms();
        idx_t count = 0;
        while (state.offset < algorithms.size() && count < STANDARD_VECTOR_SIZE)
        {
            auto &algorithm = algorithms[state.offset++];
            output.data[0].Append(Value(algorithm.name));
            output.data[1].Append(Value(algorithm.family));
            output.data[2].Append(Value(algorithm.backend == CryptoHashBackend::BLAKE3 ? "blake3" : "openssl"));
            output.data[3].Append(algorithm.available ? Value::INTEGER(NumericCast<int32_t>(algorithm.digest_length))
                                                      : Value(LogicalType::INTEGER));
            output.data[4].Append(Value::BOOLEAN(algorithm.is_xof));
            output.data[5].Append(Value::BOOLEAN(algorithm.supports_hmac));
            output.data[6].Append(Value::BOOLEAN(algorithm.available));
            count++;
        }
    }

    // Declares a positional-only parameter with a real name, so duckdb_functions() reports it instead of col<N>.
    static FunctionParameter Positional(const char *name, LogicalType type) {
        return FunctionParameter(name, std::move(type), {}, FunctionParameterKind::POSITIONAL_ONLY);
    }

    static void LoadInternal(ExtensionLoader &loader)
    {
        // crypto_hash: Computes cryptographic hash of data using specified algorithm
        auto crypto_hash_scalar_function = ScalarFunction("crypto_hash", {Positional("algorithm", LogicalType::VARCHAR), Positional("value", LogicalType::ANY)}, LogicalType::BLOB, CryptoScalarHashFun);
        crypto_hash_scalar_function.SetInitStateCallback(InitLocalState<CryptoHashLocalState>);
        crypto_hash_scalar_function.SetFallible();
        CreateScalarFunctionInfo crypto_hash_info(crypto_hash_scalar_function);
        crypto_hash_info.descriptions.push_back({
            {LogicalType::VARCHAR, LogicalType::ANY},                                // parameter_types
            {"algorithm", "value"},                                                   // parameter_names
            "Computes a cryptographic hash of the input value using the specified algorithm. "
            "Run crypto_algorithms() for the supported algorithms. "
            "Accepts strings, numbers, decimals, enums, dates, timestamps, intervals, UUIDs, and lists or arrays of those.",  // description
            {"crypto_hash('sha2-256', 'hello world')",
             "crypto_hash('blake3', 42)",
             "crypto_hash('sha2-256', [1, 2, 3])"},                                  // examples
            {"cryptography", "hash"}                                                  // categories
        });
        loader.RegisterFunction(crypto_hash_info);

        // crypto_hash_xof: Extendable-output hash with a caller-chosen length
        auto crypto_hash_xof_scalar_function = ScalarFunction("crypto_hash_xof", {Positional("algorithm", LogicalType::VARCHAR), Positional("value", LogicalType::ANY), Positional("length", LogicalType::BIGINT)}, LogicalType::BLOB, CryptoScalarHashXofFun);
        crypto_hash_xof_scalar_function.SetInitStateCallback(InitLocalState<CryptoHashLocalState>);
        crypto_hash_xof_scalar_function.SetFallible();
        CreateScalarFunctionInfo crypto_hash_xof_info(crypto_hash_xof_scalar_function);
        crypto_hash_xof_info.descriptions.push_back({
            {LogicalType::VARCHAR, LogicalType::ANY, LogicalType::BIGINT},           // parameter_types
            {"algorithm", "value", "length"},                                         // parameter_names
            "Computes an extendable-output hash (blake3, shake128 or shake256) of the input value, "
            "producing length bytes of output.",                                      // description
            {"crypto_hash_xof('shake256', 'hello world', 128)",
             "crypto_hash_xof('blake3', 'hello world', 64)"},                        // examples
            {"cryptography", "hash"}                                                  // categories
        });
        loader.RegisterFunction(crypto_hash_xof_info);

        // crypto_hmac: Computes HMAC of message with key using specified algorithm
        ScalarFunctionSet crypto_hmac_set("crypto_hmac");
        for (auto &key_type : {LogicalType::VARCHAR, LogicalType::BLOB})
        {
            for (auto &message_type : {LogicalType::VARCHAR, LogicalType::BLOB})
            {
                ScalarFunction crypto_hmac_scalar_function({Positional("algorithm", LogicalType::VARCHAR), Positional("key", key_type), Positional("message", message_type)}, LogicalType::BLOB, CryptoScalarHmacFun);
                crypto_hmac_scalar_function.SetInitStateCallback(InitLocalState<CryptoHmacLocalState>);
                crypto_hmac_scalar_function.SetFallible();
                crypto_hmac_set.AddFunction(crypto_hmac_scalar_function);
            }
        }
        CreateScalarFunctionInfo crypto_hmac_info(crypto_hmac_set);
        crypto_hmac_info.descriptions.push_back({
            {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR},      // parameter_types
            {"algorithm", "key", "message"},                                          // parameter_names
            "Computes an HMAC (Hash-based Message Authentication Code) of the message using the specified "
            "algorithm and key. Key and message may be VARCHAR or BLOB. blake3 uses its keyed mode, which "
            "requires exactly 32 bytes for the key; shake128 and shake256 are not supported.",  // description
            {"crypto_hmac('sha2-256', 'secret_key', 'message to authenticate')"},    // examples
            {"cryptography", "hmac", "authentication"}                                // categories
        });
        loader.RegisterFunction(crypto_hmac_info);

        // crypto_equals: Constant-time comparison, for verifying MACs and hashes
        ScalarFunctionSet crypto_equals_set("crypto_equals");
        for (auto &a_type : {LogicalType::VARCHAR, LogicalType::BLOB})
        {
            for (auto &b_type : {LogicalType::VARCHAR, LogicalType::BLOB})
            {
                ScalarFunction crypto_equals_scalar_function({Positional("a", a_type), Positional("b", b_type)}, LogicalType::BOOLEAN, CryptoScalarEqualsFun);
                crypto_equals_set.AddFunction(crypto_equals_scalar_function);
            }
        }
        CreateScalarFunctionInfo crypto_equals_info(crypto_equals_set);
        crypto_equals_info.descriptions.push_back({
            {LogicalType::BLOB, LogicalType::BLOB},                                  // parameter_types
            {"a", "b"},                                                               // parameter_names
            "Compares two values in constant time, so the comparison does not leak how many leading bytes match. "
            "Use it to verify HMACs and other secrets.",                             // description
            {"crypto_equals(crypto_hmac('sha2-256', 'key', 'message'), expected_mac)"},  // examples
            {"cryptography", "authentication"}                                        // categories
        });
        loader.RegisterFunction(crypto_equals_info);

        // crypto_random_bytes: Generates cryptographically secure random bytes
        auto crypto_random_bytes_scalar_function = ScalarFunction(
            "crypto_random_bytes",
            {Positional("length", LogicalType::BIGINT)}, LogicalType::BLOB, CryptoScalarRandomBytesFun);
        crypto_random_bytes_scalar_function.SetVolatile();
        crypto_random_bytes_scalar_function.SetFallible();
        CreateScalarFunctionInfo crypto_random_bytes_info(crypto_random_bytes_scalar_function);
        crypto_random_bytes_info.descriptions.push_back({
            {LogicalType::BIGINT},                                                   // parameter_types
            {"length"},                                                              // parameter_names
            "Generates cryptographically secure random bytes using OpenSSL's RAND_bytes(). "
            "Length must be between 1 and 4,294,967,295 bytes. Each call produces different random bytes.",  // description
            {"crypto_random_bytes(16)",
             "crypto_random_bytes(32)"},                                             // examples
            {"cryptography", "random"}                                               // categories
        });
        loader.RegisterFunction(crypto_random_bytes_info);

        // crypto_hash_agg: Aggregate function for hashing multiple rows
        AggregateFunctionSet agg_set("crypto_hash_agg");
        agg_set.AddFunction(GetHashAggregateFunction());
        CreateAggregateFunctionInfo crypto_hash_agg_info(agg_set);
        crypto_hash_agg_info.descriptions.push_back({
            {LogicalType::VARCHAR, LogicalType::ANY},                                // parameter_types
            {"algorithm", "value"},                                                   // parameter_names
            "Computes a cryptographic hash over multiple rows using the specified algorithm. "
            "ORDER BY is required to ensure deterministic results. Returns the same hash as crypto_hash() "
            "would for an equivalent ordered list. Returns NULL for empty result sets and errors on NULL values.",  // description
            {"crypto_hash_agg('sha2-256', column_name ORDER BY id)",
             "crypto_hash_agg('blake3', data ORDER BY timestamp)"},                  // examples
            {"cryptography", "hash", "aggregate"}                                     // categories
        });
        loader.RegisterFunction(crypto_hash_agg_info);

        // crypto_algorithms: Lists the hash algorithms and their properties
        TableFunction crypto_algorithms("crypto_algorithms", {}, CryptoAlgorithmsFunction, CryptoAlgorithmsBind,
                                        CryptoAlgorithmsInit);
        CreateTableFunctionInfo crypto_algorithms_info(crypto_algorithms);
        loader.RegisterFunction(crypto_algorithms_info);

        RegisterKdfFunctions(loader);

        QueryFarmSendTelemetry(loader, "crypto", "2026102101");
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
