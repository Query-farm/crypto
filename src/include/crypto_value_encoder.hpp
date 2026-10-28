#pragma once

#include "duckdb/common/types/uuid.hpp"
#include "duckdb/common/types/hugeint.hpp"

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#error "crypto hashes fixed-width values in little-endian byte order and does not support big-endian platforms"
#endif

namespace duckdb
{
    namespace crypto_detail
    {
        template <class HASHER>
        inline void EncodeString(HASHER &hasher, const string_t &value, bool length_prefix)
        {
            if (length_prefix)
            {
                const uint64_t len = value.GetSize();
                hasher.Update(&len, sizeof(len));
            }
            hasher.Update(value.GetData(), value.GetSize());
        }

        template <class T>
        inline hugeint_t DecimalToHugeint(const UnifiedVectorFormat &format, idx_t idx)
        {
            return hugeint_t(UnifiedVectorFormat::GetData<T>(format)[idx]);
        }
    } // namespace crypto_detail

    template <class HASHER>
    void CryptoValueEncoder::Encode(HASHER &hasher, const LogicalType &type, const UnifiedVectorFormat &format,
                                    idx_t idx, bool length_prefix_strings)
    {
        switch (type.id())
        {
        case LogicalTypeId::UUID:
        {
            // RFC 9562 byte order, so the hash matches hashing the 16 raw UUID bytes
            data_t bytes[16];
            UUID::ToBlob(UnifiedVectorFormat::GetData<hugeint_t>(format)[idx], bytes);
            hasher.Update(bytes, sizeof(bytes));
            return;
        }
        case LogicalTypeId::DECIMAL:
        {
            // The unscaled value is widened to 128 bits so the hash does not depend on the declared width
            hugeint_t value;
            switch (type.InternalType())
            {
            case PhysicalType::INT16:
                value = crypto_detail::DecimalToHugeint<int16_t>(format, idx);
                break;
            case PhysicalType::INT32:
                value = crypto_detail::DecimalToHugeint<int32_t>(format, idx);
                break;
            case PhysicalType::INT64:
                value = crypto_detail::DecimalToHugeint<int64_t>(format, idx);
                break;
            case PhysicalType::INT128:
                value = UnifiedVectorFormat::GetData<hugeint_t>(format)[idx];
                break;
            default:
                throw InternalException("Unsupported DECIMAL physical type for crypto hashing");
            }
            hasher.Update(&value.lower, sizeof(value.lower));
            hasher.Update(&value.upper, sizeof(value.upper));
            return;
        }
        case LogicalTypeId::ENUM:
        {
            // Hash the label rather than its position, so reordering the enum keeps hashes stable
            idx_t pos;
            switch (type.InternalType())
            {
            case PhysicalType::UINT8:
                pos = UnifiedVectorFormat::GetData<uint8_t>(format)[idx];
                break;
            case PhysicalType::UINT16:
                pos = UnifiedVectorFormat::GetData<uint16_t>(format)[idx];
                break;
            case PhysicalType::UINT32:
                pos = UnifiedVectorFormat::GetData<uint32_t>(format)[idx];
                break;
            default:
                throw InternalException("Unsupported ENUM physical type for crypto hashing");
            }
            crypto_detail::EncodeString(hasher, EnumType::GetString(type, pos), length_prefix_strings);
            return;
        }
        default:
            break;
        }

        auto physical = type.InternalType();
        if (physical == PhysicalType::VARCHAR)
        {
            // VARCHAR, BLOB and every type stored as a string (JSON, BIT, BIGNUM, aliases, collations)
            crypto_detail::EncodeString(hasher, UnifiedVectorFormat::GetData<string_t>(format)[idx],
                                        length_prefix_strings);
            return;
        }
        if (!TypeIsConstantSize(physical) || type.IsNested())
        {
            throw InvalidInputException("Unsupported type for crypto_hash: %s", type.ToString());
        }
        auto type_size = GetTypeIdSize(physical);
        hasher.Update(format.data + idx * type_size, type_size);
    }

} // namespace duckdb
