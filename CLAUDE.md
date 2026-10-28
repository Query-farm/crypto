# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a DuckDB extension that adds cryptographic hash functions, HMAC calculation, key derivation, constant-time comparison, and cryptographically secure random byte generation using OpenSSL and BLAKE3.

## Architecture

The extension is implemented in C++ and uses OpenSSL's EVP API for most cryptographic operations, with BLAKE3 provided by a vendored library:

1. **C++ implementation** (`src/`):
   - `src/crypto_extension.cpp`: Main extension entry point; registers the hash, HMAC, equals, random, aggregate and `crypto_algorithms()` functions
   - `src/crypto_hash.cpp`: Algorithm registry, reusable hasher and HMAC contexts, memory-tracked output, random bytes
   - `src/crypto_kdf.cpp`: Key derivation functions (PBKDF2, HKDF, scrypt, Argon2)
   - `src/include/crypto_value_encoder.hpp`: Canonical byte encoding of DuckDB values for hashing
   - `src/query_farm_telemetry.cpp`: Telemetry integration
   - DuckDB functions:
     - `crypto_hash()` - Scalar function for hashing various data types
     - `crypto_hash_xof()` - Extendable-output hash (blake3, shake128, shake256) with a chosen length
     - `crypto_hmac()` - Scalar function for HMAC computation
     - `crypto_equals()` - Constant-time comparison
     - `crypto_hash_agg()` - Aggregate function for hashing multiple rows
     - `crypto_random_bytes()` - Scalar function for generating random bytes
     - `crypto_pbkdf2()`, `crypto_hkdf()`, `crypto_scrypt()`, `crypto_argon2()` - Key derivation
     - `crypto_algorithms()` - Table function listing the hash algorithms and their properties

### Build Integration

- Uses standard CMake `find_package(OpenSSL)` to locate and link OpenSSL
- Links against OpenSSL::SSL and OpenSSL::Crypto for both static and loadable extension variants
- Requires OpenSSL 3.2+ for Keccak and Argon2 (vcpkg provides 3.6); missing algorithms are reported as unavailable
- No external code generation tools required

## Common Commands

### Building

For debug

```sh
VCPKG_TOOLCHAIN_PATH=`pwd`/vcpkg/scripts/buildsystems/vcpkg.cmake GEN=ninja make debug
```

Builds:
- `./build/debug/duckdb` - DuckDB shell
- `./build/debug/test/unittest` - Test runner with extension linked
- `./build/debug/extension/crypto/crypto.duckdb_extension` - Loadable extension binary

For release builds:

```sh
VCPKG_TOOLCHAIN_PATH=`pwd`/vcpkg/scripts/buildsystems/vcpkg.cmake GEN=ninja make release
```

Builds:
- `./build/release/duckdb` - DuckDB shell
- `./build/release/test/unittest` - Test runner with extension linked
- `./build/release/extension/crypto/crypto.duckdb_extension` - Loadable extension binary

**Note**: Requires OpenSSL to be installed on your system.

### Testing

```sh
make test_debug
```

Runs SQL tests located in `test/sql/*.test` but uses the debug build. `test/sql/*.test_slow` holds tests that allocate several GB.

### Running the Extension

```sh
./build/release/duckdb -unsigned -c "LOAD 'build/release/extension/crypto/crypto.duckdb_extension'; SELECT * FROM crypto_algorithms();"
```

## Implemented Functions

### crypto_hash()
**Syntax**: `crypto_hash(algorithm, value) → BLOB`

Computes a cryptographic hash of the input value. Supports multiple data types:
- **Strings**: VARCHAR, BLOB, and every type stored as a string (JSON, BIT, BIGNUM, VARCHAR aliases, collations)
- **Integers**: TINYINT, SMALLINT, INTEGER, BIGINT, HUGEINT, UTINYINT, USMALLINT, UINTEGER, UBIGINT, UHUGEINT
- **Floating point**: FLOAT, DOUBLE
- **Other**: BOOLEAN, DATE, TIME, TIME_TZ, TIMESTAMP (all precisions and TZ), INTERVAL, UUID, DECIMAL, ENUM
- **Lists and arrays**: `LIST` or fixed-size `ARRAY` of any of the above (an ARRAY hashes the same as the equivalent LIST)
  - NULL elements inside lists are not supported
  - Nested lists (lists of lists, lists of structs, etc.) are not supported
  - For string-like elements, each element's length is hashed before its content to prevent length extension attacks

### crypto_hash_xof()
**Syntax**: `crypto_hash_xof(algorithm, value, length) → BLOB`

Extendable-output hash for blake3, shake128 and shake256. Length is 1 to 4,294,967,295 bytes. The first bytes match `crypto_hash()` for the same algorithm.

### crypto_hmac()
**Syntax**: `crypto_hmac(algorithm, key, message) → BLOB`

Computes an HMAC using the specified algorithm, key, and message. Key and message may each be VARCHAR or BLOB. blake3 uses its keyed mode, which requires exactly 32 bytes for the key; shake128 and shake256 are not supported. Consecutive rows with the same key reuse the expanded key.

### crypto_equals()
**Syntax**: `crypto_equals(a, b) → BOOLEAN`

Constant-time comparison (`CRYPTO_memcmp`) of two VARCHAR/BLOB values, for verifying MACs.

### crypto_hash_agg()
**Syntax**: `crypto_hash_agg(algorithm, value ORDER BY sort_expression) → BLOB`

Aggregate function that computes a hash over multiple rows. **ORDER BY is required** to ensure deterministic results; a query without it is rejected during optimization. Produces the same hash as `crypto_hash()` would for an equivalent ordered list. Returns NULL for empty result sets and raises an error on NULL values (use `FILTER (WHERE value IS NOT NULL)`). Works as a window function.

### crypto_random_bytes()
**Syntax**: `crypto_random_bytes(length) → BLOB`

Generates cryptographically secure random bytes using OpenSSL's `RAND_bytes()`. Length must be between 1 and 4,294,967,295 bytes (4GB - 1, the maximum BLOB size in DuckDB). This function is marked as VOLATILE so each call produces different random bytes.

### Key derivation
- `crypto_pbkdf2(algorithm, password, salt, iterations, length)` - PBKDF2-HMAC (RFC 8018)
- `crypto_hkdf(algorithm, key, salt, info, length)` - HKDF extract-and-expand (RFC 5869); length ≤ 255 × digest length
- `crypto_scrypt(password, salt, n, r, p, length)` - scrypt (RFC 7914); n must be a power of 2
- `crypto_argon2(variant, password, salt, iterations, memory_kib, parallelism, length)` - Argon2 (RFC 9106); variant is `argon2id`, `argon2i` or `argon2d`

Byte-string arguments accept VARCHAR or BLOB. Output length is capped at 1 MiB.

### crypto_algorithms()
**Syntax**: `SELECT * FROM crypto_algorithms()`

Lists every hash algorithm with `name`, `family`, `implementation`, `digest_length`, `is_xof`, `supports_hmac` and `available`.

## Supported Hash Algorithms

The extension supports these algorithms (defined in `ALGORITHM_SPECS` in `src/crypto_hash.cpp`):
- **blake3** - 32 bytes, XOF (separate vendored library, not from OpenSSL)
- **blake2b-512** - 64 bytes; **blake2s-256** - 32 bytes
- **keccak224, keccak256, keccak384, keccak512** - original Keccak padding as used by Ethereum (not SHA3)
- **md4** (only in OpenSSL's legacy provider, reported as unavailable), **md5** - 16 bytes
- **ripemd160** - 20 bytes
- **sha1** - 20 bytes
- **sha2-224, sha2-256, sha2-384, sha2-512, sha2-512/224, sha2-512/256** - SHA-2 family
- **sha3-224, sha3-256, sha3-384, sha3-512** - SHA-3 family
- **shake128, shake256** - XOFs, 32 and 64 bytes by default
- **sm3** - 32 bytes

## Development Workflow

### Adding a New Hash Algorithm

1. Add a row to `ALGORITHM_SPECS` in `src/crypto_hash.cpp` with the SQL name, family and the name passed to `EVP_MD_fetch`
2. Add test vectors (computed with an independent implementation) to `test/sql/crypto_algorithms.test`
3. Update `test/sql/crypto_algorithms.test`'s `crypto_algorithms()` listing

### Adding a New Supported Data Type

1. Update `CryptoValueEncoder::Validate()` in `src/crypto_hash.cpp` and `CryptoValueEncoder::Encode()` in `src/include/crypto_value_encoder.hpp`
2. Choose a canonical, platform-independent encoding; it is shared by `crypto_hash()`, lists and `crypto_hash_agg()`
3. Add corresponding test cases in `test/sql/crypto_hash_types.test`

## Key Implementation Details

### Algorithm Handling
- **Registry**: `GetHashAlgorithms()` builds one `CryptoHashAlgorithm` per spec at first use, pre-fetching each `EVP_MD` with `EVP_MD_fetch` (avoids an implicit fetch per digest)
- **BLAKE3**: Handled separately using the vendored BLAKE3 library (`blake3.h`), not through OpenSSL
- **Lookup**: `LookupAlgorithm()` is case-insensitive and throws for unknown or unavailable algorithms; `CryptoAlgorithmCache` remembers the last name so a constant algorithm is looked up once per thread
- **Reuse**: `CryptoHasher` and `CryptoHmacContext` live in per-thread function local state and keep their OpenSSL contexts across rows

### Canonical Value Encoding
- Fixed-width values are hashed as little-endian bytes (big-endian platforms are rejected at compile time)
- UUID: 16 bytes in RFC 9562 order (same as hashing `unhex()` of the UUID)
- DECIMAL: unscaled value widened to a 16-byte integer, so the declared width does not matter
- ENUM: the label, not the index
- Top-level strings are hashed raw; inside lists and `crypto_hash_agg()` each string is `[uint64 length][bytes]`

### Aggregate Function
- `HashAggregateState` holds an inline blake3 hasher or an `EVP_MD_CTX`; the state memory is managed by DuckDB, and ordered aggregates reuse one state per group
- ORDER BY is enforced by a direct-rewrite callback that runs in the optimizer and sees the bound ORDER BY clause
- Two partial states cannot be merged: `Combine` copies into an empty target and errors otherwise
- Marked holistic so window frames are not built from a segment tree; finalizing does not consume the state
- In window functions without any ORDER BY the row order is not checked

### Memory Accounting
- Outputs of 4 KiB or more (`crypto_random_bytes`, `crypto_hash_xof`, KDFs) are allocated through `BufferAllocator` and attached to the result vector, so they count against `memory_limit`
- scrypt and Argon2 working memory is reserved with `BufferManager::ReserveMemory` before OpenSSL allocates it
- Each aggregate `EVP_MD_CTX` reserves 512 bytes, since OpenSSL allocates it outside DuckDB

### Error Handling

The C++ implementation throws DuckDB exceptions:
- `InvalidInputException`: For invalid algorithm names, unsupported types, NULL list elements, invalid lengths or KDF parameters
- `InternalException`: For OpenSSL operation failures (context creation, digest operations, random byte generation)
- `OutOfMemoryException` (from DuckDB): When an allocation or reservation exceeds `memory_limit`

Exceptions are caught by DuckDB's executor and presented to the user.

## Testing

The extension has SQL-based tests in `test/sql/`:
- `crypto.test` - Main suite covering all original functions, algorithms, data types, and error cases
- `crypto_algorithms.test` - `crypto_algorithms()`, added algorithms, `crypto_hash_xof()`
- `crypto_hash_types.test` / `crypto_json.test` - Canonical encoding of UUID, DECIMAL, ENUM, ARRAY, JSON and other types
- `crypto_hmac_equals.test` - BLOB keys, key reuse across rows, `crypto_equals()`
- `crypto_hash_agg_extended.test` - Windows, NULLs, more types, ORDER BY enforcement
- `crypto_kdf.test` - KDF test vectors and parameter validation
- `crypto_memory_limit.test` - Behavior under `memory_limit`
- `crypto_random_large.test_slow` - Random bytes beyond INT_MAX

Expected values come from independent implementations (Python `hashlib`, pycryptodome, argon2-cffi, blake3) or published RFC vectors.

## CI/CD

The repository uses the DuckDB extension template's CI system:
- Build configuration is in `extension_config.cmake`
- CI tools are in `extension-ci-tools/` (git submodule)
- The Makefile includes `extension-ci-tools/makefiles/duckdb_extension.Makefile`
