# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a DuckDB extension that adds cryptographic hash functions, HMAC calculation capabilities, and cryptographically secure random byte generation using OpenSSL and BLAKE3.

## Architecture

The extension is implemented in C++ and uses OpenSSL's EVP API for most cryptographic operations, with BLAKE3 provided by a vendored library:

1. **C++ implementation** (`src/`):
   - `src/crypto_extension.cpp`: Main extension entry point, registers all functions with DuckDB
   - `src/crypto_hash.cpp`: Core hash, HMAC, and random byte implementations
   - `src/query_farm_telemetry.cpp`: Telemetry integration
   - Implements four DuckDB functions:
     - `crypto_hash()` - Scalar function for hashing various data types
     - `crypto_hmac()` - Scalar function for HMAC computation
     - `crypto_hash_agg()` - Aggregate function for hashing multiple rows
     - `crypto_random_bytes()` - Scalar function for generating random bytes

### Build Integration

- Uses standard CMake `find_package(OpenSSL)` to locate and link OpenSSL
- Links against OpenSSL::SSL and OpenSSL::Crypto for both static and loadable extension variants
- No external code generation tools required

## Common Commands

### Building

For debug

```sh
VCPKG_TOOLCHAIN_PATH=`pwd`/vcpkg/scripts/buildsystems/vcpkg.cmake GEN=ninja make debug
```

Builds:
- `./build/debug/duckdb` - DuckDB shell with extension pre-loaded
- `./build/debug/test/unittest` - Test runner with extension linked
- `./build/debug/extension/crypto/crypto.duckdb_extension` - Loadable extension binary

For release builds:

```sh
VCPKG_TOOLCHAIN_PATH=`pwd`/vcpkg/scripts/buildsystems/vcpkg.cmake GEN=ninja make release
```

Builds:
- `./build/release/duckdb` - DuckDB shell with extension pre-loaded
- `./build/release/test/unittest` - Test runner with extension linked
- `./build/release/extension/crypto/crypto.duckdb_extension` - Loadable extension binary

**Note**: Requires OpenSSL to be installed on your system.

### Testing

```sh
make test_debug
```

Runs SQL tests located in `test/sql/*.test` but uses the debug build.

### Running the Extension

```sh
./build/release/duckdb
```

Launches DuckDB with the extension already loaded.

## Implemented Functions

### crypto_hash()
**Syntax**: `crypto_hash(algorithm, value) → BLOB`

Computes a cryptographic hash of the input value. Supports multiple data types:
- **Strings**: VARCHAR, BLOB
- **Integers**: TINYINT, SMALLINT, INTEGER, BIGINT, HUGEINT, UTINYINT, USMALLINT, UINTEGER, UBIGINT, UHUGEINT
- **Floating point**: FLOAT, DOUBLE
- **Other**: BOOLEAN, DATE, TIME, TIMESTAMP, UUID
- **Lists**: Arrays of any supported fixed-length types (e.g., `INTEGER[]`, `VARCHAR[]`, `BLOB[]`)
  - NULL elements inside lists are not supported
  - Nested lists (lists of lists, lists of structs, etc.) are not supported
  - For VARCHAR/BLOB lists, each element's length is hashed before its content to prevent length extension attacks

### crypto_hmac()
**Syntax**: `crypto_hmac(algorithm, key, message) → BLOB`

Computes an HMAC using the specified algorithm, key, and message. All algorithms supported except BLAKE3 requires exactly 32 bytes for the key.

### crypto_hash_agg()
**Syntax**: `crypto_hash_agg(algorithm, value ORDER BY sort_expression) → BLOB`

Aggregate function that computes a hash over multiple rows. **ORDER BY is required** to ensure deterministic results. Produces the same hash as `crypto_hash()` would for an equivalent ordered list. Returns NULL for empty result sets.

### crypto_random_bytes()
**Syntax**: `crypto_random_bytes(length) → BLOB`

Generates cryptographically secure random bytes using OpenSSL's `RAND_bytes()`. Length must be between 1 and 4,294,967,295 bytes (4GB - 1, the maximum BLOB size in DuckDB). This function is marked as VOLATILE so each call produces different random bytes.

## Supported Hash Algorithms

The extension supports these algorithms (defined in `src/crypto_hash.cpp:GetDigestMap()`):
- **blake3** - 32 bytes (separate vendored library, not from OpenSSL)
- **blake2b-512** - 64 bytes
- **keccak224, keccak256, keccak384, keccak512** - mapped to SHA3 variants
- **md4, md5** - 16 bytes (deprecated, may not work on some systems)
- **sha1** - 20 bytes
- **sha2-224, sha2-256, sha2-384, sha2-512** - SHA-2 family
- **sha3-224, sha3-256, sha3-384, sha3-512** - SHA-3 family

All functions (`crypto_hash()`, `crypto_hmac()`, and `crypto_hash_agg()`) support all these algorithms.

**Note**: Keccak is mapped to SHA3 in OpenSSL. True Keccak (pre-standardization) differs slightly from SHA3.

## Development Workflow

### Adding a New Hash Algorithm

1. Add the new algorithm to `GetDigestMap()` in `src/crypto_hash.cpp`
2. Map it to the appropriate OpenSSL EVP_MD function (e.g., `{"sha2-512", []() { return EVP_sha512(); }}`)
3. Add test vectors to `test/sql/crypto.test` and/or `test/sql/crypto_hash.test`
4. Update README.md with the new algorithm
5. The `LookupAlgorithm()` function in `src/crypto_extension.cpp` handles algorithm lookup for the main hash function

### Adding a New Supported Data Type

1. Update `CryptoScalarHashFun()` in `src/crypto_extension.cpp` to handle the new type
2. Ensure the type's binary representation is hashable
3. Add corresponding test cases in `test/sql/crypto.test`
4. Update README.md to document the new type support
5. For aggregate support, update `RegisterHashAggType()` calls in `LoadInternal()`

## Key Implementation Details

### Algorithm Handling
- **BLAKE3**: Handled separately using the vendored BLAKE3 library (`blake3.h`), not through OpenSSL
- **OpenSSL algorithms**: Use the EVP API through `GetDigestMap()` which returns a lambda that calls the appropriate `EVP_*()` function
- **Algorithm lookup**: `LookupAlgorithm()` in `src/crypto_extension.cpp` returns `nullptr` for BLAKE3, or the EVP_MD pointer for OpenSSL algorithms

### List Hashing
- Lists are hashed element-by-element in order
- For VARCHAR/BLOB elements: each element is hashed as `[8-byte length][content]` to prevent length extension attacks
- For fixed-length types: only the raw binary data is hashed
- List hashing code is in `HashListElementBlake3()` and `HashListElementEVP()` helper functions

### Aggregate Function
- `crypto_hash_agg()` uses `HashAggregateState` to maintain state across rows
- Requires ORDER BY clause - enforced by checking for combining operations
- Produces identical output to `crypto_hash()` on an equivalent ordered list
- Supports same algorithms and types as scalar function

### Error Handling

The C++ implementation throws DuckDB exceptions:
- `InvalidInputException`: For invalid algorithm names, unsupported types, NULL list elements, invalid random byte lengths
- `InternalException`: For OpenSSL operation failures (context creation, digest operations, random byte generation)

Exceptions are caught by DuckDB's executor and presented to the user.

## Testing

The extension has comprehensive SQL-based tests:
- `test/sql/crypto.test` - Main test suite covering all functions, algorithms, data types, and error cases
- `test/sql/crypto_hash.test` - Focused test suite for hash algorithms with known test vectors

Tests are run using:
```sh
make test_debug  # Run tests with debug build
```

Test coverage includes:
- All hash algorithms with known test vectors
- All supported data types (integers, floats, booleans, dates, UUIDs, etc.)
- List hashing with different element types
- HMAC computation with all algorithms
- Aggregate hashing with ORDER BY requirements
- Random byte generation with various lengths
- Error cases (invalid algorithms, unsupported types, NULL list elements, etc.)

## CI/CD

The repository uses the DuckDB extension template's CI system:
- Build configuration is in `extension_config.cmake`
- CI tools are in `extension-ci-tools/` (git submodule)
- The Makefile includes `extension-ci-tools/makefiles/duckdb_extension.Makefile`
