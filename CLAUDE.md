# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a DuckDB extension that adds cryptographic hash functions and HMAC calculation capabilities using OpenSSL.

## Architecture

The extension is implemented in C++ and uses OpenSSL's EVP API for cryptographic operations:

1. **C++ implementation** (`src/`):
   - `src/crypto_extension.cpp`: Main extension entry point, registers functions with DuckDB
   - `src/crypto_hash.cpp`: Core hash and HMAC implementations using OpenSSL
   - `src/query_farm_telemetry.cpp`: Telemetry integration
   - Implements DuckDB scalar functions: `crypto_hash()` and `crypto_hmac()`

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
make test
```

Runs SQL tests located in `test/sql/crypto.test`.  but using the release build.

### Running the Extension

```sh
./build/release/duckdb
```

Launches DuckDB with the extension already loaded.

## Supported Hash Algorithms

The extension supports these algorithms (defined in `src/crypto_hash.cpp:getDigestByName()`):
- blake2b-512
- keccak224, keccak256, keccak384, keccak512 (mapped to SHA3 variants)
- md4, md5
- sha1
- sha2-224, sha2-256, sha2-384, sha2-512
- sha3-224, sha3-256, sha3-384, sha3-512

Both `crypto_hash()` and `crypto_hmac()` support all these algorithms.

**Note**: Keccak is mapped to SHA3 in OpenSSL. True Keccak (pre-standardization) differs slightly from SHA3.

## Development Workflow

### Adding a New Hash Algorithm

1. Add the new algorithm case to `getDigestByName()` in `src/crypto_hash.cpp`
2. Return the appropriate OpenSSL EVP_MD function (e.g., `EVP_sha512_256()`)
3. Update error messages to include the new algorithm name
4. Add tests to `test/sql/crypto.test`
5. Update README.md with the new algorithm

### Error Handling

The C++ implementation throws DuckDB exceptions:
- `InvalidInputException`: For invalid algorithm names or input validation failures
- `InternalException`: For OpenSSL operation failures

Exceptions are caught by DuckDB's executor and presented to the user.

## CI/CD

The repository uses the DuckDB extension template's CI system:
- Build configuration is in `extension_config.cmake`
- CI tools are in `extension-ci-tools/` (git submodule)
- The Makefile includes `extension-ci-tools/makefiles/duckdb_extension.Makefile`
