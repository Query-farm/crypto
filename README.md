# Crypto Hash/HMAC Extension for DuckDB

This extension, `crypto`, adds cryptographic hash functions, HMAC (Hash-based Message Authentication Code) calculation, and cryptographically secure random byte generation to DuckDB.

While DuckDB already includes basic hash functions like `hash()` and `sha256()`, this extension provides additional algorithms including Blake3, SHA-3, supports hashing of various data types beyond just strings, and includes secure random number generation using OpenSSL.

## Installation

**`crypto` is a [DuckDB Community Extension](https://github.com/duckdb/community-extensions).**

To install and use the extension, run these SQL commands in your DuckDB session:

```sql
INSTALL crypto FROM community;
LOAD crypto;
```

That's it! The extension is now ready to use.

## Quick Start

```sql
-- Hash a string with SHA-256 (returns BLOB, convert to hex for readability)
SELECT lower(to_hex(crypto_hash('sha2-256', 'hello world')));
-- Result: b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9

-- Hash an integer
SELECT lower(to_hex(crypto_hash('sha2-256', 42)));
-- Result: e8a4b2ee7ede79a3afb332b5b6cc3d952a65fd8cffb897f5d18016577c33d7cc

-- Calculate HMAC with a secret key
SELECT lower(to_hex(crypto_hmac('sha2-256', 'my-secret-key', 'important message')));
-- Result: 97f324adef061b4ad0abeb6be543913d7db6ba8e6e7f33cd3c4395d619b56df4

-- Generate 32 cryptographically secure random bytes
SELECT lower(to_hex(crypto_random_bytes(32)));
-- Result: (random hex string, different each time)
```

## Hash Functions

### crypto_hash()

**Syntax:**
```sql
crypto_hash(algorithm, value) → BLOB
```

Computes a cryptographic hash of the input value using the specified algorithm.

**Parameters:**
- `algorithm` (VARCHAR): The hash algorithm name (see supported algorithms below)
- `value`: The value to hash (supports multiple data types)

**Returns:** BLOB containing the raw hash bytes

**Supported Data Types:**
- Strings: `VARCHAR`, `BLOB`
- Integers: `TINYINT`, `SMALLINT`, `INTEGER`, `BIGINT`, `HUGEINT`, `UTINYINT`, `USMALLINT`, `UINTEGER`, `UBIGINT`
- Floating point: `FLOAT`, `DOUBLE`
- Other: `BOOLEAN`, `DATE`, `TIME`, `TIMESTAMP`, `UUID`
- Lists: Arrays of fixed-length types (e.g., `INTEGER[]`, `VARCHAR[]`, `BLOB[]`)
  - **Important**: When hashing lists of `VARCHAR` or `BLOB`, each element's length (as a 64-bit integer) is hashed before its content to prevent length extension attacks

**Note:** Different data types with the same value will produce different hashes (e.g., `42::INTEGER` vs `42::BIGINT` vs `'42'::VARCHAR`).

### crypto_hash_agg()

**Syntax:**
```sql
crypto_hash_agg(algorithm, value ORDER BY sort_expression) → BLOB
```

An aggregate function that computes a cryptographic hash over multiple rows of data. This is useful for creating checksums of entire datasets, detecting changes in groups of records, or generating deterministic identifiers for sets of values.

**Parameters:**
- `algorithm` (VARCHAR): The hash algorithm name (same algorithms as `crypto_hash`)
- `value`: The column/expression to hash (supports same data types as `crypto_hash`)
- `ORDER BY`: **Required** - ensures deterministic ordering of values before hashing

**Returns:** BLOB containing the raw hash bytes, or NULL for empty result sets

**Important Notes:**
- The `ORDER BY` clause is **mandatory** because hash aggregation is order-dependent
- Values are hashed sequentially in the order specified by `ORDER BY`
- For `VARCHAR` and `BLOB` types, each value's length is hashed before its content (same as list hashing)
- The function produces the same hash as `crypto_hash()` would produce for an equivalent list
- Empty result sets return `NULL`

**Use Cases:**
- **Dataset Checksums**: Verify data integrity across tables or partitions
- **Change Detection**: Detect if any values in a group have changed
- **Merkle-like Hashing**: Create hierarchical hashes of grouped data
- **Deterministic IDs**: Generate stable identifiers for sets of values

### Supported Hash Algorithms

| Algorithm | Output Size | Description |
|-----------|-------------|-------------|
| `blake2b-512` | 64 bytes | BLAKE2b with 512-bit output |
| `blake3` | 32 bytes | BLAKE3, a modern cryptographic hash |
| `md4` | 16 bytes | MD4 (deprecated, may not work on some systems) |
| `md5` | 16 bytes | MD5 (not cryptographically secure) |
| `sha1` | 20 bytes | SHA-1 (not cryptographically secure) |
| `sha2-224` | 28 bytes | SHA-2 family with 224-bit output |
| `sha2-256` | 32 bytes | SHA-2 family with 256-bit output |
| `sha2-384` | 48 bytes | SHA-2 family with 384-bit output |
| `sha2-512` | 64 bytes | SHA-2 family with 512-bit output |
| `sha3-224` | 28 bytes | SHA-3 family with 224-bit output |
| `sha3-256` | 32 bytes | SHA-3 family with 256-bit output |
| `sha3-384` | 48 bytes | SHA-3 family with 384-bit output |
| `sha3-512` | 64 bytes | SHA-3 family with 512-bit output |
| `keccak224` | 28 bytes | Keccak-224 (mapped to SHA3-224) |
| `keccak256` | 32 bytes | Keccak-256 (mapped to SHA3-256) |
| `keccak384` | 48 bytes | Keccak-384 (mapped to SHA3-384) |
| `keccak512` | 64 bytes | Keccak-512 (mapped to SHA3-512) |

**Note:** Keccak variants are mapped to their SHA-3 equivalents in this implementation.

### Examples

```sql
-- Hash a string with different algorithms
SELECT lower(to_hex(crypto_hash('sha2-256', 'test')));
-- 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08

SELECT lower(to_hex(crypto_hash('blake3', 'test')));
-- 4878ca0425c739fa427f7eda20fe845f6b2e46ba5fe2a14df5b1e32f50603215

SELECT lower(to_hex(crypto_hash('md5', 'test')));
-- 098f6bcd4621d373cade4e832627b4f6

-- Hash different data types
SELECT lower(to_hex(crypto_hash('sha2-256', 42::INTEGER)));
-- e8a4b2ee7ede79a3afb332b5b6cc3d952a65fd8cffb897f5d18016577c33d7cc

SELECT lower(to_hex(crypto_hash('sha2-256', 3.14::DOUBLE)));
-- 2ee9194f7fa84ec9aec9742f02ba1a7f76b6b61b6ecf961a925fa9b4a67b22aa

SELECT lower(to_hex(crypto_hash('sha2-256', true::BOOLEAN)));
SELECT lower(to_hex(crypto_hash('sha2-256', DATE '2024-01-01')));
SELECT lower(to_hex(crypto_hash('sha2-256', UUID '550e8400-e29b-41d4-a716-446655440000')));

-- Hash a list of values
SELECT lower(to_hex(crypto_hash('sha2-256', [1, 2, 3, 4, 5]::INTEGER[])));
-- 4f6addc9659d6fb90fe94b6688a79f2a1fa8d36ec43f8f3e1d9b6528c448a384

SELECT lower(to_hex(crypto_hash('sha2-256', ['hello', 'world']::VARCHAR[])));
-- 306a0d104017a29193be6c7464b1fd5ee65495353a7ccad7dd2928e5fb9731fd

-- Hash data in a table column
CREATE TABLE users (id INTEGER, email VARCHAR);
INSERT INTO users VALUES (1, 'alice@example.com'), (2, 'bob@example.com');
SELECT id, lower(to_hex(crypto_hash('sha2-256', email))) as email_hash FROM users;

-- Get raw binary output size
SELECT octet_length(crypto_hash('sha2-256', 'test'));
-- 32

-- Handle NULL values
SELECT crypto_hash('sha2-256', NULL::VARCHAR) IS NULL;
-- true

-- Aggregate hash over multiple rows (requires ORDER BY)
SELECT lower(to_hex(crypto_hash_agg('sha2-256', email ORDER BY email)))
FROM users;
-- Produces a single hash representing all email values in order

-- Aggregate hash with grouping
SELECT
  department,
  lower(to_hex(crypto_hash_agg('sha2-256', employee_id ORDER BY employee_id))) as dept_hash
FROM employees
GROUP BY department;
-- Produces a hash for each department's employee IDs

-- Verify aggregate produces same hash as list
SELECT crypto_hash_agg('sha2-256', value ORDER BY value) =
       crypto_hash('sha2-256', [1, 2, 3, 4, 5]::INTEGER[])
FROM (VALUES (1), (2), (3), (4), (5)) t(value);
-- true (aggregate hash matches list hash)
```

## Random Byte Generation

### crypto_random_bytes()

**Syntax:**
```sql
crypto_random_bytes(length) → BLOB
```

Generates cryptographically secure random bytes using OpenSSL's `RAND_bytes()` function. This is useful for generating random keys, salts, nonces, and other cryptographic material.

**Parameters:**
- `length` (BIGINT): The number of random bytes to generate (must be between 1 and 4,294,967,295)

**Returns:** BLOB containing the requested number of cryptographically secure random bytes

**Security:** Uses OpenSSL's `RAND_bytes()`, which provides cryptographically strong random numbers suitable for security-sensitive applications like key generation and cryptographic operations.

**Limits:**
- Minimum length: 1 byte
- Maximum length: 4,294,967,295 bytes (4GB - 1, the maximum BLOB size in DuckDB)
- Requesting 0 or negative bytes raises an `InvalidInputException`
- Requesting more than 4GB raises an `InvalidInputException`

### Examples

```sql
-- Generate 32 random bytes (suitable for AES-256 key)
SELECT crypto_random_bytes(32);

-- Generate random bytes and convert to hex for display
SELECT lower(to_hex(crypto_random_bytes(16)));
-- Example output: 3f7a2b8c9d1e4f6a8b2c3d4e5f6a7b8c

-- Generate a random salt for password hashing
SELECT crypto_random_bytes(16) AS salt;

-- Use random bytes as an HMAC key
SELECT crypto_hmac('sha2-256', crypto_random_bytes(32), 'message to authenticate');

-- Generate multiple random values in a table
CREATE TABLE api_keys (id INTEGER, api_key BLOB);
INSERT INTO api_keys
SELECT id, crypto_random_bytes(32)
FROM range(10) t(id);

-- Verify randomness (each call produces different output)
SELECT crypto_random_bytes(16) != crypto_random_bytes(16);
-- true

-- Generate a 128-bit random UUID-like value
SELECT lower(to_hex(crypto_random_bytes(16)));

-- Create a random nonce for cryptographic operations
SELECT crypto_random_bytes(12) AS nonce;  -- 96-bit nonce for AES-GCM
```

## HMAC Functions

### crypto_hmac()

**Syntax:**
```sql
crypto_hmac(algorithm, key, message) → BLOB
```

Computes an HMAC (Hash-based Message Authentication Code) using the specified algorithm, secret key, and message.

**Parameters:**
- `algorithm` (VARCHAR): The hash algorithm name (same algorithms as `crypto_hash`)
- `key` (VARCHAR/BLOB): The secret key for HMAC calculation
- `message` (VARCHAR/BLOB): The message to authenticate

**Returns:** BLOB containing the raw HMAC bytes

**Special Requirements:**
- **Blake3**: Requires a key of exactly 32 bytes (will raise an error otherwise)

### Examples

```sql
-- Basic HMAC with SHA-256
SELECT lower(to_hex(crypto_hmac('sha2-256', 'secret-key', 'message')));
-- 287a3bd8a4fc7731a94c722079055323644d8798bd291bf9878abc9b8fd4b1d0

-- HMAC with different algorithms
SELECT lower(to_hex(crypto_hmac('sha2-512', 'key', 'The quick brown fox jumps over the lazy dog')));
-- b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a

SELECT lower(to_hex(crypto_hmac('sha3-256', 'key', 'message')));
-- 0f43852a24d5597a8200312a95993991581679d63264f1b1ad4b5ccac7fe8ba4

-- Blake3 HMAC (requires exactly 32-byte key)
SELECT lower(to_hex(crypto_hmac('blake3', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'message')));

-- HMAC with empty key or message
SELECT lower(to_hex(crypto_hmac('sha2-256', '', 'message')));
SELECT lower(to_hex(crypto_hmac('sha2-256', 'key', '')));

-- Verify HMAC in authentication scenarios
CREATE TABLE api_requests (user_id INTEGER, data VARCHAR, received_hmac BLOB);
SELECT
  user_id,
  crypto_hmac('sha2-256', 'shared-secret', data) = received_hmac AS is_valid
FROM api_requests;
```

## Common Use Cases

### Generating Cryptographic Keys and Salts
```sql
-- Generate a random AES-256 encryption key
SELECT crypto_random_bytes(32) AS encryption_key;

-- Generate random salts for password hashing
CREATE TABLE users (
  id INTEGER,
  username VARCHAR,
  password_hash BLOB,
  salt BLOB
);

INSERT INTO users (id, username, salt)
VALUES (1, 'alice', crypto_random_bytes(16));

-- Generate random HMAC keys
SELECT crypto_random_bytes(32) AS hmac_key;

-- Create a table with random API keys
CREATE TABLE api_credentials (
  user_id INTEGER,
  api_key BLOB DEFAULT crypto_random_bytes(32)
);
```

### Generating Unique IDs
```sql
-- Generate unique IDs from multiple columns
SELECT
  lower(to_hex(crypto_hash('sha2-256', id::VARCHAR || email || created_at::VARCHAR))) AS unique_id
FROM users;
```

### Data Deduplication
```sql
-- Find duplicate content by hash
SELECT
  lower(to_hex(crypto_hash('blake3', content))) AS content_hash,
  count(*) AS duplicate_count
FROM documents
GROUP BY content_hash
HAVING count(*) > 1;
```

### API Request Signing
```sql
-- Sign API requests with HMAC
SELECT
  request_id,
  lower(to_hex(crypto_hmac('sha2-256', 'api-secret-key', request_body))) AS signature
FROM api_requests;
```

### Hashing Sensitive Data
```sql
-- Hash email addresses for privacy
SELECT
  id,
  lower(to_hex(crypto_hash('sha2-256', email))) AS email_hash
FROM users;
```

### Dataset Integrity Verification
```sql
-- Create a checksum for an entire table partition
SELECT
  partition_date,
  lower(to_hex(crypto_hash_agg('blake3', transaction_id ORDER BY transaction_id))) AS partition_checksum
FROM transactions
GROUP BY partition_date;

-- Detect changes in a dataset by comparing checksums
WITH current_hash AS (
  SELECT crypto_hash_agg('sha2-256', data ORDER BY id) AS hash
  FROM critical_table
)
SELECT hash = '\x<expected_hash_value>'::BLOB AS data_unchanged
FROM current_hash;
```

### Merkle-Style Hierarchical Hashing
```sql
-- Create hierarchical hashes for efficient change detection
-- Level 1: Hash individual user transactions
WITH user_hashes AS (
  SELECT
    user_id,
    crypto_hash_agg('sha2-256', transaction_id ORDER BY timestamp) AS user_hash
  FROM transactions
  GROUP BY user_id
)
-- Level 2: Hash all user hashes to get global hash
SELECT
  lower(to_hex(crypto_hash_agg('sha2-256', user_hash ORDER BY user_id))) AS global_hash
FROM user_hashes;
```

## Important Notes

1. **Output Format**: `crypto_hash()`, `crypto_hash_agg()`, and `crypto_hmac()` all return raw binary data as `BLOB`. Use `to_hex()` to convert to hexadecimal strings, or `lower(to_hex(...))` for lowercase hex.

2. **Type Sensitivity**: The hash is computed on the binary representation of the data type. The same numeric value with different types will produce different hashes:
   ```sql
   SELECT crypto_hash('sha2-256', 42::INTEGER) != crypto_hash('sha2-256', 42::BIGINT);
   -- true (different hashes)
   ```

3. **NULL Handling**: `crypto_hash()` and `crypto_hmac()` return `NULL` if the input value is `NULL`. `crypto_hash_agg()` returns `NULL` for empty result sets.

4. **List and Aggregate Hashing with Length Encoding**:
   - Applies to both `crypto_hash()` when hashing lists and `crypto_hash_agg()` when aggregating values
   - For fixed-length types (integers, floats, dates, etc.), only the raw binary data is hashed
   - For variable-length types (`VARCHAR` and `BLOB`), each element is hashed as: `[8-byte length][content]`
   - The length is encoded as a 64-bit unsigned integer (uint64_t) in native byte order
   - This prevents length extension attacks where `['ab', 'c']` would otherwise hash the same as `['a', 'bc']`
   - Example:
     ```sql
     -- These produce different hashes due to length encoding
     SELECT lower(to_hex(crypto_hash('sha2-256', ['ab', 'c']::VARCHAR[])));
     -- 43ee655579de01ca739b3f95c1c2d3f46d353b2c0df818064ea594506cdb2617

     SELECT lower(to_hex(crypto_hash('sha2-256', ['a', 'bc']::VARCHAR[])));
     -- 9a8acca1b6c6c0befd3fbc756aed625da998c998f7252e738c4ef061906b9b21

     -- Different hashes prove length encoding prevents collisions

     -- Same applies to aggregate function
     SELECT lower(to_hex(crypto_hash_agg('sha2-256', data ORDER BY data)))
     FROM (VALUES ('ab'), ('c')) t(data);
     -- Produces different hash than ['a', 'bc']
     ```

5. **Security Considerations**:
   - MD4, MD5, and SHA-1 are **not cryptographically secure** and should not be used for security purposes
   - For modern applications, use SHA-2 (sha2-256, sha2-512) or Blake3
   - For HMAC operations, use a strong, randomly generated secret key
   - Blake3 HMAC requires exactly a 32-byte key

6. **Aggregate Function Requirements**:
   - `crypto_hash_agg()` **requires** an `ORDER BY` clause to ensure deterministic results
   - Without `ORDER BY`, the function will raise an error
   - The aggregate produces the same hash as `crypto_hash()` would for an equivalent ordered list
   - Example:
     ```sql
     -- This works - produces same hash as list [1,2,3,4,5]
     SELECT crypto_hash_agg('sha2-256', value ORDER BY value)
     FROM (VALUES (5), (2), (1), (4), (3)) t(value);

     -- This fails - ORDER BY is required
     SELECT crypto_hash_agg('sha2-256', value)
     FROM (VALUES (1), (2)) t(value);
     -- Error: Hash aggregation requires a distinct total ordering
     ```

7. **Algorithm Availability**: MD4 is deprecated and may be disabled in modern OpenSSL builds.

## Comparison with Built-in DuckDB Functions

DuckDB has built-in `hash()` and `sha256()` functions, but this extension provides:
- More hash algorithms (Blake3, SHA-3, SHA-512, etc.)
- Support for hashing multiple data types beyond strings
- HMAC calculation capabilities
- Standard cryptographic implementations via OpenSSL and Blake3

## License

This extension uses OpenSSL for most cryptographic operations and includes the Blake3 hash implementation. This extension uses the MIT license.

