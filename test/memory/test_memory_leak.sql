-- Memory leak stress test for Blake and other hash algorithms
-- This test repeatedly calls hash functions to detect memory leaks

-- Test Blake2b-512 (the main focus)
SELECT COUNT(*) FROM (
    SELECT crypto_hash('blake2b-512', 'test data ' || i::VARCHAR)
    FROM generate_series(1, 1000) AS t(i)
) t;

-- Test Blake3
SELECT COUNT(*) FROM (
    SELECT crypto_hash('blake3', 'test data ' || i::VARCHAR)
    FROM generate_series(1, 1000) AS t(i)
) t;

-- Test other algorithms to ensure comprehensive coverage
SELECT COUNT(*) FROM (
    SELECT crypto_hash('sha2-256', 'test data ' || i::VARCHAR)
    FROM generate_series(1, 1000) AS t(i)
) t;

-- Test HMAC functions (also use Rust memory allocation)
SELECT COUNT(*) FROM (
    SELECT crypto_hmac('blake2b-512', 'secret key', 'test data ' || i::VARCHAR)
    FROM generate_series(1, 1000) AS t(i)
) t;

SELECT COUNT(*) FROM (
    SELECT crypto_hmac('blake3', 'secret key', 'test data ' || i::VARCHAR)
    FROM generate_series(1, 1000) AS t(i)
) t;

-- Error case testing (also allocates memory that needs to be freed)
SELECT COUNT(*) FROM (
    SELECT
        CASE
            WHEN TRY_CAST(crypto_hash('invalid_algorithm', 'test') AS VARCHAR) IS NULL
            THEN 'error_handled'
            ELSE 'unexpected'
        END
    FROM generate_series(1, 100) AS t(i)
) t;