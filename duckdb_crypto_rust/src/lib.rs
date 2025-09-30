use std::alloc::Layout;
use std::ffi::{c_char, c_uchar, c_void, CString};
use std::ptr;
use std::slice;
use std::str;
use std::sync::Once;

use digest::{DynDigest, Mac};

use hmac::SimpleHmac;

// Blake3 wrapper to implement DynDigest trait
struct Blake3Hasher(blake3::Hasher);

impl Default for Blake3Hasher {
    fn default() -> Self {
        Blake3Hasher(blake3::Hasher::new())
    }
}

impl DynDigest for Blake3Hasher {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize_reset(&mut self) -> Box<[u8]> {
        let hash = self.0.finalize();
        self.0.reset();
        Box::from(hash.as_bytes() as &[u8])
    }

    fn finalize_into(self, _buf: &mut [u8]) -> Result<(), digest::InvalidBufferSize> {
        // Blake3 doesn't support finalize_into directly, so we implement it
        let hash = self.0.finalize();
        let hash_bytes = hash.as_bytes();
        if _buf.len() != hash_bytes.len() {
            return Err(digest::InvalidBufferSize);
        }
        _buf.copy_from_slice(hash_bytes);
        Ok(())
    }

    fn finalize_into_reset(&mut self, _buf: &mut [u8]) -> Result<(), digest::InvalidBufferSize> {
        let hash = self.0.finalize();
        self.0.reset();
        let hash_bytes = hash.as_bytes();
        if _buf.len() != hash_bytes.len() {
            return Err(digest::InvalidBufferSize);
        }
        _buf.copy_from_slice(hash_bytes);
        Ok(())
    }

    fn reset(&mut self) {
        self.0.reset();
    }

    fn output_size(&self) -> usize {
        32 // BLAKE3 produces 32-byte (256-bit) hashes
    }

    fn box_clone(&self) -> Box<dyn DynDigest> {
        Box::new(Blake3Hasher(self.0.clone()))
    }
}

macro_rules! make_str {
    ( $s : expr , $len : expr ) => {
        unsafe { str::from_utf8_unchecked(slice::from_raw_parts($s as *const u8, $len)) }
    };
}

// Dynamic hash function
fn use_hasher(hasher: &mut dyn DynDigest, data: &[u8]) -> Box<[u8]> {
    hasher.update(data);
    hasher.finalize_reset()
}

// You can use something like this when parsing user input, CLI arguments, etc.
// DynDigest needs to be boxed here, since function return should be sized.
fn select_hasher(s: &str) -> Option<Box<dyn DynDigest>> {
    match s {
        "blake2b-512" => Some(Box::<blake2::Blake2b512>::default()),
        "blake3" => None, // Blake3 handled separately due to different API
        "blake3-hmac" => None, // Blake3 handled separately
        "keccak224" => Some(Box::<sha3::Keccak224>::default()),
        "keccak256" => Some(Box::<sha3::Keccak256>::default()),
        "keccak384" => Some(Box::<sha3::Keccak384>::default()),
        "keccak512" => Some(Box::<sha3::Keccak512>::default()),
        "md4" => Some(Box::<md4::Md4>::default()),
        "md5" => Some(Box::<md5::Md5>::default()),
        "sha1" => Some(Box::<sha1::Sha1>::default()),
        "sha2-224" => Some(Box::<sha2::Sha224>::default()),
        "sha2-256" => Some(Box::<sha2::Sha256>::default()),
        "sha2-384" => Some(Box::<sha2::Sha384>::default()),
        "sha2-512" => Some(Box::<sha2::Sha512>::default()),
        "sha3-224" => Some(Box::<sha3::Sha3_224>::default()),
        "sha3-256" => Some(Box::<sha3::Sha3_256>::default()),
        "sha3-384" => Some(Box::<sha3::Sha3_384>::default()),
        "sha3-512" => Some(Box::<sha3::Sha3_512>::default()),
        _ => None,
    }
}

fn available_hash_algorithms() -> Vec<&'static str> {
    vec![
        "blake2b-512",
        "blake3",
        "blake3-hmac",
        "keccak224",
        "keccak256",
        "keccak384",
        "keccak512",
        "md4",
        "md5",
        "sha1",
        "sha2-224",
        "sha2-256",
        "sha2-384",
        "sha2-512",
        "sha3-224",
        "sha3-256",
        "sha3-384",
        "sha3-512",
    ]
}

#[repr(C)]
pub enum ResultCString {
    Ok(*mut c_char),
    Err(*mut c_char),
}

#[no_mangle]
/// Hash a varchar using the specified hashing algorithm.
pub extern "C" fn hashing_varchar(
    hash_name: *const c_char,
    hash_name_len: usize,

    content: *const c_char,
    len: usize,
) -> ResultCString {
    if hash_name.is_null() || content.is_null() {
        return ResultCString::Ok(ptr::null_mut());
    }

    let hash_name_str = make_str!(hash_name, hash_name_len);
    let content_slice = unsafe { slice::from_raw_parts(content as *const c_uchar, len) };

    // Handle Blake3 specially since it uses a different API
    if hash_name_str == "blake3" {
        let hash = blake3::hash(content_slice);
        let hex_encoded = base16ct::lower::encode_string(hash.as_bytes());
        return ResultCString::Ok(create_cstring_with_custom_allocator(&hex_encoded).into_raw());
    }

    match select_hasher(hash_name_str) {
        Some(mut hasher) => {
            let hash_result = use_hasher(&mut *hasher, content_slice);

            // Now hex encode the byte string.
            let hex_encoded = base16ct::lower::encode_string(&hash_result);

            ResultCString::Ok(create_cstring_with_custom_allocator(&hex_encoded).into_raw())
        }
        None => {
            let error_message = format!(
                "Invalid hash algorithm '{}' available algorithms are: {}",
                hash_name_str,
                available_hash_algorithms().join(", ")
            );
            ResultCString::Err(create_cstring_with_custom_allocator(&error_message).into_raw())
        }
    }
}

macro_rules! make_hmac {
    ($hash_function : ty, $key: expr, $content: expr) => {
        match SimpleHmac::<$hash_function>::new_from_slice($key).and_then(|mut hmac| {
            hmac.update($content);
            Ok(Box::new(hmac.finalize()))
        }) {
            Ok(final_result) => {
                let hex_encoded =
                    base16ct::lower::encode_string(final_result.into_bytes().as_slice());
                ResultCString::Ok(create_cstring_with_custom_allocator(&hex_encoded).into_raw())
            }
            Err(_) => {
                let error_message = "Failed to create HMAC";
                ResultCString::Err(create_cstring_with_custom_allocator(&error_message).into_raw())
            }
        }
    };
}

#[no_mangle]
/// Create a HMAC using the specified hash function and key.
pub extern "C" fn hmac_varchar(
    hash_name: *const c_char,
    hash_name_len: usize,

    key: *const c_char,
    key_len: usize,

    content: *const c_char,
    len: usize,
) -> ResultCString {
    if hash_name.is_null() || key.is_null() || content.is_null() {
        return ResultCString::Ok(ptr::null_mut());
    }

    let hash_name_str = make_str!(hash_name, hash_name_len);
    let key_slice = unsafe { slice::from_raw_parts(key as *const c_uchar, key_len) };
    let content_slice = unsafe { slice::from_raw_parts(content as *const c_uchar, len) };

    match hash_name_str {
        "blake2b-512" => {
            make_hmac!(blake2::Blake2b512, key_slice, content_slice)
        }
        "blake3" => {
            // BLAKE3 uses its own keyed hashing mode (faster, recommended)
            // We convert the key to a fixed 32-byte key
            let mut key_bytes = [0u8; 32];
            if key_slice.len() == 32 {
                key_bytes.copy_from_slice(key_slice);
            } else {
                // Hash the key to get a fixed-size key
                let key_hash = blake3::hash(key_slice);
                key_bytes.copy_from_slice(key_hash.as_bytes());
            }

            let mut hasher = blake3::Hasher::new_keyed(&key_bytes);
            hasher.update(content_slice);
            let hash = hasher.finalize();
            let hex_encoded = base16ct::lower::encode_string(hash.as_bytes());
            ResultCString::Ok(create_cstring_with_custom_allocator(&hex_encoded).into_raw())
        }
        "blake3-hmac" => {
            // Use Blake3 native keyed mode for blake3-hmac as well for consistency
            let mut key_bytes = [0u8; 32];
            if key_slice.len() == 32 {
                key_bytes.copy_from_slice(key_slice);
            } else {
                // Hash the key to get a fixed-size key
                let key_hash = blake3::hash(key_slice);
                key_bytes.copy_from_slice(key_hash.as_bytes());
            }

            let mut hasher = blake3::Hasher::new_keyed(&key_bytes);
            hasher.update(content_slice);
            let hash = hasher.finalize();
            let hex_encoded = base16ct::lower::encode_string(hash.as_bytes());
            ResultCString::Ok(create_cstring_with_custom_allocator(&hex_encoded).into_raw())
        }
        "keccak224" => {
            make_hmac!(sha3::Keccak224, key_slice, content_slice)
        }
        "keccak256" => {
            make_hmac!(sha3::Keccak256, key_slice, content_slice)
        }
        "keccak384" => {
            make_hmac!(sha3::Keccak384, key_slice, content_slice)
        }
        "keccak512" => {
            make_hmac!(sha3::Keccak512, key_slice, content_slice)
        }
        "md4" => {
            make_hmac!(md4::Md4, key_slice, content_slice)
        }
        "md5" => {
            make_hmac!(md5::Md5, key_slice, content_slice)
        }
        "sha1" => {
            make_hmac!(sha1::Sha1, key_slice, content_slice)
        }
        "sha2-224" => {
            make_hmac!(sha2::Sha224, key_slice, content_slice)
        }
        "sha2-256" => {
            make_hmac!(sha2::Sha256, key_slice, content_slice)
        }
        "sha2-384" => {
            make_hmac!(sha2::Sha384, key_slice, content_slice)
        }
        "sha2-512" => {
            make_hmac!(sha2::Sha512, key_slice, content_slice)
        }
        "sha3-224" => {
            make_hmac!(sha3::Sha3_224, key_slice, content_slice)
        }
        "sha3-256" => {
            make_hmac!(sha3::Sha3_256, key_slice, content_slice)
        }
        "sha3-384" => {
            make_hmac!(sha3::Sha3_384, key_slice, content_slice)
        }
        "sha3-512" => {
            make_hmac!(sha3::Sha3_512, key_slice, content_slice)
        }
        _ => {
            let error_message = format!(
                "Invalid hash algorithm '{}' available algorithms are: {}",
                hash_name_str,
                available_hash_algorithms().join(", ")
            );
            ResultCString::Err(create_cstring_with_custom_allocator(&error_message).into_raw())
        }
    }
}

fn create_cstring_with_custom_allocator(s: &str) -> CString {
    // Convert the input string to a CString
    let c_string = CString::new(s).expect("CString::new failed");

    // Duplicate the CString using the global allocator
    let len = c_string.as_bytes_with_nul().len();
    let layout = Layout::from_size_align(len, 1).unwrap();

    unsafe {
        let ptr = ALLOCATOR.malloc.unwrap()(layout.size()) as *mut c_char;
        if ptr.is_null() {
            panic!("Failed to allocate memory from duckdb");
        }
        ptr::copy_nonoverlapping(c_string.as_ptr(), ptr, len);
        CString::from_raw(ptr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_hash_vectors() {
        // Test empty string
        let empty = blake3::hash(b"");
        println!("blake3(''): {}", hex::encode(empty.as_bytes()));

        // Test 'abc'
        let abc = blake3::hash(b"abc");
        println!("blake3('abc'): {}", hex::encode(abc.as_bytes()));

        // Test 'hello world'
        let hello = blake3::hash(b"hello world");
        println!("blake3('hello world'): {}", hex::encode(hello.as_bytes()));
    }

    #[test]
    fn test_blake3_keyed_vectors() {
        // Test keyed mode with 'key' and 'message'
        let key_bytes = blake3::hash(b"key"); // Hash key to 32 bytes
        let mut hasher = blake3::Hasher::new_keyed(key_bytes.as_bytes());
        hasher.update(b"message");
        let result = hasher.finalize();
        println!("blake3_keyed('key', 'message'): {}", hex::encode(result.as_bytes()));

        // Test keyed mode with 'key' and empty message
        let key_bytes = blake3::hash(b"key");
        let mut hasher = blake3::Hasher::new_keyed(key_bytes.as_bytes());
        hasher.update(b"");
        let result = hasher.finalize();
        println!("blake3_keyed('key', ''): {}", hex::encode(result.as_bytes()));
    }

    #[test]
    fn test_blake3_hmac_vectors() {
        use hmac::SimpleHmac;
        use hmac::Mac;

        // Test HMAC with 'key' and 'message'
        let mut mac = SimpleHmac::<Blake3Hasher>::new_from_slice(b"key").unwrap();
        mac.update(b"message");
        let result = mac.finalize();
        println!("blake3-hmac('key', 'message'): {}", hex::encode(result.into_bytes()));

        // Test HMAC with 'my secret key' and 'test message'
        let mut mac = SimpleHmac::<Blake3Hasher>::new_from_slice(b"my secret key").unwrap();
        mac.update(b"test message");
        let result = mac.finalize();
        println!("blake3-hmac('my secret key', 'test message'): {}", hex::encode(result.into_bytes()));
    }
}

type DuckDBMallocFunctionType = unsafe extern "C" fn(usize) -> *mut ::std::os::raw::c_void;
type DuckDBFreeFunctionType = unsafe extern "C" fn(*mut c_void);

struct Allocator {
    malloc: Option<DuckDBMallocFunctionType>,
    free: Option<DuckDBFreeFunctionType>,
}

// Create a global instance of the Allocator struct.
static mut ALLOCATOR: Allocator = Allocator {
    malloc: None,
    free: None,
};

// A Once instance to ensure that the allocator is only initialized once.
static INIT: Once = Once::new();

#[no_mangle]
pub extern "C" fn init_memory_allocation(
    malloc_fn: DuckDBMallocFunctionType,
    free_fn: DuckDBFreeFunctionType,
) {
    unsafe {
        INIT.call_once(|| {
            ALLOCATOR.malloc = Some(malloc_fn);
            ALLOCATOR.free = Some(free_fn);
        });
    }
}
