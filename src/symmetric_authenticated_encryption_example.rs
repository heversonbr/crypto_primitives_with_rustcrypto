#[allow(unused_imports)]

use log::{info, error, debug};
use aes_gcm::{Aes256Gcm, Key, Nonce}; // AES-GCM
use aes_gcm::aead::{Aead, KeyInit}; // AES-GCM AEAD (Authenticated Encryption with Associated Data)
use rand; // Random number generator for secure random values
use rand::RngCore; // Required for `fill_bytes()`

// NOTE: For cryptographic use cases, it’s important to use a secure random number generator, 
// such as `rand::rngs::OsRng`, to ensure safe generation of keys and nonces.

#[allow(unused_imports)]
#[allow(dead_code)]
pub fn aes_gcm_authentication_encryption_example(){
    // AES-256-GCM provides confidentiality, integrity, and authenticity by using GCM (Galois/Counter Mode),
    // which includes authentication via GMAC (Galois Message Authentication Code).
    info!("---------------Symmetric Encryption-------------------");
    info!("Example 4.1: Authenticated Encryption with AES-256-GCM");
    info!("------------ Confidentiality and Integrity -----------");
    info!("------------------------------------------------------");
    // 1) Get a random number generator for key and nonce generation
    let mut rng = rand::thread_rng(); // Provides thread-local RNG (deprecated in rand v0.9)
    // NOTE: In rand v0.9, use `rand::rng()` instead of `rand::thread_rng()`
    // 2) Generate a random 256-bit key (32 bytes)
    let mut key_bytes = [0u8; 32];  // Create a 32-byte array for the key
    rng.fill_bytes(&mut key_bytes);  // Fill the array with random bytes (secure randomness)
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);  // Convert the byte array to a key
    info!("Generated key: {:?}", key);
    // 3) Generate a random 12-byte nonce (Initialization Vector)
    // A unique nonce must be used for each encryption to ensure security.
    let mut nonce_bytes = [0u8; 12];  // 12 bytes for the nonce
    rng.fill_bytes(&mut nonce_bytes);  // Fill the nonce with random bytes
    let nonce = Nonce::from_slice(&nonce_bytes);  // Convert to Nonce type
    debug!("Generated nonce: {:?}", nonce);
    // 4) Data we want to encrypt (plaintext)
    let plaintext = b"My Sensitive data that needs encryption";
    // 5) Associated Data (AAD) - Authenticated but not encrypted (Optional in this example)
    //let aad = b"header-metadata";
    // 6) Create AES-GCM cipher instance using the generated key
    let cipher = Aes256Gcm::new(key);
    // 7) ENCRYPT the data
    let encrypted_text = cipher.encrypt(nonce, plaintext.as_ref())
        .expect("encryption failure!");  // Encrypt using AES-GCM
    info!("Original (plaintext): {:?}", std::str::from_utf8(plaintext).unwrap());
    debug!("Original (bytes): {:?}", plaintext);
    debug!("Encrypted (ciphertext): {:?}\n", encrypted_text);
    // 8) DECRYPT the data
    let decrypted_text = cipher.decrypt(nonce, encrypted_text.as_ref())
        .expect("decryption failure!");  // Decrypt using AES-GCM
    debug!("Decrypted (bytes): {:?}", decrypted_text);
    info!("Decrypted (plaintext): {:?}", std::str::from_utf8(&decrypted_text).unwrap());
    // NOTE: 
    // `rand::thread_rng()` is deprecated in rand v0.9 and later, replaced by `rand::rng()`.
}


// [Dependencies for ChaCha20-Poly1305]
// chacha20poly1305 = "0.10" # RustCrypto's ChaCha20-Poly1305 implementation
// rand = "0.8"
use chacha20poly1305::ChaCha20Poly1305;

#[allow(dead_code)]
pub fn chacha_poly_authentication_encryption_example() {
    // ChaCha20-Poly1305 is an AEAD (Authenticated Encryption with Associated Data) cipher, offering an alternative to AES-GCM.
    // It's especially useful on systems without hardware acceleration (e.g., mobile, embedded devices).
    // Stream cipher: No block size, making it efficient for variable-length data.
    // Resistant to side-channel attacks.
    info!("---------------------Symmetric Encryption-------------------");
    info!("Example 4.2: Authenticated Encryption with ChaCha20-Poly1305");
    info!("----------------- Confidentiality and Integrity ------------");
    info!("------------------------------------------------------------");
    // 1) Get a random number generator for key and nonce generation
    let mut rng = rand::thread_rng();  // Provides thread-local RNG (deprecated in rand v0.9)
    // NOTE: In rand v0.9, use `rand::rng()` instead of `rand::thread_rng()`
    // 2) Generate a random 256-bit key (32 bytes)
    let mut key_bytes = [0u8; 32];  // Create a 32-byte array for the key
    rng.fill_bytes(&mut key_bytes);  // Fill the array with random bytes (secure randomness)
    let key = Key::<ChaCha20Poly1305>::from_slice(&key_bytes);  // Convert the byte array to key
    // 3) Generate a random 12-byte nonce (Initialization Vector)
    // A unique nonce is needed for each encryption to ensure security.
    let mut nonce_bytes = [0u8; 12];  // 12 bytes for the nonce
    rng.fill_bytes(&mut nonce_bytes);  // Fill the nonce with random bytes
    let nonce = Nonce::from_slice(&nonce_bytes);  // Convert to Nonce type
    // 4) Set data to encrypt (plaintext)
    let plaintext = b"Sensitive data for ChaCha20-Poly1305";
    info!("Text to Encrypt: {}", std::str::from_utf8(plaintext).unwrap());
    // 4.1) Associated Data (AAD) - Authenticated but not encrypted
    let aad = b"authenticated-header";
    debug!("Associated Data (AAD): {}", std::str::from_utf8(aad).unwrap());
    // 5) Instantiate the ChaCha20-Poly1305 cipher using the generated key
    let cipher = ChaCha20Poly1305::new(key);
    // 6) ENCRYPT the data
    let ciphered_text = cipher.encrypt(nonce, plaintext.as_ref())
        .expect("encryption failure!");  // Encrypt using ChaCha20-Poly1305
    debug!("Encrypted text: {:?}", &ciphered_text);
    // 7) DECRYPT the data
    let decrypted_text = cipher.decrypt(nonce, ciphered_text.as_ref())
        .expect("decryption failure!");  // Decrypt using ChaCha20-Poly1305
    info!("Decrypted text: {}", std::str::from_utf8(&decrypted_text).expect("decryption error"));
}