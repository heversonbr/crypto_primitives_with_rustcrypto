mod hashing;
mod message_authentication;
mod symmetric_authenticated_encryption_example;
mod asymmetric_authenticated_encryption_example;
mod password_hashing_with_key_derivation_functions;
mod key_exchange;

use log::LevelFilter;
use env_logger::Builder;

// Here you find examples of how to use basic cryptography primitives with RustCrypto
#[allow(unused_imports)]
#[allow(dead_code)]
fn main() {
    println!("Crytography primitives with RustCrypto Library");
    // 0) Using 'log' and 'env_logger' for logging, initialize logger:
    // env_logger::init();   // <- use this way to control using the env variable 'RUST_LOG=DEBUG cargo run'
    // set to debug to see more output
    Builder::new().filter_level(LevelFilter::Info).init();
    
    // 1) Hashwith SHA256
    hashing::hash_example();
    //
    // 2) Derivation Key functions (h)
    // 2.1) Hashing with Argon2: 
    password_hashing_with_key_derivation_functions::run_argon_example();
    password_hashing_with_key_derivation_functions::run_brute_force_example();
    //
    // 3) Verifying integrity and authentication with HMAC (Hash-based Message Authentication Code)
    message_authentication::check_integrity_example();
    //
    // 4) Symmetric encryption: 
    // 4.1) Encryption & authentication with AES-256-GCM
    symmetric_authenticated_encryption_example::aes_gcm_authentication_encryption_example();
    // 4.2) Encryption & authentication with ChaCha20-Poly1305
    symmetric_authenticated_encryption_example::chacha_poly_authentication_encryption_example();
    //
    // 5) Asymmetric encryption:
    // 5.1) Asymmetric encryption fo Confidentiality using RSA and OAEP
    asymmetric_authenticated_encryption_example::rsa_oaep_asymmetric_encryption_confidentiality_example();
    // 5.2) Asymmetric encryption for Digital Signatures using RSA and PKCS1-v1_5
    asymmetric_authenticated_encryption_example::rsa_asymmetric_encryption_digital_signatures_authentication();
    // 5.3) Asymmetric encryption for Digital Signatures using Ed25519
    asymmetric_authenticated_encryption_example::ed25529_asymmetric_encryption_digital_signatures_authentication();
    //
    // 6) Key exchange:
    // 6.1) Key exchange using Diffie-Hellman (DH) Key Exchange algorithm
    key_exchange::key_exchange_dh_example();
    // 6.2) Key exchange using Elliptic Curve Diffie-Hellman (ECDH): public keyswithout serialization
    key_exchange::key_exchange_ecdh_example_1();
    // 6.3) Key exchange using Elliptic Curve Diffie-Hellman (ECDH): public keys are serialized into byte arrays (EncodedPoint)
    key_exchange::key_exchange_ecdh_example_2();
    // 6.4) Key exchange using X25519 Key Exchange algorithm
    key_exchange::key_exchange_ex25519_example();

}
