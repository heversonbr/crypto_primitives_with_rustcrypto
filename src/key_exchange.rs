// In cryptography, key exchange is essential for establishing secure communication between parties. 
// RustCrypto provides crates to facilitate secure key exchange implementations in Rust, including:
// - Diffie-Hellman (DH) Key Exchange
// - Elliptic Curve Diffie-Hellman (ECDH)
// - X25519
//
// Dependencies for key exchange:
// - DH (Diffie-Hellman): 
//     - rand = "0.8"
//     - num-bigint = "0.4"
//     - num-traits = "0.2"
//     - num-integer = "0.1"
// - ECDH (Elliptic Curve Diffie-Hellman):
//     - p256 = { version = "0.13", features = ["ecdh"] }
//     - rand_core = { version = "0.6", features = ["std"] }
// - X25519:
//     - x25519-dalek = "2.0"
//     - rand_core = { version = "0.6", features = ["getrandom"] }

// 1) Key exchange using Diffie-Hellman (DH) Key Exchange algorithm

use num_bigint::BigUint;
use num_traits::One;
use rand;
use num_bigint::RandBigInt;
use log::{info, debug};

#[allow(dead_code)]
pub fn key_exchange_dh_example() {
    // The Diffie-Hellman key exchange works as follows:
    // 1. Both parties agree on a large prime number `p` and a generator `g` (also called a primitive root modulo p).
    // 2. Each party generates a private key (`a` for Alice and `b` for Bob).
    // 3. Public keys are computed as:
    //    - A = g^a mod p
    //    - B = g^b mod p
    // 4. Each party computes the shared secret, ensuring that:
    //    - B^a mod p == A^b mod p

    info!("---------------------------------------------------------------------------");
    info!("Example 6.1:  Key exchange using Diffie-Hellman (DH) Key Exchange algorithm");
    info!("---------------------------------------------------------------------------");

    let p = BigUint::parse_bytes(b"23", 10).unwrap(); // Prime number
    let g = BigUint::parse_bytes(b"5", 10).unwrap();  // Generator

    // 2. Generate random private keys for Alice and Bob
    let mut rng = OsRng;
    let priv_a = rng.gen_biguint_range(&BigUint::one(), &p); // Private key for Alice
    let priv_b = rng.gen_biguint_range(&BigUint::one(), &p); // Private key for Bob

    // 2. Compute public keys using the generator and private keys
    let pub_a = g.modpow(&priv_a, &p); // Public key A = g^priv_a mod p
    let pub_b = g.modpow(&priv_b, &p); // Public key B = g^priv_b mod p

    // 3. Compute the shared secrets
    let shared_secret_a = pub_b.modpow(&priv_a, &p); // Shared secret for Alice (B^a mod p)
    let shared_secret_b = pub_a.modpow(&priv_b, &p); // Shared secret for Bob (A^b mod p)

    // Check if both secrets match (they should)
    info!("Secrets equal ?: {:?}", shared_secret_a == shared_secret_b);
    debug!("Shared Secret Alice: {}", shared_secret_a);
    debug!("Shared Secret Bob: {}", shared_secret_b);
}

// 2) Key exchange using Elliptic Curve Diffie-Hellman (ECDH)
// The secp256r1 curve (used in ECDH) is often preferred in older systems, but for modern designs, 
// X25519 is generally considered to offer superior security and performance.
use p256::{EncodedPoint, PublicKey, ecdh::EphemeralSecret};
use rand::rngs::OsRng;

#[allow(dead_code)]
pub fn key_exchange_ecdh_example_1() {
    // In this example, public keys are derived directly from the secret keys without serialization.
    // This is useful for systems where both parties share keys within the same memory space (e.g., same Rust process).
    // Key exchange occurs with minimal overhead, making it simpler and more efficient.

    info!("----------------------------------------------------------------------");
    info!("Example 6.2: Key exchange using Elliptic Curve Diffie-Hellman (ECDH): ");
    info!("             public keys without serialization");
    info!("----------------------------------------------------------------------");

    // 1. Generate private keys for Alice and Bob
    let alice_secret = EphemeralSecret::random(&mut OsRng);
    let bob_secret = EphemeralSecret::random(&mut OsRng);

    // 2. Derive the corresponding public keys
    let alice_public = PublicKey::from(&alice_secret);
    let bob_public = PublicKey::from(&bob_secret);

    // 3. Compute the shared secrets using ECDH
    let alice_shared = alice_secret.diffie_hellman(&bob_public);
    let bob_shared = bob_secret.diffie_hellman(&alice_public);

    // Check if both shared secrets match
    info!("Secrets equal ?: {:?}", alice_shared.raw_secret_bytes() == bob_shared.raw_secret_bytes());
    debug!("Alice's Shared Secret: {:?}", alice_shared.raw_secret_bytes());
    debug!("Bob's Shared Secret: {:?}", bob_shared.raw_secret_bytes());
}

#[allow(dead_code)]
pub fn key_exchange_ecdh_example_2() {
    // In this example, the public keys are serialized into byte arrays (EncodedPoint), 
    // which can be transmitted over a network or stored for future use.
    // The keys are decoded using `from_sec1_bytes()` to retrieve the PublicKey object.
    // This method is useful for external systems or protocols that require SEC1-encoded keys.

    info!("-----------------------------------------------------------------------");
    info!("Example 6.3: Key exchange using Elliptic Curve Diffie-Hellman (ECDH):  ");
    info!("             public keys are serialized into byte arrays (EncodedPoint)");
    info!("-----------------------------------------------------------------------");

    // 1. Generate private keys for Alice and Bob
    let alice_secret = EphemeralSecret::random(&mut OsRng);
    let bob_secret = EphemeralSecret::random(&mut OsRng);

    // 2. Serialize the public keys into byte arrays
    let alice_public_bytes = EncodedPoint::from(alice_secret.public_key());
    let bob_public_bytes = EncodedPoint::from(bob_secret.public_key());

    // 3. Decode the public keys back into PublicKey objects
    let bob_public_key = PublicKey::from_sec1_bytes(bob_public_bytes.as_ref()).expect("Bob's public key is invalid!");
    let alice_public_key = PublicKey::from_sec1_bytes(alice_public_bytes.as_ref()).expect("Alice's public key is invalid!");

    // 4. Compute the shared secrets using ECDH
    let alice_shared_secret = alice_secret.diffie_hellman(&bob_public_key);
    let bob_shared_secret = bob_secret.diffie_hellman(&alice_public_key);

    // Check if both shared secrets match
    info!("Secrets equal ?: {:?}", alice_shared_secret.raw_secret_bytes() == bob_shared_secret.raw_secret_bytes());
    debug!("Alice's Shared Secret: {:?}", alice_shared_secret.raw_secret_bytes());
    debug!("Bob's Shared Secret: {:?}", bob_shared_secret.raw_secret_bytes());
}

// 3) Key exchange using X25519 Key Exchange algorithm
// X25519 is based on the Curve25519 elliptic curve, which offers high security and efficiency. 
// It uses Montgomery curves that allow efficient and constant-time scalar multiplication operations.
// X25519 is resistant to certain attacks that affect other curves like secp256r1 and is widely used in modern protocols.
use x25519_dalek::{StaticSecret, PublicKey as x25519_PublicKey};
#[allow(dead_code)]
pub fn key_exchange_ex25519_example() {

    info!("-------------------------------------------------------------");
    info!("Example 6.4: Key exchange using X25519 Key Exchange algorithm");
    info!("-------------------------------------------------------------");

    // 1. Generate private keys (static) for Alice and Bob using X25519
    let alice_secret = StaticSecret::random_from_rng(OsRng);
    let bob_secret = StaticSecret::random_from_rng(OsRng);

    // 2. Derive the corresponding public keys
    let alice_public = x25519_PublicKey::from(&alice_secret);
    let bob_public = x25519_PublicKey::from(&bob_secret);

    // 3. Compute the shared secrets using X25519
    let alice_shared = alice_secret.diffie_hellman(&bob_public);
    let bob_shared = bob_secret.diffie_hellman(&alice_public);

    // Check if both shared secrets match
    assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    info!("Secrets equal ?: {:?}", alice_shared.as_bytes() == bob_shared.as_bytes());
    debug!("Alice's Shared Secret: {:?}", alice_shared.as_bytes());
    debug!("Bob's Shared Secret: {:?}", bob_shared.as_bytes());
}