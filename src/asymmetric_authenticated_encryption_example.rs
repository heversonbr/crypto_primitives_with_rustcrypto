use log::{info,debug,error};

// [dependencies]
// rsa = "0.9"  # RustCrypto's RSA crate
// rand = "0.9"  # Secure random number generator
// sha2 = "0.10"  # Hash function for OAEP

use rsa::{Oaep, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey}; // RSA asymmetric encryption/decryption
use rand::rngs::OsRng; // Cryptographically secure random number generator
use sha2::{Sha256, Digest}; // Hash function used in OAEP

// ---------------------------
// Secure communication (confidentiality) with RSA Encryption/Decryption
#[allow(dead_code)]
pub fn rsa_oaep_asymmetric_encryption_confidentiality_example() {
    info!("---------------Asymmetric Encryption------------");
    info!("Example 5.1: RSA Encryption/Decryption with OAEP");
    info!("----------------- Confidentiality --------------");
    info!("------------------------------------------------");
    // 1) Generate RSA Key Pair (2048-bit for security)
    let mut rng = OsRng; // Random number generator
    let dest_private_key = RsaPrivateKey::new(&mut rng, 2048)
                    .expect("Failed to generate private key");
    let dest_public_key = RsaPublicKey::from(&dest_private_key);
    // 2) Define the message
    let plaintext_msg = b"Hello, this is my message to send, Im using RustCrypto";
    info!("Plaintext Msg: {:?}", std::str::from_utf8(plaintext_msg));
    // 3) Encrypt the message with the receiver's public key (Confidentiality)
    let padding = Oaep::new::<Sha256>();
    let encrypted_data = dest_public_key.encrypt(&mut rng, padding, plaintext_msg)
                    .expect("Failed to encrypt message");
    debug!("Encrypted Msg: {:?}", &encrypted_data);
    // 4) Decrypt the message with the private key
    let dest_padding = Oaep::new::<Sha256>();
    let decrypted_data = dest_private_key.decrypt(dest_padding, &encrypted_data)
                    .expect("Failed to decrypt message!");
    info!("Decrypted Msg: {:?}", std::str::from_utf8(&decrypted_data).unwrap());
}

// ---------------------------
// Digital signatures with RSA 
// uses rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Sign};
#[allow(dead_code)]
pub fn rsa_asymmetric_encryption_digital_signatures_authentication(){ 
    info!("---------------Asymmetric Encryption------------");
    info!("Example 5.2: Digital signatures with RSA");
    info!("----------------- Confidentiality --------------");
    info!("------------------------------------------------");
    // Instantiate a random number generator 
    let mut rng = OsRng;
    // Generate a 2048-bit RSA key pair
    let signer_private_key = RsaPrivateKey::new(&mut rng, 2048)
                .expect("Failed to generate private key");
    let signer_public_key = RsaPublicKey::from(&signer_private_key);
    // Message to be signed
    let message = b"Secure message with RSA Signature";
    info!("Plaintext message: {:?}", std::str::from_utf8(message)
                .expect("Error extracting string from bytes"));
    // Hash the message using SHA-256
    let mut hasher = Sha256::new();
    hasher.update(message);
    let hashed_message = hasher.finalize();
    // Sign the hashed message
    let padding = Pkcs1v15Sign::new::<Sha256>();
    let signature = signer_private_key
                .sign(padding.clone(), &hashed_message)
                .expect("Failed to sign message");
    // Print the signature in hexadecimal format
    let signature_hex = hex::encode(&signature);
    info!("Signature (hex): {}", signature_hex);
    // Verify the signature
    let verify_result = signer_public_key
                .verify(padding, &hashed_message, &signature);
    match verify_result {
        Ok(_) => println!("Signature verified!"),
        Err(_) => error!("Signature verification failed!"),
    }
}


// Digital signatures using Ed25519 (elliptic-curve)
// Ed25519 is an elliptic-curve digital signature algorithm (EdDSA) known for its high security, speed, 
// and resistance to side-channel attacks. It is widely used for digital signatures to ensure 
// data integrity, authentication, and non-repudiation.
// NOTE: ed25519-dalek 2.1.1, which has breaking changes compared to earlier versions: e.g., Keypair::generate() has been removed
use ed25519_dalek::{Signer, SigningKey, Signature, Verifier, VerifyingKey};
#[allow(dead_code)]
pub fn ed25529_asymmetric_encryption_digital_signatures_authentication(){
    info!("------------------------Asymmetric Encryption------------------");
    info!("Example 5.3: Digital signatures using (elliptic-curve) Ed25519 ");
    info!("-------------------------- Confidentiality --------------------");
    info!("---------------------------------------------------------------");
    // Generate a new Ed25519 keypair (private & public keys)
    let mut csprng = OsRng;
    let signing_key: SigningKey = SigningKey::generate(&mut csprng);
    let verifying_key: VerifyingKey = signing_key.verifying_key();
    // Define a message to sign
    let message = b"Hello, RustCrypto here: This is my data to sign!";
    info!("Plaintext message: {:?}", std::str::from_utf8(message)
            .expect("Error extracting string from bytes"));
    // Sign the message with the private key
    let signature: Signature = signing_key.sign(message);
    // Print the signature in hexadecimal format
    let signature_hex = hex::encode(&signature.to_vec());
    info!("Signature (hex): {}", signature_hex);
    // Verify the signature using the public key
    match verifying_key.verify(message, &signature) {
        Ok(_) => info!("Signature is VALID!"),
        Err(_) => error!("Signature is INVALID!"),
    }
}


