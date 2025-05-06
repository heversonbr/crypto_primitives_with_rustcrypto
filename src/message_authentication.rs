// HMAC (Hash-based Message Authentication Code) is a cryptographic technique used for verifying data integrity and authenticity.
// It combines a cryptographic hash function (e.g., SHA-256) with a secret key to generate a unique authentication code for a given message.
//
// How it works:
// 1. The sender and receiver share a secret key.
// 2. The sender computes the HMAC by hashing the message along with the secret key.
// 3. The receiver recomputes the HMAC upon receiving the message and compares it to the received HMAC.
// 4. If they match, the message is authentic and has not been altered.
//
// HMAC provides strong security against tampering. If an attacker modifies the message, they won’t be able to recompute the HMAC correctly without the secret key.
//
// Key Features:
// - **Integrity**: Ensures the message hasn’t been altered.
// - **Authentication**: Verifies that the message came from a trusted source (i.e., someone who knows the secret key).
//
// Recommended HMAC algorithms:
// - HMAC-SHA-256 / HMAC-SHA-512 (secure & widely used)
// - Avoid using weak hash functions (e.g., MD5, SHA-1).
//
// Common Use Cases:
// - API authentication (e.g., AWS Signature v4, OAuth HMAC-SHA256)
// - Message integrity checks in network protocols (e.g., TLS, IPSec)
// - Token-based authentication (e.g., JWT HMAC signing)
//
// Dependencies:
// - hmac = "0.12"
// - sha2 = "0.10"
// - hex = "0.4"

use hex::encode;
use log::info;
use sha2::Sha256;   // Import SHA-256 hash function and Digest trait
use hmac::{Hmac, Mac};  // Import HMAC and Mac traits for HMAC operations
use log::debug;

#[allow(unused_imports)]
#[allow(dead_code)]
pub fn check_integrity_example(){
    // Example of verifying message integrity using HMAC
    info!("--------------------------------------------");
    info!("Example 3: Message Authentication using HMAC");
    info!("--------------------------------------------");

    // Shared secret key (must be kept private by both sender and receiver)
    let secret_key = "mysupersecretkey".as_bytes();

    // Message to be authenticated (using 'b' to indicate binary representation of the string)
    let message = b"Hello, HMAC in Rust! This is the data I want to verify later";

    // Sender: Compute the HMAC for the message using the secret key
    // The sender will send both the message and the HMAC to the receiver
    let hmac_result = generate_hmac(secret_key, message);
    info!("Generated HMAC: {}", hmac_result);

    // Receiver: Compute the HMAC on the received message and compare it with the received HMAC
    // If the HMACs match, the message is authentic and has not been tampered with
    let is_valid = verify_hmac(secret_key, message, &hmac_result);
    info!("HMAC is valid? : {}", is_valid);
}

// Function to generate HMAC for a message
// Takes the shared secret key and message as input, and returns the HMAC in Hex format
#[allow(dead_code)]
fn generate_hmac(shared_key: &[u8], message: &[u8]) -> String {
    // Step 1: Initialize HMAC with the SHA-256 hash function using the shared secret key
    let mut mac = Hmac::<Sha256>::new_from_slice(shared_key).expect("HMAC can take a key of any size");   
    // Step 2: Update the HMAC with the message
    mac.update(message);  // Feeds the message into the HMAC instance
    // Step 3: Finalize the HMAC computation and get the result
    let mac_result = mac.finalize();  
    // Step 4: Convert the result into a byte array (Vec<u8>) and then into a hex-encoded string
    let result_in_bytes = mac_result.into_bytes();                    
    encode(result_in_bytes)  // Return the HMAC in hex format
}
// Function to verify the HMAC for a received message
// Takes the shared secret key, the message to verify, and the received expected HMAC as input
#[allow(dead_code)]
fn verify_hmac(shared_key: &[u8], message_to_verify: &[u8], received_expected_hmac: &str) -> bool {   
    debug!("Received HMAC: {}", received_expected_hmac);
    // Step 1: Generate the computed HMAC for the received message using the shared secret key
    let computed_hmac = generate_hmac(shared_key, message_to_verify);
    debug!("Computed HMAC: {}", computed_hmac);
    // Step 2: Compare the computed HMAC with the received expected HMAC
    // If they match, the message is authentic and has not been altered
    computed_hmac == received_expected_hmac  // Return true if HMACs match, false otherwise
}