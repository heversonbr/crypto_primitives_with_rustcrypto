

// hashing with SHA256: we need the following dependencies
// [dependencies]
// sha2 = "0.10"  # SHA-2 hashing
// hex = "0.4"    # Optional: for hex encoding

use hex::encode;
use sha2::{Sha256, Digest};   // Import Sha256 and Digest trait
use log::{info, debug};

#[allow(unused_imports)]
#[allow(dead_code)]

pub fn hash_example() { 
    info!("-------------------");
    info!("Example 1: Hashing");
    info!("-------------------");
    // Create a SHA-256 hasher.
	// Add data using .update().
	// Finalize with .finalize() to get the hash.
	// Convert to a readable hex string.

    let input_data = "My text to hash";     // input data to hash 
    debug!("data: {} ", input_data);
    let result = hash_with_sha2(input_data.as_bytes());
    info!("SHA256 Hash: {}" , result);
}

#[allow(dead_code)]
// This function hashes input data using the SHA-256 algorithm and returns the result as a hexadecimal string.
pub fn hash_with_sha2(data_to_hash: &[u8]) -> String {
    
    // Step 1: Create a new instance of the SHA-256 hasher.
    let mut hasher = Sha256::new();

    // Step 2: Update the hasher with the data we want to hash.
    hasher.update(data_to_hash);

    // Step 3: Finalize the hashing process and get the hashed data.
    let hashed_data = hasher.finalize();

    // Step 4: Convert the hashed data (byte array) into a human-readable hexadecimal string.
    encode(hashed_data)
}