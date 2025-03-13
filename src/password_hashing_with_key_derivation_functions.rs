use log::{info, debug};
use std::time::Instant;
use rand::rngs::OsRng;
use argon2::{self, password_hash::SaltString, Argon2,PasswordHasher, PasswordHash,PasswordVerifier,Algorithm,Version, Params};

use crate::hashing::hash_with_sha2;  // Importing SHA-256 hashing function from the `hashing` module

// Example 1): Hashing/Verifying using KDF with Argon2
#[allow(dead_code)]
pub fn run_argon_example(){

    info!("-----------------------------------");
    info!("Example 2: Key Derivation Functions");
    info!("-----------------------------------");
    info!("Showing the same password hashed twice results in 2 different hashes:");

    let password1_to_hash = "this is my very secure password to be hashed";
    let password2_to_hash = &password1_to_hash;    // Verify the same
    debug!("password1_to_hash: {:?}", password1_to_hash);
    debug!("password2_to_hash: {:?}", password2_to_hash);

    // Hash pass 1
    let hash1_argon2 = hash_with_argon2(password1_to_hash);
    info!("Hash(password1_to_hash): {:?}", hash1_argon2);

     // Hash pass 2
    let hash2_argon2 = hash_with_argon2(password2_to_hash);
    info!("Hash(password2_to_hash): {:?}", hash2_argon2);

    // verify password1 against a hash of password1 
    info!("Verifying password1_to_hash against its hash => ");
    if verify_argon2(password1_to_hash, &hash1_argon2.as_str()) {
        println!("Hash Valid!");  }
        else{ println!("Error: hash not valid!") ;
    }

    // verify password1 against a hash of password1 
    info!("Verifying password2_to_hash against its hash  => ");
    if verify_argon2(password1_to_hash, &hash2_argon2.as_str()) {
        println!("Valid");
    } else {  println!("error"); }

}

// Password Hashing with Argon2
fn hash_with_argon2(pass: &str) -> String {
    
    // Step 1: Instantiate the random number generator (RNG) for generating salts
    let rng = OsRng;

    // Step 2: Create the Argon2 hasher with strong parameters for hashing
    let argon_hasher = Argon2::new(
        Algorithm::Argon2id,    // Using Argon2id (best security variant)
        Version::V0x13,         // Standard Argon2 version
        Params::new(
            65536,     // Memory cost (64MB)
            2,         // Time cost (2 iterations)
            1,         // Parallelism (using 1 thread)
            None   // Default output length (32 bytes)
        ).unwrap(), // 
    );

    // Step 3: Generate a random salt for the password hash to ensure uniqueness even for identical passwords
    let salt = SaltString::generate(rng);

    // Step 4: Start timing the hashing process for performance measurement
    let start_time = Instant::now();  

    // Step 5: Hash the password using Argon2 and the generated salt
    let hashed_data = argon_hasher.hash_password(pass.as_bytes(), &salt).expect("Error computing Argon2 hash!");

    // Calculate the time taken for hashing
    let argon2_duration = start_time.elapsed();   
    let hashed_string: String = hashed_data.to_string();
    
    // Debugging output to show the hashed password and the time taken for hashing
    debug!("Argon2 hash: {:?}", hashed_string);
    debug!("Argon2 took: {:?} to hash!", argon2_duration);
    
    // Return the hashed password as a string
    hashed_string
}

// Verify a password against a hash using Argon2
#[allow(dead_code)]
fn verify_argon2(password_to_verify: &str, argon2_hash: &str) -> bool { 
    // Log the password and hash for debugging purposes
    debug!("password_to_verify: {:?}", password_to_verify);
    debug!("argon_hash: {:?}", argon2_hash);

    // Step 1: Create the Argon2 verifier
    let argon2 = Argon2::default();

    // Step 2: Parse the hash string into a PasswordHash struct
    let parsed_password_hash = PasswordHash::new(argon2_hash).ok().expect("Error parsing the hash");

    // Step 3: Verify if the password matches the Argon2 hash
    argon2.verify_password(password_to_verify.as_bytes(), &parsed_password_hash).is_ok()  // Return true if valid
}

// SHA-256 hashing function as a comparison (for demo purposes)
fn hash_sha256(pass: &str) -> String {
    hash_with_sha2(pass.as_bytes())  // Reusing the SHA-256 hash function from the `hashing` module
}

// Brute force example: showing how to execute an offline brute-force attack
// and how KDF (Key Derivation Functions) can slow down the hash process
#[allow(dead_code)]
pub fn run_brute_force_example() { 

    info!("-----------------------------------------------");
    info!("Example 2.1: Brute force with Sha256 and Argon2");
    info!("-----------------------------------------------");

    // The target password we're trying to crack
    let target_password = "MySuperPasswordExampleJ28hd6mpdCfaZB";

    // Step 1: Hash the target password using SHA-256
    let sha256_hash = hash_sha256(target_password);
    info!("SHA-256 Hash: {}", sha256_hash);

    // Step 2: Hash the target password using Argon2
    let argon2_hash = hash_with_argon2(target_password);
    info!("Argon2 Hash: {}", argon2_hash);

    // Step 3: Attempt brute-force attack on SHA-256 hash
    info!("\nAttempting brute-force attack on SHA-256...");
    match brute_force_sha256(&sha256_hash) {
        Some(found) => info!("Cracked SHA-256 password: {}", found),
        None => info!("Failed to crack SHA-256 password."),
    }

    // Step 4: Attempt brute-force attack on Argon2 hash
    info!("\nAttempting brute-force attack on Argon2...");
    match brute_force_argon2(&argon2_hash) {
        Some(found) => println!("Cracked Argon2 password: {}", found),
        None => println!("Failed to crack Argon2 password."),
   }
}

// Brute-force attack on SHA-256 hash
#[allow(dead_code)]
pub fn brute_force_sha256(stolen_password: &str) -> Option<String> { 
    // Create a small dictionary of potential passwords for brute-force simulation
    const PASSWORD_DICTIONARY: [&str; 5] = ["123456", "password", "qwerty", "password123", "MySuperPasswordExampleJ28hd6mpdCfaZB"];

    // Start timing the brute-force attempt
    let bf_start_time = Instant::now();
    
    // Step 1: Loop through the dictionary and hash each entry to compare with the stolen hash
    for dict_pass in PASSWORD_DICTIONARY { 
        let current_dictionary_pass_hashed = hash_sha256(dict_pass); 
        if current_dictionary_pass_hashed == stolen_password { 
            // If a match is found, return the dictionary password
            let sha256_duration = bf_start_time.elapsed();
            debug!("SHA-256 Verification took {:?}", sha256_duration);
            return Some(dict_pass.to_string());
        }
    }

    // If no match is found, return None
    let sha256_duration = bf_start_time.elapsed();
    info!("SHA-256 Verification took {:?}", sha256_duration);
    None
}

// Brute-force using Argon2
pub fn brute_force_argon2(stolen_password: &str) -> Option<String> { 
    
    // Create a small dictionary of potential passwords for brute-force simulation
    const PASSWORD_DICTIONARY: [&str; 5] = ["123456", "password", "qwerty", "password123", "MySuperPasswordExampleJ28hd6mpdCfaZB"];

    // Instantiate the Argon2 verifier
    let argon2 = Argon2::default();
    
    // Parse the stolen hash for comparison
    let stolen_password_parsed = PasswordHash::new(stolen_password).ok()?; 
    
    // Start timing the brute-force attempt
    let start_time = Instant::now();
    
    // Step 1: Loop through the dictionary and test each password against the stolen hash
    for &dict_pwd in &PASSWORD_DICTIONARY {
        if argon2.verify_password(dict_pwd.as_bytes(), &stolen_password_parsed).is_ok() {
            // If a match is found, return the dictionary password
            let argon2_duration = start_time.elapsed();
            info!("Argon2 Verification (took {:?})", argon2_duration);
            return Some(dict_pwd.to_string());
        }
    }

    // If no match is found, return None
    let argon2_duration = start_time.elapsed();
    info!("Argon2 Verification (took {:?})", argon2_duration);
    None
}


