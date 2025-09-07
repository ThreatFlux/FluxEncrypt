use fluxencrypt::keys::KeyPair;
use fluxencrypt::encryption::RsaOaepCipher;

fn main() {
    print_test_header();
    
    let (keypair1, keypair2) = generate_test_keypairs();
    let cipher = RsaOaepCipher::new();
    let secret_data = b"This is highly confidential information that must be protected!";
    
    let (ciphertext1, ciphertext2) = perform_encryption_tests(&cipher, &keypair1, secret_data);
    
    if !verify_encryption_randomness(&ciphertext1, &ciphertext2) {
        return;
    }
    
    if !verify_correct_decryption(&cipher, &keypair1, &ciphertext1, secret_data) {
        return;
    }
    
    if !verify_wrong_key_security(&cipher, &keypair2, &ciphertext1) {
        return;
    }
    
    if !test_different_key_sizes(&cipher) {
        return;
    }
    
    print_success_summary();
}

fn print_test_header() {
    println!("🔒 RSA-OAEP Security Validation Test");
    println!("====================================");
}

fn generate_test_keypairs() -> (KeyPair, KeyPair) {
    println!("1. Generating two different RSA key pairs...");
    let keypair1 = KeyPair::generate(2048).unwrap();
    let keypair2 = KeyPair::generate(2048).unwrap();
    (keypair1, keypair2)
}

fn perform_encryption_tests(cipher: &RsaOaepCipher, keypair: &KeyPair, secret_data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    println!("2. Encrypting data with first key pair...");
    let ciphertext1 = cipher.encrypt(keypair.public_key(), secret_data).unwrap();
    let ciphertext2 = cipher.encrypt(keypair.public_key(), secret_data).unwrap();
    (ciphertext1, ciphertext2)
}

fn verify_encryption_randomness(ciphertext1: &[u8], ciphertext2: &[u8]) -> bool {
    println!("3. Verifying encryption randomness...");
    if ciphertext1 != ciphertext2 {
        println!("   ✅ PASS: Same plaintext produces different ciphertexts (randomized)");
        true
    } else {
        println!("   ❌ FAIL: Encryption is deterministic (security issue!)");
        false
    }
}

fn verify_correct_decryption(cipher: &RsaOaepCipher, keypair: &KeyPair, ciphertext: &[u8], expected: &[u8]) -> bool {
    println!("4. Verifying correct decryption...");
    let decrypted = cipher.decrypt(keypair.private_key(), ciphertext).unwrap();
    if decrypted == expected {
        println!("   ✅ PASS: Decryption with correct key recovers original data");
        true
    } else {
        println!("   ❌ FAIL: Decryption failed with correct key");
        false
    }
}

fn verify_wrong_key_security(cipher: &RsaOaepCipher, wrong_keypair: &KeyPair, ciphertext: &[u8]) -> bool {
    println!("5. Verifying security against wrong private key...");
    match cipher.decrypt(wrong_keypair.private_key(), ciphertext) {
        Ok(_) => {
            println!("   ❌ FAIL: Decryption succeeded with wrong private key (security breach!)");
            false
        }
        Err(_) => {
            println!("   ✅ PASS: Decryption fails with wrong private key (secure)");
            true
        }
    }
}

fn test_different_key_sizes(cipher: &RsaOaepCipher) -> bool {
    println!("6. Testing different key sizes...");
    for key_size in [2048, 3072, 4096] {
        if !test_key_size(cipher, key_size) {
            return false;
        }
    }
    true
}

fn test_key_size(cipher: &RsaOaepCipher, key_size: u32) -> bool {
    let kp = KeyPair::generate(key_size).unwrap();
    let test_data = b"Test data for different key sizes";
    let ct = cipher.encrypt(kp.public_key(), test_data).unwrap();
    let pt = cipher.decrypt(kp.private_key(), &ct).unwrap();
    
    if pt == test_data {
        println!("   ✅ {}-bit key: OK", key_size);
        true
    } else {
        println!("   ❌ {}-bit key: FAILED", key_size);
        false
    }
}

fn print_success_summary() {
    println!("\n🎉 All RSA-OAEP security tests PASSED!");
    println!("The implementation uses proper RSA-OAEP with:");
    println!("  - SHA-256 for hashing");
    println!("  - Random padding (non-deterministic encryption)");
    println!("  - Proper key isolation (wrong keys fail)");
    println!("  - Multiple key sizes supported (2048, 3072, 4096)");
}
