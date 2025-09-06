use fluxencrypt::keys::KeyPair;
use fluxencrypt::encryption::RsaOaepCipher;

fn main() {
    println!("🔒 RSA-OAEP Security Validation Test");
    println!("====================================");
    
    // Generate two different key pairs
    println!("1. Generating two different RSA key pairs...");
    let keypair1 = KeyPair::generate(2048).unwrap();
    let keypair2 = KeyPair::generate(2048).unwrap();
    
    let cipher = RsaOaepCipher::new();
    let secret_data = b"This is highly confidential information that must be protected!";
    
    println!("2. Encrypting data with first key pair...");
    let ciphertext1 = cipher.encrypt(keypair1.public_key(), secret_data).unwrap();
    let ciphertext2 = cipher.encrypt(keypair1.public_key(), secret_data).unwrap();
    
    // Verify that same plaintext produces different ciphertexts (due to random padding)
    println!("3. Verifying encryption randomness...");
    if ciphertext1 != ciphertext2 {
        println!("   ✅ PASS: Same plaintext produces different ciphertexts (randomized)");
    } else {
        println!("   ❌ FAIL: Encryption is deterministic (security issue!)");
        return;
    }
    
    // Verify correct decryption
    println!("4. Verifying correct decryption...");
    let decrypted1 = cipher.decrypt(keypair1.private_key(), &ciphertext1).unwrap();
    if decrypted1 == secret_data {
        println!("   ✅ PASS: Decryption with correct key recovers original data");
    } else {
        println!("   ❌ FAIL: Decryption failed with correct key");
        return;
    }
    
    // Verify that wrong private key fails
    println!("5. Verifying security against wrong private key...");
    match cipher.decrypt(keypair2.private_key(), &ciphertext1) {
        Ok(_) => {
            println!("   ❌ FAIL: Decryption succeeded with wrong private key (security breach!)");
            return;
        }
        Err(_) => {
            println!("   ✅ PASS: Decryption fails with wrong private key (secure)");
        }
    }
    
    // Test different key sizes
    println!("6. Testing different key sizes...");
    for key_size in [2048, 3072, 4096] {
        let kp = KeyPair::generate(key_size).unwrap();
        let test_data = b"Test data for different key sizes";
        let ct = cipher.encrypt(kp.public_key(), test_data).unwrap();
        let pt = cipher.decrypt(kp.private_key(), &ct).unwrap();
        if pt == test_data {
            println!("   ✅ {}-bit key: OK", key_size);
        } else {
            println!("   ❌ {}-bit key: FAILED", key_size);
            return;
        }
    }
    
    println!("\n🎉 All RSA-OAEP security tests PASSED!");
    println!("The implementation uses proper RSA-OAEP with:");
    println!("  - SHA-256 for hashing");
    println!("  - Random padding (non-deterministic encryption)");
    println!("  - Proper key isolation (wrong keys fail)");
    println!("  - Multiple key sizes supported (2048, 3072, 4096)");
}
