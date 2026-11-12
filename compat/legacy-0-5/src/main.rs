//! Preserve persisted SymmetricCipher secrets across the 0.5 to 0.8 migration.
//!
//! The golden value is independently generated AES-256-GCM with nonce
//! 000102030405060708090a0b, then encoded as the published 0.5 wire layout:
//! base64(nonce || ciphertext || tag). Both implementations must decode these
//! fixed bytes, so a new-version roundtrip cannot hide a format regression.

fn main() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../fixture.json")).expect("fixed compatibility fixture");
    let key = fixture["key_hex"].as_str().expect("fixture key");
    let plaintext = fixture["plaintext"].as_str().expect("fixture plaintext");
    let ciphertext = fixture["ciphertext"].as_str().expect("fixture ciphertext");

    let legacy = fluxencrypt_legacy::symmetric::SymmetricCipher::new(key).expect("legacy cipher");
    let current =
        fluxencrypt_current::symmetric::SymmetricCipher::new(key).expect("current cipher");
    assert_eq!(
        legacy.decrypt(ciphertext).expect("0.5 golden decryption"),
        plaintext
    );
    assert_eq!(
        current
            .decrypt(ciphertext)
            .expect("current golden decryption"),
        plaintext
    );

    let old_ciphertext = legacy.encrypt(plaintext).expect("legacy encryption");
    assert_eq!(
        current.decrypt(&old_ciphertext).expect("stored 0.5 secret"),
        plaintext
    );
    let new_ciphertext = current.encrypt(plaintext).expect("current encryption");
    assert_eq!(
        legacy
            .decrypt(&new_ciphertext)
            .expect("rollback interoperability"),
        plaintext
    );
    println!("Fixed legacy ciphertext and bidirectional 0.5 secret compatibility passed");
}
