//! RSA key pair functionality.

use crate::error::{FluxError, Result};
use crate::keys::{PrivateKey, PublicKey};
use rsa::RsaPrivateKey;

/// An RSA key pair containing both public and private keys
#[derive(Debug)]
pub struct KeyPair {
    public_key: PublicKey,
    private_key: PrivateKey,
}

impl KeyPair {
    /// Generate a new RSA key pair
    ///
    /// # Arguments
    /// * `key_size` - The key size in bits (2048, 3072, or 4096)
    ///
    /// # Returns
    /// A new RSA key pair
    pub fn generate(key_size: usize) -> Result<Self> {
        validate_key_size(key_size)?;

        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, key_size)
            .map_err(|e| FluxError::crypto(format!("Failed to generate RSA private key: {}", e)))?;

        let public_key = private_key.to_public_key();

        Ok(Self {
            public_key: PublicKey::new(public_key),
            private_key: PrivateKey::new(private_key),
        })
    }

    /// Get the public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Get the private key
    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    /// Consume the key pair and return the individual keys
    pub fn into_keys(self) -> (PublicKey, PrivateKey) {
        (self.public_key, self.private_key)
    }

    /// Create a key pair from separate public and private keys
    pub fn from_keys(public_key: PublicKey, private_key: PrivateKey) -> Result<Self> {
        validate_key_compatibility(&public_key, &private_key)?;

        Ok(Self {
            public_key,
            private_key,
        })
    }
}

/// Validate that the key size is supported
fn validate_key_size(key_size: usize) -> Result<()> {
    match key_size {
        2048 | 3072 | 4096 => Ok(()),
        _ => Err(FluxError::invalid_input("Invalid RSA key size")),
    }
}

/// Validate that public and private keys are compatible
fn validate_key_compatibility(public_key: &PublicKey, private_key: &PrivateKey) -> Result<()> {
    if public_key.key_size_bits() != private_key.key_size_bits() {
        return Err(FluxError::key("Key sizes don't match"));
    }

    let derived_public = private_key.public_key()?;
    if public_key.modulus() != derived_public.modulus() {
        return Err(FluxError::key("Public key doesn't match private key"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_key_generation() {
        let keypair = KeyPair::generate(2048).unwrap();
        assert_eq!(keypair.public_key().key_size_bits(), 2048);
        assert_eq!(keypair.private_key().key_size_bits(), 2048);
    }

    #[test]
    fn test_invalid_key_size() {
        let invalid_sizes = vec![512, 1024, 1536, 2047, 2049, 5000];

        for size in invalid_sizes {
            let result = KeyPair::generate(size);
            assert!(result.is_err(), "Should fail for key size {}", size);

            if let Err(e) = result {
                assert!(e.to_string().contains("Invalid RSA key size"));
            }
        }
    }

    #[test]
    fn test_key_sizes() {
        for &size in &[2048, 3072, 4096] {
            let keypair = KeyPair::generate(size).unwrap();
            assert_eq!(keypair.public_key().key_size_bits(), size);
            assert_eq!(keypair.public_key().key_size_bytes(), size / 8);
            assert_eq!(keypair.private_key().key_size_bits(), size);
            assert_eq!(keypair.private_key().key_size_bytes(), size / 8);
        }
    }

    #[test]
    fn test_keypair_debug_format() {
        let keypair = KeyPair::generate(2048).unwrap();
        let debug_str = format!("{:?}", keypair);

        assert!(debug_str.contains("KeyPair"));
        assert!(debug_str.contains("public_key"));
        assert!(debug_str.contains("private_key"));
    }

    #[test]
    fn test_keypair_key_access() {
        let keypair = KeyPair::generate(2048).unwrap();

        let public_key = keypair.public_key();
        let private_key = keypair.private_key();

        assert_eq!(public_key.key_size_bits(), 2048);
        assert_eq!(private_key.key_size_bits(), 2048);
    }

    #[test]
    fn test_keypair_into_keys() {
        let keypair = KeyPair::generate(2048).unwrap();
        let original_pub_modulus = keypair.public_key().modulus();
        let original_priv_modulus = keypair.private_key().modulus();

        let (public_key, private_key) = keypair.into_keys();

        assert_eq!(public_key.modulus(), original_pub_modulus);
        assert_eq!(private_key.modulus(), original_priv_modulus);
    }

    #[test]
    fn test_keypair_from_keys() {
        let original_keypair = KeyPair::generate(2048).unwrap();
        let (public_key, private_key) = original_keypair.into_keys();

        let reconstructed_keypair = KeyPair::from_keys(public_key, private_key).unwrap();

        assert_eq!(reconstructed_keypair.public_key().key_size_bits(), 2048);
        assert_eq!(reconstructed_keypair.private_key().key_size_bits(), 2048);
    }

    #[test]
    fn test_keypair_from_keys_mismatched_sizes() {
        let keypair_2048 = KeyPair::generate(2048).unwrap();
        let keypair_3072 = KeyPair::generate(3072).unwrap();

        let (pub_2048, _) = keypair_2048.into_keys();
        let (_, priv_3072) = keypair_3072.into_keys();

        let result = KeyPair::from_keys(pub_2048, priv_3072);
        assert!(result.is_err());

        if let Err(e) = result {
            assert!(e.to_string().contains("Key sizes don't match"));
        }
    }

    #[test]
    fn test_key_generation_uniqueness() {
        let keypair1 = KeyPair::generate(2048).unwrap();
        let keypair2 = KeyPair::generate(2048).unwrap();

        assert_ne!(
            keypair1.public_key().modulus(),
            keypair2.public_key().modulus()
        );
        assert_ne!(
            keypair1.private_key().modulus(),
            keypair2.private_key().modulus()
        );
        assert_ne!(
            keypair1.private_key().private_exponent(),
            keypair2.private_key().private_exponent()
        );
    }

    #[test]
    fn test_modulus_msb_set() {
        for &key_size in &[2048, 3072, 4096] {
            let keypair = KeyPair::generate(key_size).unwrap();
            let modulus = keypair.public_key().modulus();

            assert!(
                modulus[0] & 0x80 != 0,
                "MSB should be set for {}-bit key",
                key_size
            );

            assert_eq!(modulus.len(), key_size / 8);
        }
    }

    #[test]
    fn test_error_message_quality() {
        let result = KeyPair::generate(1024);

        if let Err(e) = result {
            let error_msg = e.to_string();
            assert!(error_msg.contains("Invalid RSA key size"));
        }
    }

    #[test]
    fn test_concurrent_key_generation() {
        use std::thread;

        let mut handles = vec![];

        for i in 0..5 {
            let handle = thread::spawn(move || {
                let keypair = KeyPair::generate(2048).unwrap();
                (i, keypair.public_key().modulus().to_vec())
            });
            handles.push(handle);
        }

        let mut moduli = vec![];
        for handle in handles {
            let (thread_id, modulus) = handle.join().unwrap();
            moduli.push((thread_id, modulus));
        }

        for i in 0..moduli.len() {
            for j in (i + 1)..moduli.len() {
                assert_ne!(
                    moduli[i].1, moduli[j].1,
                    "Moduli from threads {} and {} should be different",
                    moduli[i].0, moduli[j].0
                );
            }
        }
    }

    proptest! {
        #[test]
        fn test_key_generation_properties(
            key_size in prop::sample::select(vec![2048usize, 3072, 4096])
        ) {
            let keypair = KeyPair::generate(key_size).unwrap();

            prop_assert_eq!(keypair.public_key().key_size_bits(), key_size);
            prop_assert_eq!(keypair.private_key().key_size_bits(), key_size);
            prop_assert_eq!(keypair.public_key().modulus().len(), key_size / 8);
            prop_assert_eq!(keypair.private_key().modulus().len(), key_size / 8);

            prop_assert!(keypair.public_key().modulus()[0] & 0x80 != 0);
            prop_assert!(keypair.private_key().modulus()[0] & 0x80 != 0);

            prop_assert_eq!(keypair.public_key().public_exponent(), vec![0x01, 0x00, 0x01]);
        }
    }
}
