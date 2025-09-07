//! Secure key storage functionality.
//!
//! This module provides functionality for securely storing and loading
//! cryptographic keys to and from the filesystem with proper permissions
//! and optional encryption.

use crate::error::{FluxError, Result};
use crate::keys::{KeyPair, PrivateKey, PublicKey};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

/// File permissions for key files on Unix systems
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Key storage manager for secure file operations
#[derive(Debug)]
pub struct KeyStorage {
    /// Whether to encrypt private keys when storing
    encrypt_private_keys: bool,
}

/// Options for key storage operations
#[derive(Debug, Clone)]
pub struct StorageOptions {
    /// File permissions mode (Unix only)
    pub file_mode: Option<u32>,
    /// Whether to overwrite existing files
    pub overwrite: bool,
    /// Password for encrypting private keys
    pub password: Option<String>,
}

impl Default for StorageOptions {
    fn default() -> Self {
        Self {
            file_mode: Some(0o600), // Read/write for owner only
            overwrite: false,
            password: None,
        }
    }
}

impl KeyStorage {
    /// Create a new key storage manager
    pub fn new() -> Self {
        Self {
            encrypt_private_keys: false,
        }
    }

    /// Create a new key storage manager with encryption enabled
    pub fn with_encryption() -> Self {
        Self {
            encrypt_private_keys: true,
        }
    }

    /// Save a key pair to separate files
    ///
    /// # Arguments
    /// * `keypair` - The key pair to save
    /// * `public_key_path` - Path for the public key file
    /// * `private_key_path` - Path for the private key file
    /// * `options` - Storage options
    pub fn save_keypair(
        &self,
        keypair: &KeyPair,
        public_key_path: &Path,
        private_key_path: &Path,
        options: &StorageOptions,
    ) -> Result<()> {
        // Save public key
        self.save_public_key(keypair.public_key(), public_key_path, options)?;

        // Save private key
        self.save_private_key(keypair.private_key(), private_key_path, options)?;

        Ok(())
    }

    /// Save a public key to file
    ///
    /// # Arguments
    /// * `public_key` - The public key to save
    /// * `path` - The file path to save to
    /// * `options` - Storage options
    pub fn save_public_key(
        &self,
        public_key: &PublicKey,
        path: &Path,
        options: &StorageOptions,
    ) -> Result<()> {
        // Check if file exists and overwrite is not allowed
        if path.exists() && !options.overwrite {
            return Err(FluxError::invalid_input(format!(
                "File already exists: {}",
                path.display()
            )));
        }

        // Convert key to PEM format
        let pem_data = public_key.to_pem()?;

        // Write to file
        let mut file = self.create_file_with_permissions(path, options.file_mode)?;
        file.write_all(pem_data.as_bytes())?;

        log::info!("Public key saved to: {}", path.display());
        Ok(())
    }

    /// Save a private key to file
    ///
    /// # Arguments
    /// * `private_key` - The private key to save
    /// * `path` - The file path to save to
    /// * `options` - Storage options
    pub fn save_private_key(
        &self,
        private_key: &PrivateKey,
        path: &Path,
        options: &StorageOptions,
    ) -> Result<()> {
        self.check_file_overwrite_policy(path, options)?;
        let pem_data = self.generate_private_key_pem(private_key, options)?;
        self.write_private_key_file(path, &pem_data)?;
        log::info!("Private key saved to: {}", path.display());
        Ok(())
    }

    /// Check if file exists and handle overwrite policy
    fn check_file_overwrite_policy(&self, path: &Path, options: &StorageOptions) -> Result<()> {
        if path.exists() && !options.overwrite {
            return Err(FluxError::invalid_input(format!(
                "File already exists: {}",
                path.display()
            )));
        }
        Ok(())
    }

    /// Generate PEM data for private key based on encryption settings
    fn generate_private_key_pem(
        &self,
        private_key: &PrivateKey,
        options: &StorageOptions,
    ) -> Result<String> {
        if self.should_encrypt_private_key(options) {
            private_key.to_encrypted_pem(options.password.as_ref().unwrap())
        } else {
            private_key.to_pem()
        }
    }

    /// Check if private key should be encrypted
    fn should_encrypt_private_key(&self, options: &StorageOptions) -> bool {
        self.encrypt_private_keys && options.password.is_some()
    }

    /// Write private key file with restrictive permissions
    fn write_private_key_file(&self, path: &Path, pem_data: &str) -> Result<()> {
        let mut file = self.create_file_with_permissions(path, Some(0o600))?;
        file.write_all(pem_data.as_bytes())?;
        Ok(())
    }

    /// Load a public key from file
    ///
    /// # Arguments
    /// * `path` - The file path to load from
    ///
    /// # Returns
    /// The loaded public key
    pub fn load_public_key(&self, path: &Path) -> Result<PublicKey> {
        let mut file = File::open(path).map_err(|e| {
            FluxError::invalid_input(format!(
                "Cannot open public key file {}: {}",
                path.display(),
                e
            ))
        })?;

        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        // Parse the key from PEM format
        crate::keys::parsing::parse_public_key_from_str(&contents)
    }

    /// Load a private key from file
    ///
    /// # Arguments
    /// * `path` - The file path to load from
    /// * `password` - Optional password for encrypted keys
    ///
    /// # Returns
    /// The loaded private key
    pub fn load_private_key(&self, path: &Path, password: Option<&str>) -> Result<PrivateKey> {
        let mut file = File::open(path).map_err(|e| {
            FluxError::invalid_input(format!(
                "Cannot open private key file {}: {}",
                path.display(),
                e
            ))
        })?;

        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        // Check if the key is encrypted
        if contents.contains("ENCRYPTED") && password.is_none() {
            return Err(FluxError::invalid_input(
                "Private key is encrypted but no password provided",
            ));
        }

        if let Some(pwd) = password {
            // Parse encrypted private key
            crate::keys::parsing::parse_encrypted_private_key_from_str(&contents, pwd)
        } else {
            // Parse the key from PEM format
            crate::keys::parsing::parse_private_key_from_str(&contents)
        }
    }

    /// Load a key pair from separate files
    ///
    /// # Arguments
    /// * `public_key_path` - Path to the public key file
    /// * `private_key_path` - Path to the private key file
    /// * `password` - Optional password for encrypted private key
    ///
    /// # Returns
    /// The loaded key pair
    pub fn load_keypair(
        &self,
        public_key_path: &Path,
        private_key_path: &Path,
        password: Option<&str>,
    ) -> Result<KeyPair> {
        let public_key = self.load_public_key(public_key_path)?;
        let private_key = self.load_private_key(private_key_path, password)?;

        // Create a keypair from the loaded keys
        KeyPair::from_keys(public_key, private_key)
    }

    /// Create a file with specific permissions
    fn create_file_with_permissions(&self, path: &Path, mode: Option<u32>) -> Result<File> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;

        // Set file permissions on Unix systems
        #[cfg(unix)]
        if let Some(mode) = mode {
            let metadata = file.metadata()?;
            let mut permissions = metadata.permissions();
            permissions.set_mode(mode);
            std::fs::set_permissions(path, permissions)?;
        }

        Ok(file)
    }
}

impl Default for KeyStorage {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function to save a key pair to the default locations
pub fn save_keypair_default(keypair: &KeyPair, base_name: &str) -> Result<()> {
    let storage = KeyStorage::new();
    let options = StorageOptions::default();

    let public_name = format!("{}.pub", base_name);
    let private_name = format!("{}.pem", base_name);
    let public_path = Path::new(&public_name);
    let private_path = Path::new(&private_name);

    storage.save_keypair(keypair, public_path, private_path, &options)
}

/// Convenience function to load a key pair from the default locations
pub fn load_keypair_default(base_name: &str, password: Option<&str>) -> Result<KeyPair> {
    let storage = KeyStorage::new();

    let public_name = format!("{}.pub", base_name);
    let private_name = format!("{}.pem", base_name);
    let public_path = Path::new(&public_name);
    let private_path = Path::new(&private_name);

    storage.load_keypair(public_path, private_path, password)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_storage_options_default() {
        let options = StorageOptions::default();
        assert_eq!(options.file_mode, Some(0o600));
        assert!(!options.overwrite);
        assert!(options.password.is_none());
    }

    #[test]
    fn test_key_storage_creation() {
        let storage = KeyStorage::new();
        assert!(!storage.encrypt_private_keys);

        let storage = KeyStorage::with_encryption();
        assert!(storage.encrypt_private_keys);
    }

    #[test]
    fn test_save_public_key() {
        use crate::keys::KeyPair;

        let keypair = KeyPair::generate(2048).unwrap();
        let storage = KeyStorage::new();
        let options = StorageOptions::default();

        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("test_key.pub");

        let result = storage.save_public_key(keypair.public_key(), &key_path, &options);
        assert!(result.is_ok());
        assert!(key_path.exists());
    }

    #[test]
    fn test_save_and_load_public_key() {
        use crate::keys::KeyPair;

        let keypair = KeyPair::generate(2048).unwrap();
        let storage = KeyStorage::new();
        let options = StorageOptions::default();

        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("test_key.pub");

        // Save the key
        storage
            .save_public_key(keypair.public_key(), &key_path, &options)
            .unwrap();

        // Load it back
        let loaded_key = storage.load_public_key(&key_path).unwrap();

        // Check that key sizes match
        assert_eq!(
            loaded_key.key_size_bits(),
            keypair.public_key().key_size_bits()
        );
    }

    #[test]
    fn test_save_and_load_encrypted_private_key() {
        use crate::keys::KeyPair;

        let keypair = KeyPair::generate(2048).unwrap();
        let storage = KeyStorage::with_encryption();
        let password = "test_password_123".to_string();
        let options = StorageOptions {
            password: Some(password.clone()),
            ..Default::default()
        };

        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("test_encrypted_key.pem");

        // Save the encrypted key
        storage
            .save_private_key(keypair.private_key(), &key_path, &options)
            .unwrap();

        // Load it back
        let loaded_key = storage
            .load_private_key(&key_path, Some(&password))
            .unwrap();

        // Check that key components match
        assert_eq!(
            loaded_key.key_size_bits(),
            keypair.private_key().key_size_bits()
        );
        assert_eq!(loaded_key.modulus(), keypair.private_key().modulus());
    }

    #[test]
    fn test_check_file_overwrite_policy() {
        let storage = KeyStorage::new();
        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("test_overwrite.pem");

        // Test with non-existent file - should succeed
        let options = StorageOptions::default();
        assert!(storage
            .check_file_overwrite_policy(&key_path, &options)
            .is_ok());

        // Create the file first
        std::fs::write(&key_path, "test content").unwrap();

        // Test with existing file and overwrite=false - should fail
        let result = storage.check_file_overwrite_policy(&key_path, &options);
        assert!(result.is_err());

        // Test with existing file and overwrite=true - should succeed
        let options_overwrite = StorageOptions {
            overwrite: true,
            ..Default::default()
        };
        assert!(storage
            .check_file_overwrite_policy(&key_path, &options_overwrite)
            .is_ok());
    }

    #[test]
    fn test_should_encrypt_private_key() {
        let storage_no_encryption = KeyStorage::new();
        let storage_with_encryption = KeyStorage::with_encryption();

        let options_no_password = StorageOptions::default();
        let options_with_password = StorageOptions {
            password: Some("test_password".to_string()),
            ..Default::default()
        };

        // No encryption storage should never encrypt
        assert!(!storage_no_encryption.should_encrypt_private_key(&options_no_password));
        assert!(!storage_no_encryption.should_encrypt_private_key(&options_with_password));

        // Encryption storage should encrypt only when password is provided
        assert!(!storage_with_encryption.should_encrypt_private_key(&options_no_password));
        assert!(storage_with_encryption.should_encrypt_private_key(&options_with_password));
    }

    #[test]
    fn test_generate_private_key_pem() {
        use crate::keys::KeyPair;

        let keypair = KeyPair::generate(2048).unwrap();
        let storage_no_encryption = KeyStorage::new();
        let storage_with_encryption = KeyStorage::with_encryption();

        let options_no_password = StorageOptions::default();
        let options_with_password = StorageOptions {
            password: Some("test_password".to_string()),
            ..Default::default()
        };

        // Test unencrypted PEM generation
        let pem_unencrypted = storage_no_encryption
            .generate_private_key_pem(keypair.private_key(), &options_no_password)
            .unwrap();
        assert!(pem_unencrypted.starts_with("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(!pem_unencrypted.contains("ENCRYPTED"));

        // Test encrypted PEM generation
        let pem_encrypted = storage_with_encryption
            .generate_private_key_pem(keypair.private_key(), &options_with_password)
            .unwrap();
        assert!(pem_encrypted.contains("-----BEGIN"));
        assert!(pem_encrypted.contains("ENCRYPTED"));
    }
}
