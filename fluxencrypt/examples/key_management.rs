//! Key management example showing key generation, storage, and loading.

use fluxencrypt::keys::{
    storage::{KeyStorage, StorageOptions},
    KeyPair,
};
use tempfile::tempdir;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    println!("FluxEncrypt Key Management Example");
    println!("==================================");

    let temp_dir = tempdir()?;
    let base_path = temp_dir.path();

    // Generate and save key pair
    let keypair = KeyPair::generate(2048)?;
    let storage = KeyStorage::new();

    let public_path = base_path.join("example_key.pub");
    let private_path = base_path.join("example_key.pem");

    let options = StorageOptions {
        overwrite: true,
        ..Default::default()
    };

    storage.save_keypair(&keypair, &public_path, &private_path, &options)?;
    println!("✓ Key pair saved successfully");

    // Load keys back
    let _loaded_public = storage.load_public_key(&public_path)?;
    let _loaded_private = storage.load_private_key(&private_path, None)?;
    println!("✓ Keys loaded successfully");

    Ok(())
}
