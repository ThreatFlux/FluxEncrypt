//! Environment configuration example.

use fluxencrypt::env::EnvSecretProvider;
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    println!("FluxEncrypt Environment Configuration Example");
    println!("============================================");

    // Set up example environment variables
    env::set_var("FLUX_PUBLIC_KEY", "example-public-key-data");
    env::set_var("FLUX_PRIVATE_KEY", "example-private-key-data");

    let provider = EnvSecretProvider::with_prefix("FLUX");

    if let Some(public_data) = provider.get_optional_string("PUBLIC_KEY") {
        println!("✓ Found public key in environment: {}", public_data);
    }

    if let Some(private_data) = provider.get_optional_string("PRIVATE_KEY") {
        println!("✓ Found private key in environment: {}", private_data);
    }

    // Clean up
    env::remove_var("FLUX_PUBLIC_KEY");
    env::remove_var("FLUX_PRIVATE_KEY");

    Ok(())
}
