//! Environment secret provider implementation.
//!
//! This module provides functionality to load cryptographic keys and secrets
//! from environment variables with automatic format detection and validation.

use crate::env::secrets::{EnvSecret, SecretFormat};
use crate::error::{FluxError, Result};
use crate::keys::{PrivateKey, PublicKey};
use std::env;

/// Environment secret provider for loading keys from environment variables
#[derive(Debug, Default)]
pub struct EnvSecretProvider {
    /// Prefix for environment variable names
    prefix: Option<String>,
    /// Whether to require all secrets to exist
    strict_mode: bool,
}

impl EnvSecretProvider {
    /// Create a new environment secret provider
    pub fn new() -> Self {
        Self {
            prefix: None,
            strict_mode: false,
        }
    }

    /// Create a new environment secret provider with a variable name prefix
    ///
    /// # Arguments
    /// * `prefix` - The prefix to use for environment variable names
    pub fn with_prefix(prefix: impl Into<String>) -> Self {
        Self {
            prefix: Some(prefix.into()),
            strict_mode: false,
        }
    }

    /// Enable strict mode (all requested secrets must exist)
    pub fn strict(mut self) -> Self {
        self.strict_mode = true;
        self
    }

    /// Get a public key from an environment variable
    ///
    /// # Arguments
    /// * `var_name` - The environment variable name
    ///
    /// # Returns
    /// The public key loaded from the environment
    pub fn get_public_key(&self, var_name: &str) -> Result<PublicKey> {
        let secret = self.get_secret(var_name)?;
        secret.as_public_key()
    }

    /// Get a private key from an environment variable
    ///
    /// # Arguments
    /// * `var_name` - The environment variable name
    ///
    /// # Returns
    /// The private key loaded from the environment
    pub fn get_private_key(&self, var_name: &str) -> Result<PrivateKey> {
        let secret = self.get_secret(var_name)?;
        secret.as_private_key()
    }

    /// Get a secret string from an environment variable
    ///
    /// # Arguments
    /// * `var_name` - The environment variable name
    ///
    /// # Returns
    /// The secret string
    pub fn get_string(&self, var_name: &str) -> Result<String> {
        let full_name = self.build_var_name(var_name);

        env::var(&full_name).map_err(|_| {
            if self.strict_mode {
                FluxError::env(format!(
                    "Required environment variable not found: {}",
                    full_name
                ))
            } else {
                FluxError::env(format!("Environment variable not found: {}", full_name))
            }
        })
    }

    /// Get a secret from an environment variable with automatic format detection
    ///
    /// # Arguments
    /// * `var_name` - The environment variable name
    ///
    /// # Returns
    /// The parsed secret
    pub fn get_secret(&self, var_name: &str) -> Result<EnvSecret> {
        let value = self.get_string(var_name)?;
        EnvSecret::from_string(value)
    }

    /// Get a secret with a specific format
    ///
    /// # Arguments
    /// * `var_name` - The environment variable name
    /// * `format` - The expected format of the secret
    ///
    /// # Returns
    /// The parsed secret
    pub fn get_secret_with_format(
        &self,
        var_name: &str,
        format: SecretFormat,
    ) -> Result<EnvSecret> {
        let value = self.get_string(var_name)?;
        EnvSecret::from_string_with_format(value, format)
    }

    /// Check if an environment variable exists
    ///
    /// # Arguments
    /// * `var_name` - The environment variable name
    ///
    /// # Returns
    /// `true` if the variable exists, `false` otherwise
    pub fn has_var(&self, var_name: &str) -> bool {
        let full_name = self.build_var_name(var_name);
        env::var(&full_name).is_ok()
    }

    /// Get an optional secret (returns None if not found)
    ///
    /// # Arguments
    /// * `var_name` - The environment variable name
    ///
    /// # Returns
    /// The secret if found, None otherwise
    pub fn get_optional_secret(&self, var_name: &str) -> Option<EnvSecret> {
        self.get_secret(var_name).ok()
    }

    /// Get an optional string (returns None if not found)
    ///
    /// # Arguments
    /// * `var_name` - The environment variable name
    ///
    /// # Returns
    /// The string if found, None otherwise
    pub fn get_optional_string(&self, var_name: &str) -> Option<String> {
        self.get_string(var_name).ok()
    }

    /// Load multiple secrets at once
    ///
    /// # Arguments
    /// * `var_names` - A slice of environment variable names
    ///
    /// # Returns
    /// A vector of results for each variable
    pub fn get_multiple_secrets(&self, var_names: &[&str]) -> Vec<Result<EnvSecret>> {
        var_names
            .iter()
            .map(|&name| self.get_secret(name))
            .collect()
    }

    /// Build the full environment variable name with prefix
    fn build_var_name(&self, var_name: &str) -> String {
        match &self.prefix {
            Some(prefix) => format!("{}_{}", prefix, var_name),
            None => var_name.to_string(),
        }
    }

    /// List all environment variables that match the prefix
    pub fn list_matching_vars(&self) -> Vec<String> {
        let prefix = match &self.prefix {
            Some(p) => format!("{}_", p),
            None => String::new(),
        };

        env::vars()
            .filter_map(|(key, _)| {
                if key.starts_with(&prefix) {
                    Some(key)
                } else {
                    None
                }
            })
            .collect()
    }
}

/// Builder for creating environment secret providers with custom configuration
#[derive(Debug, Default)]
pub struct EnvSecretProviderBuilder {
    prefix: Option<String>,
    strict_mode: bool,
}

impl EnvSecretProviderBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the environment variable prefix
    pub fn prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    /// Enable strict mode
    pub fn strict(mut self) -> Self {
        self.strict_mode = true;
        self
    }

    /// Build the provider
    pub fn build(self) -> EnvSecretProvider {
        EnvSecretProvider {
            prefix: self.prefix,
            strict_mode: self.strict_mode,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_provider_creation() {
        let provider = EnvSecretProvider::new();
        assert!(provider.prefix.is_none());
        assert!(!provider.strict_mode);

        let provider = EnvSecretProvider::with_prefix("FLUX");
        assert_eq!(provider.prefix, Some("FLUX".to_string()));

        let provider = EnvSecretProvider::new().strict();
        assert!(provider.strict_mode);
    }

    #[test]
    fn test_var_name_building() {
        let provider = EnvSecretProvider::new();
        assert_eq!(provider.build_var_name("TEST"), "TEST");

        let provider = EnvSecretProvider::with_prefix("FLUX");
        assert_eq!(provider.build_var_name("TEST"), "FLUX_TEST");
    }

    #[test]
    fn test_has_var() {
        env::set_var("TEST_VAR_EXISTS", "value");

        let provider = EnvSecretProvider::new();
        assert!(provider.has_var("TEST_VAR_EXISTS"));
        assert!(!provider.has_var("TEST_VAR_DOES_NOT_EXIST"));

        env::remove_var("TEST_VAR_EXISTS");
    }

    #[test]
    fn test_get_string() {
        env::set_var("TEST_STRING", "hello world");

        let provider = EnvSecretProvider::new();
        let result = provider.get_string("TEST_STRING").unwrap();
        assert_eq!(result, "hello world");

        let result = provider.get_string("NONEXISTENT");
        assert!(result.is_err());

        env::remove_var("TEST_STRING");
    }

    #[test]
    fn test_optional_methods() {
        env::set_var("TEST_OPTIONAL", "value");

        let provider = EnvSecretProvider::new();

        let result = provider.get_optional_string("TEST_OPTIONAL");
        assert_eq!(result, Some("value".to_string()));

        let result = provider.get_optional_string("NONEXISTENT");
        assert_eq!(result, None);

        env::remove_var("TEST_OPTIONAL");
    }

    #[test]
    fn test_builder() {
        let provider = EnvSecretProviderBuilder::new()
            .prefix("FLUX")
            .strict()
            .build();

        assert_eq!(provider.prefix, Some("FLUX".to_string()));
        assert!(provider.strict_mode);
    }
}
