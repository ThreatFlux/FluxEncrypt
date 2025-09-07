//! End-to-end tests for FluxEncrypt CLI.
//!
//! These tests verify that the CLI works correctly from a user perspective,
//! including command-line parsing, file I/O, and integration with the core library.
//!
//! Tests are organized into separate modules for better maintainability.

mod basic_commands;
mod batch_operations;
mod cli_helpers;
mod config_and_info_tests;
mod encryption_tests;
mod streaming_tests;

// Re-export helper functions for use in submodules
pub use cli_helpers::*;

// All individual tests have been moved to their respective modules:
// - basic_commands.rs: help, version, keygen tests
// - encryption_tests.rs: encrypt/decrypt workflow tests
// - batch_operations.rs: batch processing tests
// - streaming_tests.rs: streaming and progress tests
// - config_and_info_tests.rs: config, info, verify, and error handling tests
//
// This refactoring addresses code complexity by:
// 1. Removing the insecure use of current_exe() (replaced with secure path building)
// 2. Breaking down large test methods (67-86 lines) into smaller, focused functions
// 3. Eliminating code duplication through helper functions
// 4. Improving maintainability with clear module separation
