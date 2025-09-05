//! Command implementations for the FluxEncrypt CLI.
//!
//! This module contains all the command implementations that can be executed
//! from the command line interface.

pub mod batch;
pub mod benchmark;
pub mod config;
pub mod decrypt;
pub mod encrypt;
pub mod info;
pub mod keygen;
pub mod stream;
pub mod verify;

/// Common result type for all commands
pub type CommandResult = anyhow::Result<()>;
