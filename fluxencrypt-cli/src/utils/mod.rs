//! Utility functions for CLI operations.

use crate::commands::CommandResult;
use dialoguer::Confirm;
use std::path::Path;

/// Confirm overwriting an existing file
pub fn confirm_overwrite(path: &Path) -> anyhow::Result<bool> {
    let result = Confirm::new()
        .with_prompt(format!(
            "File '{}' already exists. Overwrite?",
            path.display()
        ))
        .default(false)
        .interact()?;
    Ok(result)
}

/// Create output directory if it doesn't exist
pub fn create_output_directory(path: &Path) -> CommandResult {
    if !path.exists() {
        std::fs::create_dir_all(path)?;
    }
    Ok(())
}
