//! Stream command implementations.

use crate::commands::CommandResult;
use clap::Args;

#[derive(Args)]
pub struct StreamEncryptCommand {
    #[arg(short, long)]
    input: String,
}

#[derive(Args)]
pub struct StreamDecryptCommand {
    #[arg(short, long)]
    input: String,
}

pub fn execute_encrypt(_cmd: StreamEncryptCommand) -> CommandResult {
    println!("Stream encrypt command - TODO: Implement");
    Ok(())
}

pub fn execute_decrypt(_cmd: StreamDecryptCommand) -> CommandResult {
    println!("Stream decrypt command - TODO: Implement");
    Ok(())
}
