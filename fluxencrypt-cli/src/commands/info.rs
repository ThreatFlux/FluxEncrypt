//! Info command implementation.

use crate::commands::CommandResult;
use clap::Args;

#[derive(Args)]
pub struct InfoCommand {
    #[arg(short, long)]
    file: String,
}

pub fn execute(_cmd: InfoCommand) -> CommandResult {
    println!("Info command - TODO: Implement");
    Ok(())
}
