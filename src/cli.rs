use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "password", about = "A simple password manager CLI")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Vault {
        #[command(subcommand)]
        command: VaultCommands,
    },
    Password {
        #[command(subcommand)]
        command: PasswordCommands,
    },
}

#[derive(Subcommand, Debug)]
pub enum VaultCommands {
    Add {
        vault_name: String,
        master_pass: String,
    },
    Remove {
        vault_name: String,
        master_pass: String,
    },
    List {
        vault_name: String,
        master_pass: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum PasswordCommands {
    Add {
        vault_name: String,
        master_pass: String,
        name: String,
        username: String,
        password: String,
    },
    Remove {
        vault_name: String,
        master_pass: String,
        name: String,
    },
}

pub fn parse_cli() -> Commands {
    Cli::parse().command
}
