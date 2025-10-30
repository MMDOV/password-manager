use crate::cli::{Commands, PasswordCommands, VaultCommands};
use crate::vault::Vault;

pub fn handle_command(command: Commands) {
    match command {
        Commands::Vault { command } => handle_vault(command),
        Commands::Password { command } => handle_password(command),
    }
}

fn handle_vault(command: VaultCommands) {
    match command {
        VaultCommands::Add {
            vault_name,
            master_pass,
        } => {
            let mut vault = Vault::new(&vault_name);
            let vault_key = vault
                .derive_vault_key(master_pass.as_ref())
                .expect("Error trying to encrypt master key");
            vault
                .encrypt_data(&vault_key, b"")
                .expect("Error encrypting data");
            vault.save_to_file().expect("Error saving to file")
        }
        VaultCommands::Remove {
            vault_name,
            master_pass,
        } => {
            println!("Vault '{}' removed", vault_name);
        }
        VaultCommands::List {
            vault_name,
            master_pass,
        } => {
            let vault = Vault::new_from_file(vault_name).expect("Error trying to load the vault");
            let vault_key = vault
                .derive_vault_key(master_pass.as_ref())
                .expect("Error trying to encrypt master key");
            let decryped_text = vault
                .decrypt_data(&vault_key)
                .expect("Error trying to open vault");

            let plane_text = String::from_utf8(decryped_text).expect("Error trying to parse text");
            println!("{}", &plane_text);
        }
    }
}

fn handle_password(command: PasswordCommands) {
    match command {
        PasswordCommands::Add {
            vault_name,
            master_pass,
            name,
            username,
            password,
        } => {
            let mut vault =
                Vault::new_from_file(vault_name).expect("Error trying to load the vault");
            let vault_key = vault
                .derive_vault_key(master_pass.as_ref())
                .expect("Error trying to encrypt master key");
            let decryped_text = vault
                .decrypt_data(&vault_key)
                .expect("Error trying to open vault");
            let plane_text = String::from_utf8(decryped_text).expect("Error trying to parse text");
            let new_text = format!("{}\r\n{name}:{username}:{password}", &plane_text);
            vault
                .encrypt_data(&vault_key, new_text.as_ref())
                .expect("Error encrypting data");
            vault.save_to_file().expect("Error saving to file")
        }
        PasswordCommands::Remove {
            vault_name,
            master_pass,
            name,
        } => {
            println!("Removed password '{}' from vault '{}'", name, vault_name);
        }
    }
}
