use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, AeadCore, KeyInit},
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand::rand_core::{OsRng, TryRngCore};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::prelude::*;

// NOTE: take a master password and create a vault with that password
// that vault is a file inside that file theres our salt, nonce and the ciphered text
// all the new passwords are being added to that vault
// TODO: needs some sort of ui
// TODO: needs the ability to generate strong passwords for user to use
// TODO: still need to do the main loop what we have does nothing basically
// TODO: add more todos
// FIX: add error handling everyting is panicking right now
fn main() {
    let password = b"somethingrandom for testing";
    let mut vault = Vault::new("mamad");
    let vault_key = vault.derive_vault_key(password);

    vault.encrypt_data(&vault_key, b"some random text");
    let plaintext = vault.decrypt_data(&vault_key);
    vault.save_to_file();

    assert_eq!(&plaintext, b"some random text")
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Argon2Params {
    salt: String,
    mem_cost: u32,
    time_cost: u32,
    parallelism: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        let mut salt = [0u8; 32];
        OsRng.try_fill_bytes(&mut salt).unwrap();
        Self {
            salt: STANDARD.encode(salt),
            mem_cost: 19 * 1024,
            time_cost: 2,
            parallelism: 1,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct EncryptionData {
    nonce: String,
    ciphertext: String,
}

impl Default for EncryptionData {
    fn default() -> Self {
        Self {
            nonce: String::new(),
            ciphertext: String::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Vault {
    name: String,
    version: u8,
    argon2: Argon2Params,
    encryption: EncryptionData,
}

impl Vault {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            version: 1,
            argon2: Argon2Params::default(),
            encryption: EncryptionData::default(),
        }
    }

    pub fn new_from_file(file_name: String) -> Vault {
        let file = File::open(file_name).unwrap();
        let vault: Vault = serde_json::from_reader(file).unwrap();
        vault
    }

    pub fn derive_vault_key(&self, master_password: &[u8]) -> [u8; 32] {
        let argon2_params = &self.argon2;
        let params = Params::new(
            argon2_params.mem_cost,
            argon2_params.time_cost,
            argon2_params.parallelism,
            Some(32),
        )
        .unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut output_key = [0u8; 32];
        argon2
            .hash_password_into(
                master_password,
                &STANDARD.decode(&argon2_params.salt).unwrap(),
                &mut output_key,
            )
            .unwrap();

        output_key
    }

    pub fn encrypt_data(&mut self, vault_key: &[u8], plaintext: &[u8]) {
        let cipher = Aes256Gcm::new(vault_key.into());
        let nonce = Aes256Gcm::generate_nonce(&mut aes_gcm::aead::OsRng);

        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).unwrap();

        self.encryption.nonce = STANDARD.encode(nonce);
        self.encryption.ciphertext = STANDARD.encode(ciphertext);
    }

    pub fn decrypt_data(&self, vault_key: &[u8]) -> Vec<u8> {
        let cipher = Aes256Gcm::new(vault_key.into());
        let nonce = STANDARD.decode(&self.encryption.nonce).unwrap();
        let ciphertext = STANDARD.decode(&self.encryption.ciphertext).unwrap();
        cipher
            .decrypt(nonce.as_slice().into(), ciphertext.as_ref())
            .unwrap()
    }

    pub fn save_to_file(&self) {
        let json = serde_json::to_string_pretty(&self).unwrap();

        println!("{json}");
        let file_name = format!("{}.vault", self.name.as_str());

        let mut file = File::create(file_name).unwrap();

        file.write_all(json.as_ref()).unwrap();
    }
}
