use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, AeadCore, KeyInit},
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand::rand_core::{OsRng, TryRngCore};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{self, prelude::*};

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Serde JSON error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("Argon2 error: {0}")]
    Argon2(String),

    #[error("AEAD encryption/decryption error")]
    Aead,
}
impl From<argon2::Error> for VaultError {
    fn from(e: argon2::Error) -> Self {
        VaultError::Argon2(e.to_string())
    }
}

impl From<aes_gcm::aead::Error> for VaultError {
    fn from(_: aes_gcm::aead::Error) -> Self {
        VaultError::Aead
    }
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

    pub fn new_from_file(file_name: String) -> Result<Vault, VaultError> {
        let file = File::open(file_name)?;
        let vault: Vault = serde_json::from_reader(file)?;
        Ok(vault)
    }

    pub fn derive_vault_key(&self, master_password: &[u8]) -> Result<[u8; 32], VaultError> {
        let argon2_params = &self.argon2;
        let params = Params::new(
            argon2_params.mem_cost,
            argon2_params.time_cost,
            argon2_params.parallelism,
            Some(32),
        )?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut output_key = [0u8; 32];
        argon2.hash_password_into(
            master_password,
            &STANDARD.decode(&argon2_params.salt)?,
            &mut output_key,
        )?;

        Ok(output_key)
    }

    pub fn encrypt_data(&mut self, vault_key: &[u8], plaintext: &[u8]) -> Result<(), VaultError> {
        let cipher = Aes256Gcm::new(vault_key.into());
        let nonce = Aes256Gcm::generate_nonce(&mut aes_gcm::aead::OsRng);

        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref())?;

        self.encryption.nonce = STANDARD.encode(nonce);
        self.encryption.ciphertext = STANDARD.encode(ciphertext);
        Ok(())
    }

    pub fn decrypt_data(&self, vault_key: &[u8]) -> Result<Vec<u8>, VaultError> {
        let cipher = Aes256Gcm::new(vault_key.into());
        let nonce = STANDARD.decode(&self.encryption.nonce)?;
        let ciphertext = STANDARD.decode(&self.encryption.ciphertext)?;
        let decrypted_text = cipher.decrypt(nonce.as_slice().into(), ciphertext.as_ref())?;

        Ok(decrypted_text)
    }

    pub fn save_to_file(&self) -> Result<(), VaultError> {
        let json = serde_json::to_string_pretty(&self)?;

        println!("{json}");
        let file_name = format!("{}.vault", self.name.as_str());

        let mut file = File::create(file_name)?;

        file.write_all(json.as_ref())?;

        Ok(())
    }
}
