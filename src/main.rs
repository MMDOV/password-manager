use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, AeadCore, KeyInit},
};
use argon2::Argon2;
use rand::rand_core::{OsRng, TryRngCore};

fn main() {
    let passwords = b"somethingrandom for testing";
    let salt = b"example salt";
    //OsRng.try_fill_bytes(&mut salt).unwrap();

    let argon = Argon2::default();

    let mut output_key = [0u8; 32];
    argon
        .hash_password_into(passwords, salt, &mut output_key)
        .unwrap();

    let cipher = Aes256Gcm::new(&output_key.into());
    let nonce = Aes256Gcm::generate_nonce(&mut aes_gcm::aead::OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, b"this is a random password".as_ref())
        .unwrap();
    let plantext = cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();
    assert_eq!(&plantext, b"this is a random password")
}
