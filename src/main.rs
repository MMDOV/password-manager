use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, AeadCore, KeyInit},
};
use argon2::Argon2;
use rand::rand_core::{OsRng, TryRngCore};

// NOTE: take a master password and create a vault with that password
// that vault is a file inside that file theres our salt, nonce and the ciphered text
// all the new passwords are being added to that vault
// TODO: needs some sort of ui
// TODO: needs the ability to generate strong passwords for user to use
// TODO: still need to do the main loop what we have does nothing basically
// TODO: add more todos
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
