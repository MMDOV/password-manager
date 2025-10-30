mod cli;
mod handlers;
mod vault;
use passwords::PasswordGenerator;
use vault::Vault;

// NOTE: take a master password and create a vault with that password
// that vault is a file inside that file theres our salt, nonce and the ciphered text
// all the new passwords are being added to that vault
// TODO: needs some sort of ui
// TODO: needs the ability to generate strong passwords for user to use
// TODO: still need to do the main loop what we have does nothing basically
// TODO: add more todos
// FIX: add error handling everyting is panicking right now
fn main() {
    let command = cli::parse_cli();
    handlers::handle_command(command);

    //let pg = PasswordGenerator {
    //    length: 15,
    //    numbers: true,
    //    lowercase_letters: true,
    //    uppercase_letters: true,
    //    symbols: true,
    //    spaces: false,
    //    exclude_similar_characters: false,
    //    strict: true,
    //};
    //let password = pg.generate_one().unwrap();
    //println!("{password}");
    //let mut vault = Vault::new("mamad");
    //let vault_key = vault.derive_vault_key(password.as_ref()).unwrap();

    //vault
    //    .encrypt_data(&vault_key, b"some random text")
    //    .expect("");
    //let plaintext = vault.decrypt_data(&vault_key).unwrap();
    //vault.save_to_file().unwrap();

    //assert_eq!(&plaintext, b"some random text");
}
