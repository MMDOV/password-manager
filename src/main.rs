mod cli;
mod handlers;
mod tui;
mod vault;

// NOTE: take a master password and create a vault with that password
// that vault is a file inside that file theres our salt, nonce and the ciphered text
// all the new passwords are being added to that vault
// TODO: needs some sort of ui
// TODO: add more todos
// FIX: add error handling everyting is panicking right now
fn main() {
    let commands = cli::parse_cli();
    handlers::handle_command(commands);
}
