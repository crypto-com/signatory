mod logger;
extern crate log;
extern crate signatory_sgx;
use log::{error, info};
use signatory_sgx::provider::create_keypair;
use std::net::TcpStream;

fn main() {
    let _ = logger::init();
    let mut stream = match TcpStream::connect("localhost:8888") {
        Ok(s) => s,
        Err(e) => {
            error!("error to connect server: {:?}", e);
            return;
        }
    };

    let secret_key_path = "secret_key";
    let public_key_path = "publick_key";

    if let Err(e) = create_keypair(&mut stream, secret_key_path, public_key_path) {
        error!("create keypair failed with error: {}", e);
    } else {
        info!(
            "create keypair success, secret key: {}, public key: {}",
            secret_key_path, public_key_path
        );
    }
}
