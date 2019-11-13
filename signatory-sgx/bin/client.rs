extern crate log;
extern crate signatory_sgx;
use signatory_sgx::provider::create_keypair;
use std::net::TcpStream;



fn main() {
    let mut stream = match TcpStream::connect("localhost:8888") {
        Ok(s) => { s },
        Err(e) => {
            println!("error to connect server: {:?}", e);
            return
        }
    };

    let secret_key_path = "secret_key";
    let public_key_path = "publick_key";

    if let Err(e) = create_keypair(&mut stream, secret_key_path, public_key_path) {
        println!("create keypair failed with error: {}", e);
    } else {
        println!("create keypaie success, secret key: {}, public key: {}", secret_key_path, public_key_path);
    }
}
