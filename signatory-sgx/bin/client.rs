extern crate signatory_sgx;
use log::{error, info};
use signatory_sgx::provider::create_keypair;
use std::net::TcpStream;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
name = "client",
about = "client for sgx server"
)]
pub enum CMD {
    /// create a new secret key and public key
    Keypair {
        /// set file path that secret key stored
        #[structopt(short, long, default_value = "secret_key", parse(from_os_str))]
        secret_file: PathBuf,

        /// set file path that public key stored
        #[structopt(short, long, default_value = "public_key", parse(from_os_str))]
        public_file: PathBuf,
    },

    /// get public key of a secret key file
    Publickey {
        /// secret key file path
        #[structopt(short, long, default_value = "secret_key", parse(from_os_str))]
        secret_file: PathBuf,
    },
}

impl CMD {
    pub fn execute(&self) {
       match self {
           CMD::Keypair {
               secret_file: secret_key_path,
               public_file: public_key_path,
           } => {
               let mut stream = match TcpStream::connect("localhost:8888") {
                   Ok(s) => s,
                   Err(e) => {
                       error!("error to connect server: {:?}", e);
                       return;
                   }
               };
               if let Err(e) = create_keypair(&mut stream, secret_key_path, public_key_path) {
                   error!("create keypair failed with error: {}", e);
               } else {
                   info!(
                       "create keypair success, secret key: {:?}, public key: {:?}",
                       secret_key_path, public_key_path
                   );
               }
           },
           CMD::Publickey { secret_file: secret_file_path } => {
               println!("TODO: will to get public key for secret file {:?}", secret_file_path);
           }
       }
    }
}

fn main() {
    env_logger::init();
    let cmd = CMD::from_args();
    cmd.execute()
}
