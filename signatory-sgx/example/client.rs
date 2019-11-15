extern crate signatory_sgx;
use log::error;
use signatory::public_key::PublicKeyed;
use signatory::signature::Signer;
use signatory_sgx::error::Error;
use signatory_sgx::provider::SgxSigner;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "client", about = "client for sgx server")]
pub enum CMD {
    /// create a new secret key and public key
    Keypair {
        /// set file path that secret key stored
        #[structopt(short, long, default_value = "secret_key", parse(from_os_str))]
        secret_file: PathBuf,

        /// set server address
        #[structopt(short, long, default_value = "127.0.0.1:8888")]
        addr: String,
    },

    /// get public key of a secret key file
    Publickey {
        /// secret key file path
        #[structopt(short, long, default_value = "secret_key", parse(from_os_str))]
        secret_file: PathBuf,
        /// set server address
        #[structopt(short, long, default_value = "127.0.0.1:8888")]
        addr: String,
    },

    /// sign a string example
    Sign {
        /// secret key file path
        #[structopt(short, long, default_value = "secret_key", parse(from_os_str))]
        secret_file: PathBuf,
        /// set server address
        #[structopt(short, long, default_value = "127.0.0.1:8888")]
        addr: String,
        /// sign data
        #[structopt(short, long, default_value = "hello world")]
        data: String,
    },
}

impl CMD {
    pub fn execute(&self) -> Result<(), Error> {
        match self {
            // generate key pair
            CMD::Keypair { secret_file, addr } => {
                let signer = SgxSigner::new(addr, secret_file);
                signer.create_keypair()?;
                Ok(())
            }
            // get public key from a secret file
            CMD::Publickey { secret_file, addr } => {
                let signer = SgxSigner::new(addr, secret_file);
                let pubkey = signer.public_key().unwrap();
                let pubkey_str = hex::encode(pubkey.as_bytes());
                println!("public key: {}\n", pubkey_str);
                Ok(())
            }
            // sign a string
            CMD::Sign {
                secret_file,
                addr,
                data,
            } => {
                let signer = SgxSigner::new(addr, secret_file);
                let data_raw: Vec<u8> = data.clone().into_bytes();
                let signed_result = signer.try_sign(&data_raw).unwrap();
                println!("signed result: {:?}", signed_result);
                Ok(())
            }
        }
    }
}

fn main() {
    env_logger::init();
    let cmd = CMD::from_args();
    if let Err(e) = cmd.execute() {
        error!("{}", e);
    }
}
