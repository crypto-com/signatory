use crossbeam_channel::{unbounded, Receiver};
use signatory::public_key::PublicKeyed;
use signatory::signature::Signer;
use signatory_sgx::error::Error;
use signatory_sgx::protocol::{KeyType, SecretKeyEncoding};
use signatory_sgx::provider::SgxSigner;
use signatory_sgx::server::{run_server, stop_server, C2S};
use std::path::PathBuf;
use std::thread;
use std::thread::JoinHandle;
use structopt::StructOpt;
use subtle_encoding::encoding::Encoding;

#[derive(Debug, StructOpt)]
#[structopt(name = "client", about = "client for sgx server")]
pub enum CMD {
    /// create a new secret key and public key
    Keygen {
        /// set sgxs file path
        #[structopt(short, long, parse(from_os_str))]
        sgx_file: PathBuf,
        /// set secret file path
        #[structopt(short, long, parse(from_os_str))]
        key_file: PathBuf,
    },
    /// import a secret key into sgx
    Import {
        /// set sgxs file path
        #[structopt(short, long, parse(from_os_str))]
        sgx_file: PathBuf,
        /// set file path that sgx-secret key stored
        #[structopt(long, default_value = "secret_key", parse(from_os_str))]
        key_file: PathBuf,
        /// set the secret key
        #[structopt(short, long)]
        key: String,
        /// set the secret key type(base64)
        #[structopt(long, default_value = "base64")]
        key_type: String,
    },

    /// get public key of a secret key file
    Pubkey {
        /// set sgxs file path
        #[structopt(short, long, parse(from_os_str))]
        sgx_file: PathBuf,
        /// set secret file path
        #[structopt(short, long, parse(from_os_str))]
        key_file: PathBuf,
    },

    /// sign a string example
    Sign {
        /// set sgxs file path
        #[structopt(short, long, parse(from_os_str))]
        sgx_file: PathBuf,
        /// set secret file path
        #[structopt(short, long, parse(from_os_str))]
        key_file: PathBuf,
        /// sign data
        #[structopt(short, long, default_value = "hello world")]
        data: String,
    },
}

fn start_server(client2server_rx: Receiver<C2S>, sgx_file: PathBuf) -> JoinHandle<()> {
    thread::spawn(move || {
        if let Err(e) = run_server(client2server_rx, sgx_file) {
            println!("error: {:?}", e.what);
        };
    })
}

impl CMD {
    pub fn execute(&self) -> Result<(), Error> {
        let (client2server_tx, client2server_rx) = unbounded::<C2S>();
        let t = match self {
            // generate key pair
            CMD::Keygen { sgx_file, key_file } => {
                let t = start_server(client2server_rx, sgx_file.clone());
                let signer = SgxSigner::new(client2server_tx.clone(), key_file);
                let keypair = signer.keygen()?;
                let pubkey_str = signer.store_key(&keypair)?;
                println!(
                    "stored secret key in file: {:?}, the public key is: {}",
                    key_file, pubkey_str
                );
                t
            }
            // import a secret key
            CMD::Import {
                sgx_file,
                key_file,
                key,
                key_type,
            } => {
                let t = start_server(client2server_rx, sgx_file.clone());
                let signer = SgxSigner::new(client2server_tx.clone(), key_file);
                let ktype: KeyType;
                if key_type == "base64" {
                    ktype = KeyType::Base64;
                } else {
                    return Err(Error::new("error key_type"));
                }
                signer.import(ktype, key)?;
                println!("import success");
                t
            }
            // get public key from a secret file
            CMD::Publickey { sgx_file, key_file } => {
                let t = start_server(client2server_rx, sgx_file.clone());
                let signer = SgxSigner::new(client2server_tx.clone(), key_file);
                let pubkey = signer.public_key().unwrap();
                let encoder = SecretKeyEncoding::default();
                let pubkey_str = encoder.encode_to_string(pubkey.as_bytes()).unwrap();
                println!("public key: {}", pubkey_str);
                t
            }
            // sign a string
            CMD::Sign {
                sgx_file,
                key_file,
                data,
            } => {
                let t = start_server(client2server_rx, sgx_file.clone());
                let signer = SgxSigner::new(client2server_tx.clone(), key_file);
                let data_raw: Vec<u8> = data.clone().into_bytes();
                let signed_result = signer.try_sign(&data_raw).unwrap();
                println!("signed result: {:?}", signed_result);
                t
            }
        };
        stop_server(client2server_tx);
        let _ = t.join().unwrap();
        Ok(())
    }
}

fn main() {
    env_logger::init();
    let cmd = CMD::from_args();
    if let Err(e) = cmd.execute() {
        println!("error: {}", e.what);
    };
}
