use crate::error::Error;
use crate::protocol::{Decode, Encode, KeyPair, Request, Response, get_data_from_stream};
use crate::seal_signer::SealedSigner;
use log::{debug, info};
use std::io::prelude::*;
use std::net::TcpStream;

fn handle_request(raw_data: &[u8]) -> Result<Response, Error> {
    debug!("handle raw data: {:?}", raw_data);
    let request =
        Request::decode(raw_data).map_err(|e| Error::new(format!("invalid request: {:?}", e)))?;
    match request {
        Request::Ping => {
            info!("get ping, return pong");
            Ok(Response::Pong)
        }
        Request::GenerateKey => {
            info!("generate keypair");
            let sealed_privkey = SealedSigner::new()?;
            debug!("sealed signer: {:?}", sealed_privkey);
            let pubkey = sealed_privkey.get_public_key()?;
            let raw_pubkey = pubkey.into_bytes().to_vec();
            let key_pair = KeyPair {
                sealed_privkey,
                pubkey: raw_pubkey,
            };
            Ok(Response::KeyPair(key_pair))
        }
        Request::Import(raw_key_pair) => {
            info!("import key");
            let sealed_privkey = SealedSigner::import(raw_key_pair)?;
            debug!("sealed signer: {:?}", sealed_privkey);
            let pubkey = sealed_privkey.get_public_key()?;
            let raw_pubkey = pubkey.into_bytes().to_vec();
            let key_pair = KeyPair {
                sealed_privkey,
                pubkey: raw_pubkey,
            };
            Ok(Response::KeyPair(key_pair))
        }
        Request::GetPublicKey(sealed_signer) => {
            info!("get public key");
            debug!("get sealed signer: {:?}", sealed_signer);
            let pubkey = sealed_signer.get_public_key()?;
            let raw_pubkey = pubkey.into_bytes().to_vec();
            Ok(Response::PublicKey(raw_pubkey))
        }
        Request::Sign((sealed_signer, raw_data)) => {
            info!("sign data");
            let sig = sealed_signer.try_sign(&raw_data)?;
            Ok(Response::Signed(sig))
        }
    }
}

pub fn serve(stream: &mut TcpStream) -> Result<(), Error> {
    let request_raw_data = get_data_from_stream(stream)?;
    let response = handle_request(&request_raw_data)?;
    debug!("send response to client: {:?}", response);
    let response_raw_data = response.encode()?;
    let _ = stream.write(&response_raw_data)?;
    Ok(())
}
