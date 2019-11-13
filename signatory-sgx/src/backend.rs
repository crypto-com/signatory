use crate::error::Error;
use crate::protocol::{Decode, Encode, KeyPair, Request, Response, ENCRYPTION_REQUEST_SIZE};
use crate::seal_signer::SealedSigner;
use std::io::prelude::*;
use std::net::TcpStream;

fn handler_request(raw_data: &[u8]) -> Result<Vec<u8>, Error> {
    let request = Request::decode(raw_data)?;
    match request {
        Request::GenerateKey => {
            let sealed_privkey = SealedSigner::new()?;
            let pubkey = sealed_privkey.get_public_key()?;
            let raw_pubkey = pubkey.into_bytes().to_vec();
            let key_pair = KeyPair {
                sealed_privkey,
                pubkey: raw_pubkey,
            };
            Ok(Response::KeyPair(key_pair).encode()?)
        }
        Request::GetPublicKey(sealed_signer) => {
            let pubkey = sealed_signer.get_public_key()?;
            let raw_pubkey = pubkey.into_bytes().to_vec();
            Ok(Response::PublicKey(raw_pubkey).encode()?)
        }
        Request::Sign((sealed_signer, raw_data)) => {
            let sig = sealed_signer.try_sign(&raw_data)?;
            Ok(Response::Signed(sig.to_bytes().to_vec()).encode()?)
        }
    }
}

pub fn serve(stream: &mut TcpStream) -> Result<(), Error> {
    let mut buff = vec![0; ENCRYPTION_REQUEST_SIZE];
    let _ = stream.read(&mut buff)?;
    match handler_request(&buff) {
        Ok(data) => {
            let _ = stream.write(&data)?;
        }
        Err(e) => {
            let response = Response::Error(format!("error: {:?}", e));
            let data = response.encode()?;
            let _ = stream.write(&data)?;
        }
    };
    Ok(())
}
