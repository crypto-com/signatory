use crate::error::Error;
use crate::protocol::{Decode, Encode, KeyPair, Request, Response, ENCRYPTION_REQUEST_SIZE};
use crate::seal_signer::SealedSigner;
use log::debug;
use std::fs::File;
use std::io::prelude::*;
use std::net::TcpStream;
use std::path::Path;

pub fn send(stream: &mut TcpStream, request: Request) -> Result<Response, Error> {
    debug!("send request {:?}", request);
    let request_rawdata = request.encode()?;
    let _ = stream.write(&request_rawdata)?;
    let mut data = [0_u8; ENCRYPTION_REQUEST_SIZE];
    let _ = stream.read(&mut data)?;
    debug!("get raw data: {:?}", data.to_vec());
    Response::decode(&data)
}

pub fn create_keypair<P: AsRef<Path>>(
    stream: &mut TcpStream,
    secret_key_path: P,
    public_key_path: P,
) -> Result<(), Error> {
    let request = Request::GenerateKey;
    if let Response::KeyPair(keypair) = send(stream, request)? {
        store_keypair(&keypair, secret_key_path, public_key_path)
    } else {
        return Err(Error::new("response error"));
    }
}

fn store_keypair<P: AsRef<Path>>(
    key_pair: &KeyPair,
    secret_key_path: P,
    publick_key_path: P,
) -> Result<(), Error> {
    let public_key = &key_pair.pubkey;
    let public_key_str = hex::encode(public_key);
    let mut pubkey_file = File::create(publick_key_path)?;
    pubkey_file.write_all(&public_key_str.as_bytes())?;

    // can not use the old secret_key path
    if secret_key_path.as_ref().exists() {
        return Err(Error::new(format!(
            "secret key path {:?} already exist",
            secret_key_path.as_ref()
        )));
    }
    let mut secret_file = File::create(secret_key_path)?;
    let secret_raw_data = key_pair.sealed_privkey.encode()?;
    let secret_str = hex::encode(&secret_raw_data);
    secret_file.write_all(&secret_str.as_bytes())?;
    Ok(())
}

pub fn get_pubkey(stream: &mut TcpStream, secret_str: &str) -> Result<String, Error> {
    let secret_raw = hex::decode(secret_str).map_err(|e| Error::new("invalid secret string"))?;
    let request = Request::GetPublicKey(SealedSigner::decode(&secret_raw)?);
    let r = send(stream, request)?;
    println!("response: {:?}", r);
    if let Response::PublicKey(pubkey_raw) = r {
        let pubkey_str = hex::encode(&pubkey_raw);
        Ok(pubkey_str)
    } else {
        return Err(Error::new("response error"));
    }
}
