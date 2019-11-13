use crate::error::Error;
use crate::protocol::{Decode, Encode, Request, Response, KeyPair, ENCRYPTION_REQUEST_SIZE};
use std::io::prelude::*;
use std::net::TcpStream;
use std::path::Path;
use std::fs::File;

pub fn send(stream: &mut TcpStream, request: Request) -> Result<Response, Error> {
    let request_rawdata = request.encode()?;
    let _ = stream.write(&request_rawdata)?;
    let mut data = [0_u8; ENCRYPTION_REQUEST_SIZE];
    let _ = stream.read(&mut data)?;
    Response::decode(&data)
}

pub fn create_keypair<P: AsRef<Path>>(
    stream: &mut TcpStream,
    secret_key_path: P,
    public_key_path: P) -> Result<(), Error> {
    let request = Request::GenerateKey;
    if let Response::KeyPair(keypair)  = send(stream, request)? {
        store_keypair(&keypair, secret_key_path, public_key_path)
    } else {
        return Err(Error::new("response error"))
    }
}

fn store_keypair<P: AsRef<Path>>(
    key_pair: &KeyPair,
    secret_key_path: P,
    publick_key_path: P) -> Result<(), Error>{
    let public_key = &key_pair.pubkey;
    let mut pubkey_file = File::create(publick_key_path)?;
    pubkey_file.write_all(&public_key)?;

    // can not use the old secret_key path
    if secret_key_path.as_ref().exists() {
       return Err(Error::new("secret key path already exist"))
    }
    let mut secret_file = File::create(secret_key_path)?;
    secret_file.write_all(&key_pair.sealed_privkey.encode()?)?;
    Ok(())
}
