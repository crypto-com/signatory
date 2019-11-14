use crate::error::Error;
use crate::protocol::{Decode, Encode, KeyPair, Request, Response, ENCRYPTION_REQUEST_SIZE};
use crate::seal_signer::SealedSigner;
use log::debug;
use std::fs::{self, File};
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
    public_key_path: P,
) -> Result<(), Error> {
    let public_key = &key_pair.pubkey;
    let public_key_str = hex::encode(public_key);
    let mut pubkey_file = File::create(public_key_path)?;
    pubkey_file.write_all(&public_key_str.as_bytes())?;

    // dangerous to use the old secret_key path
    if secret_key_path.as_ref().exists() {
        return Err(Error::new(format!(
            "secret key path {:?} already exist",
            secret_key_path.as_ref()
        )));
    }
    let secret_raw_data = key_pair.sealed_privkey.encode()?;
    store_data_to_file(&secret_raw_data, secret_key_path)
}

pub fn store_data_to_file<P: AsRef<Path>>(data: &[u8], file_path: P) -> Result<(), Error> {
    let mut file = File::create(file_path)?;
    let data_str = hex::encode(data);
    file.write_all(data_str.as_bytes())?;
    Ok(())
}

pub fn get_data_from_file<P: AsRef<Path>>(file_path: P) -> Result<Vec<u8>, Error> {
    let data_str = fs::read_to_string(file_path)?;
    let data_raw =
        hex::decode(data_str.trim()).map_err(|_e| Error::new("error to decode content in file"))?;
    Ok(data_raw)
}

pub fn get_pubkey(stream: &mut TcpStream, secret_raw: &[u8]) -> Result<Vec<u8>, Error> {
    let request = Request::GetPublicKey(SealedSigner::decode(secret_raw)?);
    let response = send(stream, request)?;
    debug!("response: {:?}", response);
    match response {
        Response::PublicKey(pubkey_raw) => Ok(pubkey_raw),
        Response::Error(s) => Err(Error::new(s)),
        _ => Err(Error::new("response error")),
    }
}

pub fn sign(stream: &mut TcpStream, secret_raw: &[u8], data: Vec<u8>) -> Result<Vec<u8>, Error> {
    let sealed_signer = SealedSigner::decode(secret_raw)?;
    let request = Request::Sign((sealed_signer, data));
    let response = send(stream, request)?;
    debug!("response: {:?}", response);
    match response {
        Response::Signed(data) => Ok(data),
        Response::Error(s) => Err(Error::new(s)),
        _ => Err(Error::new("response error")),
    }
}
