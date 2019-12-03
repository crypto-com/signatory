use crate::error::Error;
use crate::seal_signer::SealedSigner;
use serde::{Deserialize, Serialize};
use std::io::{Error as IoError, Read, Write};

pub type DataType = Vec<u8>;
#[cfg(feature = "std")]
pub type SecretKeyEncoding = subtle_encoding::Base64;

#[derive(Debug)]
pub enum KeyType {
    Base64,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    Ping,
    KeyGen,
    GetPublicKey(SealedSigner),
    Import(Vec<u8>), // return Response::KeyPair
    Sign((SealedSigner, DataType)),
}

impl Encode for Request {}
impl<'de> Decode<'de> for Request {}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Pong,
    KeyPair(KeyPair),
    PublicKey(Vec<u8>),
    Signed(DataType),
    Error(String),
}

impl Encode for Response {}
impl<'de> Decode<'de> for Response {}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyPair {
    pub sealed_privkey: SealedSigner,
    pub pubkey: Vec<u8>,
}

pub fn get_data_from_stream<T: Read>(stream: &mut T) -> Result<Vec<u8>, Error> {
    let mut len_info = [0_u8; 8];
    let _ = stream.read(&mut len_info)?;
    let data_len = usize::from_le_bytes(len_info);
    let mut data = vec![0_u8; data_len];
    let _ = stream.read(&mut data)?;
    Ok(data)
}

pub fn send_data_to_stream<W: Write>(
    stream: &mut W,
    data: &[u8],
    with_len_info: bool,
) -> Result<usize, IoError> {
    let l1 = if with_len_info {
        let data_len: [u8; 8] = data.len().to_le_bytes();
        stream.write(&data_len)?
    } else {
        0
    };
    let l2 = stream.write(&data[..])?;
    Ok(l1 + l2)
}

pub trait Encode: Serialize {
    fn encode(&self, with_len_info: bool) -> Result<Vec<u8>, Error> {
        let data = bincode::serialize(self)
            .map_err(|e| Error::new(format!("serialize seal signer failed with error: {:?}", e)))?;
        // the first 8 bits is the length info of the serialized data
        if with_len_info {
            let len_data: [u8; 8] = data.len().to_le_bytes();
            let mut result = len_data.to_vec();
            result.extend_from_slice(&data);
            Ok(result)
        } else {
            Ok(data)
        }
    }
}

pub trait Decode<'de>: Deserialize<'de> {
    fn decode(encoded: &'de [u8]) -> Result<Self, Error> {
        bincode::deserialize(encoded)
            .map_err(|e| Error::new(format!("deserialize with error: {:?}", e)))
    }
}
