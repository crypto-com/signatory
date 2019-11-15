use crate::error::Error;
use crate::seal_signer::SealedSigner;
use serde::{Deserialize, Serialize};

pub const ENCRYPTION_REQUEST_SIZE: usize = 1024 * 1; // 1 KB

pub type DataType = Vec<u8>;

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    Ping,
    GenerateKey,
    GetPublicKey(SealedSigner),
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

pub trait Encode: Serialize {
    fn encode(&self) -> Result<Vec<u8>, Error> {
        let data = bincode::serialize(self)
            .map_err(|e| Error::new(format!("serialize seal signer failed with error: {:?}", e)))?;
        if data.len() > ENCRYPTION_REQUEST_SIZE {
            Err(Error::new("encoded data too large"))
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
