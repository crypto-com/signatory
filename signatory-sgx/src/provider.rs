use crate::error::Error;
use crate::protocol::{Decode, Encode, KeyPair, KeyType, Request, Response, SecretKeyEncoding};
use crate::seal_signer::SealedSigner;
use crate::server::C2S;
use crossbeam_channel::{unbounded, Receiver, Sender};
use log::debug;
use signatory::ed25519;
use signatory::public_key::PublicKeyed;
use signatory::signature::{Error as SigError, Signature, Signer};
use std::path::Path;
use subtle_encoding::encoding::Encoding;

#[inline]
pub fn store_data_to_file<P: AsRef<Path>>(data: &[u8], file_path: P) -> Result<(), Error> {
    let encoder = SecretKeyEncoding::default();
    encoder
        .encode_to_file(data, file_path)
        .map_err(|e| Error::new(format!("encode to file failed: {:?}", e)))?;
    Ok(())
}

#[inline]
pub fn get_data_from_file<P: AsRef<Path>>(file_path: P) -> Result<Vec<u8>, Error> {
    let encoder = SecretKeyEncoding::default();
    let data_raw = encoder
        .decode_from_file(file_path)
        .map_err(|e| Error::new(format!("decode from file failed: {:?}", e)))?;
    Ok(data_raw)
}

#[inline]
pub fn encode_to_string(raw_data: &[u8]) -> Result<String, Error> {
    let encoder = SecretKeyEncoding::default();
    let result = encoder
        .encode_to_string(raw_data)
        .map_err(|e| Error::new(format!("encode data to string failed: {:?}", e)))?;
    Ok(result)
}

pub struct SgxSigner<P: AsRef<Path>> {
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
    client2server_tx: Sender<C2S>,
    sealed_signer_path: P,
}

impl<P: AsRef<Path>> SgxSigner<P> {
    pub fn new(client2server_tx: Sender<C2S>, sealed_signer_path: P) -> Self {
        let (tx, rx) = unbounded::<Vec<u8>>();
        Self {
            tx,
            rx,
            client2server_tx,
            sealed_signer_path,
        }
    }

    fn send(&self, request: Request) -> Result<Response, Error> {
        debug!("send request {:?}", request);
        let request_rawdata = request.encode(true)?;
        self.client2server_tx
            .send((self.tx.clone(), request_rawdata))
            .map_err(|e| Error::new(format!("send data error: {:?}", e)))?;
        let data = self
            .rx
            .recv()
            .map_err(|e| Error::new(format!("receive data error: {:?}", e)))?;
        Response::decode(&data[8..]) // remove the first 8 bits info
    }

    pub fn store_key(&self, key_pair: &KeyPair) -> Result<String, Error> {
        // dangerous to use the old secret_key path
        if self.sealed_signer_path.as_ref().exists() {
            return Err(Error::new("secret key path already exist"));
        }
        let secret_raw_data = key_pair.sealed_privkey.encode(false)?;
        store_data_to_file(&secret_raw_data, &self.sealed_signer_path)?;
        let pubkey_str = encode_to_string(&key_pair.pubkey)?;
        Ok(pubkey_str)
    }

    #[inline]
    fn get_sealed_signer(&self) -> Result<SealedSigner, Error> {
        let sgx_secret_raw = get_data_from_file(self.sealed_signer_path.as_ref())?;
        let signer = SealedSigner::decode(&sgx_secret_raw)?;
        Ok(signer)
    }

    pub fn ping(&self) -> Result<(), Error> {
        let request = Request::Ping;
        let response = self.send(request)?;
        match response {
            Response::Pong => Ok(()),
            Response::Error(s) => Err(Error::new(s)),
            _ => Err(Error::new("response invalid")),
        }
    }

    pub fn keygen(&self) -> Result<KeyPair, Error> {
        let request = Request::KeyGen;
        match self.send(request)? {
            Response::Error(s) => Err(Error::new(s)),
            Response::KeyPair(keypair) => Ok(keypair),
            _ => Err(Error::new("error kind of response")),
        }
    }

    pub fn import<S: AsRef<str>>(&self, key_type: KeyType, key_str: S) -> Result<KeyPair, Error> {
        let key_pair_raw = match key_type {
            KeyType::Base64 => {
                let encoder = SecretKeyEncoding::default();
                let raw = encoder
                    .decode_from_str(key_str.as_ref())
                    .map_err(|_| Error::new("invalid key"))?;
                raw
            }
        };
        let request = Request::Import(key_pair_raw);
        match self.send(request)? {
            Response::Error(s) => Err(Error::new(s)),
            Response::KeyPair(keypair) => Ok(keypair),
            _ => Err(Error::new("error kind of response")),
        }
    }

    pub fn get_pubkey(&self) -> Result<Vec<u8>, Error> {
        let sealed_signer = self.get_sealed_signer()?;
        let request = Request::GetPublicKey(sealed_signer);
        let response = self.send(request)?;
        debug!("response: {:?}", response);
        match response {
            Response::PublicKey(pubkey_raw) => Ok(pubkey_raw),
            Response::Error(s) => Err(Error::new(s)),
            _ => Err(Error::new("response error")),
        }
    }

    pub fn sign_msg(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let sealed_signer = self.get_sealed_signer()?;
        let request = Request::Sign((sealed_signer, msg.to_vec()));
        let response = self.send(request)?;
        debug!("response: {:?}", response);
        match response {
            Response::Signed(data) => Ok(data),
            Response::Error(s) => Err(Error::new(s)),
            _ => Err(Error::new("response error")),
        }
    }
}

impl<P> PublicKeyed<ed25519::PublicKey> for SgxSigner<P>
where
    P: AsRef<Path> + Send + Sync,
{
    fn public_key(&self) -> Result<ed25519::PublicKey, SigError> {
        let pubkey_raw = self.get_pubkey().map_err(SigError::from_source)?;
        let pubkey = ed25519::PublicKey::from_bytes(&pubkey_raw);
        if let Some(p) = pubkey {
            Ok(p)
        } else {
            Err(SigError::new())
        }
    }
}

impl<P> Signer<ed25519::Signature> for SgxSigner<P>
where
    P: AsRef<Path> + Send + Sync,
{
    fn try_sign(&self, msg: &[u8]) -> Result<ed25519::Signature, SigError> {
        let signature_raw = self.sign_msg(msg).map_err(SigError::from_source)?;
        let signature = ed25519::Signature::from_bytes(&signature_raw[..])?;
        Ok(signature)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_file() {
        let a = b"hello world";
        store_data_to_file(a, "/tmp/a.txt").unwrap();
        let b = get_data_from_file("/tmp/a.txt").unwrap();
        assert_eq!(a.to_vec(), b);
    }
}
