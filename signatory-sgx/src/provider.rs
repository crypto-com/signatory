use crate::error::Error;
use crate::protocol::{Decode, Encode, KeyPair, Request, Response, ENCRYPTION_REQUEST_SIZE};
use crate::seal_signer::SealedSigner;
use log::debug;
use signatory::ed25519;
use signatory::public_key::PublicKeyed;
use signatory::signature::{Error as SigError, Signature, Signer};
use std::fs::{self, File};
use std::io::prelude::*;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;

#[inline]
pub fn store_data_to_file<P: AsRef<Path>>(data: &[u8], file_path: P) -> Result<(), Error> {
    let mut file = File::create(file_path)?;
    let data_str = hex::encode(data);
    file.write_all(data_str.as_bytes())?;
    Ok(())
}

#[inline]
pub fn get_data_from_file<P: AsRef<Path>>(file_path: P) -> Result<Vec<u8>, Error> {
    let data_str = fs::read_to_string(file_path)?;
    let data_raw =
        hex::decode(data_str.trim()).map_err(|_e| Error::new("error to decode content in file"))?;
    Ok(data_raw)
}

pub struct SgxSigner<S: ToSocketAddrs, P: AsRef<Path>> {
    sgx_server: S,
    sealed_signer_path: P,
}

impl<S: ToSocketAddrs, P: AsRef<Path>> SgxSigner<S, P> {
    pub fn new(addr: S, sealed_signer_path: P) -> Self {
        Self {
            sgx_server: addr,
            sealed_signer_path,
        }
    }

    #[inline]
    fn connect(&self) -> Result<TcpStream, Error> {
        let stream = TcpStream::connect(&self.sgx_server)?;
        Ok(stream)
    }

    fn send(&self, request: Request) -> Result<Response, Error> {
        let mut stream = self.connect()?;
        debug!("send request {:?}", request);
        let request_rawdata = request.encode()?;
        let _ = stream.write(&request_rawdata)?;
        let mut data = [0_u8; ENCRYPTION_REQUEST_SIZE];
        let _ = stream.read(&mut data)?;
        debug!("get raw data: {:?}", data.to_vec());
        Response::decode(&data)
    }

    fn store_key(&self, key_pair: &KeyPair) -> Result<(), Error> {
        // dangerous to use the old secret_key path
        if self.sealed_signer_path.as_ref().exists() {
            return Err(Error::new("secret key path already exist"));
        }
        let secret_raw_data = key_pair.sealed_privkey.encode()?;
        store_data_to_file(&secret_raw_data, &self.sealed_signer_path)
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

    pub fn create_keypair(&self) -> Result<(), Error> {
        let request = Request::GenerateKey;
        let response = self.send(request)?;
        match response {
            Response::KeyPair(keypair) => Ok(()),
            Response::Error(s) => Err(Error::new(s)),
            _ => Err(Error::new("response error")),
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

impl<S, P> PublicKeyed<ed25519::PublicKey> for SgxSigner<S, P>
where
    S: ToSocketAddrs + Sync + Send,
    P: AsRef<Path> + Sync + Send,
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

impl<S, P> Signer<ed25519::Signature> for SgxSigner<S, P>
where
    S: ToSocketAddrs + Sync + Send,
    P: AsRef<Path> + Sync + Send,
{
    fn try_sign(&self, msg: &[u8]) -> Result<ed25519::Signature, SigError> {
        let signature_raw = self.sign_msg(msg).map_err(SigError::from_source)?;
        let signature = ed25519::Signature::from_bytes(&signature_raw[..])?;
        Ok(signature)
    }
}
