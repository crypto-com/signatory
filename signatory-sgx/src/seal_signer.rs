use crate::protocol::{Decode, Encode};
use crate::seal_data::{Label, SealData};
use serde::{Deserialize, Serialize};

#[cfg(feature = "sgx")]
use crate::error::Error;
#[cfg(feature = "sgx")]
use crate::seal_data::{seal_key, unseal_key};
#[cfg(feature = "sgx")]
use aead::{generic_array::GenericArray, Aead, NewAead};
#[cfg(feature = "sgx")]
use aes_gcm_siv::Aes128GcmSiv;
#[cfg(feature = "sgx")]
use rand::random;
#[cfg(feature = "sgx")]
use signatory::ed25519;
#[cfg(feature = "sgx")]
use signatory::public_key::PublicKeyed;
#[cfg(feature = "sgx")]
use signatory::signature::Signature;
#[cfg(feature = "sgx")]
use signatory::signature::{Signer, Verifier};
#[cfg(feature = "sgx")]
use signatory_dalek::{Ed25519Signer, Ed25519Verifier};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct SealedSigner {
    sealed_seed: Vec<u8>,
    seal_data: SealData,
    label: Label,
}

#[cfg(feature = "sgx")]
impl SealedSigner {
    pub fn new() -> Result<Self, Error> {
        let label: Label = random();
        let seed = ed25519::Seed::generate();
        let raw_seed = seed.as_secret_slice();

        let (eget_key, seal_data) = seal_key(label);
        let aead = get_algo(&eget_key);
        let nonce = GenericArray::from_slice(&seal_data.nonce);
        let sealed_seed = aead
            .encrypt(nonce, raw_seed)
            .map_err(|e| Error::new(format!("encrypt seed failed with error: {:?}", e)))?;

        let s = Self {
            sealed_seed,
            seal_data,
            label,
        };
        Ok(s)
    }

    fn get_signer(&self) -> Result<Ed25519Signer, Error> {
        let seal_key = unseal_key(self.label, &self.seal_data)?;
        let nonce = GenericArray::from_slice(&self.seal_data.nonce);
        let aead = get_algo(&seal_key);
        let raw_seed = aead
            .decrypt(nonce, self.sealed_seed.as_ref())
            .map_err(|_e| Error::new("get signer failed, the host changed or the program changed"))?;
        if let Some(signer) =
            ed25519::Seed::from_bytes(raw_seed).map(|seed| Ed25519Signer::from(&seed))
        {
            Ok(signer)
        } else {
            Err(Error::new("get signer failed"))
        }
    }

    pub fn try_sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let signer = self.get_signer()?;
        let sig = signer
            .try_sign(data)
            .map_err(|e| Error::new(format!("sign data with error: {}", e)))?;
        Ok(sig.to_bytes().to_vec())
    }

    pub fn verify(&self, msg: &[u8], sig_raw: &[u8]) -> Result<(), Error> {
        let public_key = self.get_public_key()?;
        let verifier = Ed25519Verifier::from(&public_key);
        let sig =
            ed25519::Signature::from_bytes(sig_raw).map_err(|_| Error::new("invalid signature"))?;
        verifier
            .verify(msg, &sig)
            .map_err(|e| Error::new(format!("varify failed with error: {:?}", e)))
    }

    pub fn get_public_key(&self) -> Result<ed25519::PublicKey, Error> {
        let signer = self.get_signer()?;
        signer
            .public_key()
            .map_err(|e| Error::new(format!("get public key failed with error: {:?}", e)))
    }
}

impl Encode for SealedSigner {}
impl<'de> Decode<'de> for SealedSigner {}

#[cfg(feature = "sgx")]
fn get_algo(seal_key: &[u8]) -> Aes128GcmSiv {
    let key = GenericArray::clone_from_slice(seal_key);
    let aead = Aes128GcmSiv::new(key);
    aead
}

#[cfg(all(test, feature = "sgx"))]
mod tests {
    use super::*;

    #[test]
    fn test_serde() {
        let sealed_signer = SealedSigner::new().unwrap();
        let encoded = sealed_signer.encode().unwrap();
        let decoded = SealedSigner::decode(&encoded).unwrap();
        assert_eq!(sealed_signer, decoded);
    }

    #[test]
    fn test_sign() {
        let sealed = SealedSigner::new().unwrap();
        // sign message
        let msg = b"hello world";
        let sig_raw = sealed.try_sign(msg).unwrap();
        // verify sig
        assert!(sealed.verify(msg, &sig_raw).is_ok());
    }

    #[test]
    fn test_get_pubkey() {
        let sealed = SealedSigner::new().unwrap();
        let pubkey = sealed.get_public_key();
        assert!(pubkey.is_ok());
    }
}
