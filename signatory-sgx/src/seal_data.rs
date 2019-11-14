use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sgx_isa::{Attributes, Miscselect};

#[cfg(feature = "sgx")]
use crate::error::Error;
#[cfg(feature = "sgx")]
use rand::random;
#[cfg(feature = "sgx")]
use sgx_isa::Report;
#[cfg(feature = "sgx")]
use sgx_isa::{Keyname, Keypolicy, Keyrequest};
#[cfg(feature = "sgx")]
use std::convert::AsRef;

#[derive(Debug, Clone, PartialEq)]
struct SealAttributes(Attributes);

impl AsRef<Attributes> for SealAttributes {
    fn as_ref(&self) -> &Attributes {
        &self.0
    }
}

impl Serialize for SealAttributes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.0.as_ref();
        serializer.serialize_bytes(bytes)
    }
}

impl<'de> Deserialize<'de> for SealAttributes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw_data: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if let Some(attr) = Attributes::try_copy_from(&raw_data) {
            Ok(SealAttributes(attr))
        } else {
            Err(de::Error::custom("deserilize to SealAttributes error"))
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
struct SealMiscselect(Miscselect);

impl AsRef<Miscselect> for SealMiscselect {
    fn as_ref(&self) -> &Miscselect {
        &self.0
    }
}

impl Serialize for SealMiscselect {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let num: u32 = self.0.bits();
        serializer.serialize_u32(num)
    }
}

impl<'de> Deserialize<'de> for SealMiscselect {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bits: u32 = Deserialize::deserialize(deserializer)?;
        if let Some(misc) = Miscselect::from_bits(bits as _) {
            Ok(SealMiscselect(misc))
        } else {
            Err(de::Error::custom(format!(
                "deserilize Miscselect from {} failed",
                bits
            )))
        }
    }
}

pub type EgetKey = [u8; 16];
pub type Label = [u8; 16];
pub type Nonce = [u8; 12];
pub type CpuSvn = [u8; 16];
pub type IsvSvn = u16;

/// Information about how the sealing key was derived. This
/// should be stored alongside the sealed data, so that the enclave
/// can rederive the same key later.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SealData {
    rand: [u8; 16],
    pub nonce: Nonce,
    isvsvn: IsvSvn,
    cpusvn: CpuSvn,
    // Record attributes and miscselect so that we can verify that
    // we can derive the correct wrapping key, but the actual input
    // to the derivation is CPU enclave state + SW-specified masks.
    attributes: SealAttributes,
    miscselect: SealMiscselect,
}

/// Derive a sealing key for the current enclave given `label` and `seal_data`.
#[cfg(feature = "sgx")]
fn egetkey(label: Label, seal_data: &SealData) -> Result<EgetKey, Error> {
    // Key ID is combined from fixed label and random data
    let mut keyid = [0; 32];
    {
        let (label_dst, rand_dst) = keyid.split_at_mut(16);
        label_dst.copy_from_slice(&label);
        rand_dst.copy_from_slice(&seal_data.rand);
    }

    Keyrequest {
        keyname: Keyname::Seal as _,
        keypolicy: Keypolicy::MRENCLAVE,
        isvsvn: seal_data.isvsvn,
        cpusvn: seal_data.cpusvn,
        attributemask: [!0; 2],
        keyid: keyid,
        miscmask: !0,
        ..Default::default()
    }
    .egetkey()
    .map_err(|e| Error::new(format!("get egetkey failed with error: {:?}", e)))
}

/// Get a key for sealing data.
///
/// The returned key may be used for authenticated encryption.
///
/// If you call `seal_key` at different places in your code to seal
/// different types of data, make sure to pass a different `label`.
/// The returned `SealData` should be stored alongside the
/// ciphertext to make sure the data can be unsealed again later.
#[cfg(feature = "sgx")]
pub fn seal_key(label: Label) -> (EgetKey, SealData) {
    let report = Report::for_self();
    let seal_data = SealData {
        // Generate fresh randomness for each sealing operation.
        rand: random(),
        // Copy the parameters of the current enclave into SealData.
        nonce: random(),
        isvsvn: report.isvsvn,
        cpusvn: report.cpusvn,
        attributes: SealAttributes(report.attributes),
        miscselect: SealMiscselect(report.miscselect),
    };

    // EGETKEY should never error here because we used the
    // information from `Report::for_self`.
    (egetkey(label, &seal_data).unwrap(), seal_data)
}

/// Get a key for unsealing data.
///
/// The returned key may be used for authenticated decryption.
///
/// Pass in the same `label` that was used to get the sealing key,
/// and pass in the `seal_data` that was returned when obtaining the
/// sealing key.
///
/// # Errors
///
/// May return an error if the sealing key was not generated by the
/// same enclave configuration, or if the SGX TCB level has been
/// downgraded.
#[cfg(feature = "sgx")]
pub fn unseal_key(label: Label, seal_data: &SealData) -> Result<EgetKey, Error> {
    let report = Report::for_self();
    // Make sure the parameters that are not checked for correctness
    // by EGETKEY match the current enclave. Without this check,
    // EGETKEY will proceed to derive a key, which will be an
    // incorrect key.
    if report.attributes != *seal_data.attributes.as_ref()
        || report.miscselect != *seal_data.miscselect.as_ref()
    {
        return Err(Error::new("seal data not match"));
    }

    egetkey(label, &seal_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_attributes_serde() {
        let report = Report::for_self();
        let seal_attributes = SealAttributes(report.attributes);
        let encoded = bincode::serialize(&seal_attributes).unwrap();
        let decoded = bincode::deserialize(&encoded[..]).unwrap();
        assert_eq!(seal_attributes, decoded);
    }

    #[test]
    fn test_seal_misc_serde() {
        let report = Report::for_self();
        let seal_data = SealMiscselect(report.miscselect);
        let encoded = bincode::serialize(&seal_data).unwrap();
        let decoded = bincode::deserialize(&encoded[..]).unwrap();
        assert_eq!(seal_data, decoded);
    }

    #[test]
    fn test_seal_data_serde() {
        let label = Label::from([0; 16]);
        let (_, seal_data) = seal_key(label);
        let encoded = bincode::serialize(&seal_data).unwrap();
        let decoded = bincode::deserialize(&encoded[..]).unwrap();
        assert_eq!(seal_data, decoded);
    }
}
