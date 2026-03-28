use std::fmt;

use aead::{Aead, KeyInit, Nonce as AeadNonce};
use aes::Aes128;
use base64::{Engine, engine::general_purpose::STANDARD};
use ocb3::Ocb3;
use rand::RngCore;

type Aes128Ocb3 = Ocb3<Aes128>;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const DIRECTION_MASK: u64 = 1u64 << 63;
const SEQUENCE_MASK: u64 = !DIRECTION_MASK;

#[derive(Debug)]
pub struct CryptoError {
    pub message: String,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CryptoError {}

#[derive(Clone)]
pub struct Base64Key {
    key: [u8; 16],
}

impl Base64Key {
    pub fn new() -> Self {
        let mut key = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut key);
        Base64Key { key }
    }

    pub fn printable_key(&self) -> String {
        let encoded = STANDARD.encode(self.key);
        encoded.trim_end_matches('=').to_string()
    }

    pub fn data(&self) -> &[u8; 16] {
        &self.key
    }
}

#[derive(Clone, Debug)]
pub struct MoshNonce {
    bytes: [u8; NONCE_LEN],
}

impl MoshNonce {
    pub fn from_val(val: u64) -> Self {
        let mut bytes = [0u8; NONCE_LEN];
        bytes[4..12].copy_from_slice(&val.to_be_bytes());
        MoshNonce { bytes }
    }

    pub fn from_bytes(wire_bytes: &[u8]) -> Result<Self, CryptoError> {
        if wire_bytes.len() != 8 {
            return Err(CryptoError {
                message: "Nonce representation must be 8 octets long.".into(),
            });
        }
        let mut bytes = [0u8; NONCE_LEN];
        bytes[4..12].copy_from_slice(wire_bytes);
        Ok(MoshNonce { bytes })
    }

    pub fn cc_str(&self) -> &[u8] {
        &self.bytes[4..12]
    }

    pub fn data(&self) -> &[u8; NONCE_LEN] {
        &self.bytes
    }

    pub fn val(&self) -> u64 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&self.bytes[4..12]);
        u64::from_be_bytes(buf)
    }
}

pub struct Message {
    pub nonce: MoshNonce,
    pub text: Vec<u8>,
}

pub struct Session {
    cipher: Aes128Ocb3,
    blocks_encrypted: u64,
}

impl Session {
    pub fn new(key: &Base64Key) -> Result<Self, CryptoError> {
        let cipher =
            Aes128Ocb3::new_from_slice(key.data()).map_err(|_| CryptoError {
                message: "Could not initialize AES-OCB context.".into(),
            })?;
        Ok(Session {
            cipher,
            blocks_encrypted: 0,
        })
    }

    pub fn encrypt(&mut self, plaintext: &Message) -> Result<Vec<u8>, CryptoError> {
        let pt_len = plaintext.text.len();

        let nonce = AeadNonce::<Aes128Ocb3>::from_slice(plaintext.nonce.data());
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext.text.as_slice())
            .map_err(|_| CryptoError {
                message: "ae_encrypt() returned error.".into(),
            })?;

        self.blocks_encrypted +=
            (pt_len as u64 >> 4) + if pt_len & 0xF != 0 { 1 } else { 0 };
        if self.blocks_encrypted >> 47 != 0 {
            return Err(CryptoError {
                message: "Encrypted 2^47 blocks.".into(),
            });
        }

        let mut output = Vec::with_capacity(8 + ciphertext.len());
        output.extend_from_slice(plaintext.nonce.cc_str());
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Message, CryptoError> {
        if data.len() < 8 + TAG_LEN {
            return Err(CryptoError {
                message: "Ciphertext must contain nonce and tag.".into(),
            });
        }

        let nonce = MoshNonce::from_bytes(&data[..8])?;
        let body = &data[8..];

        let aead_nonce = AeadNonce::<Aes128Ocb3>::from_slice(nonce.data());
        let plaintext =
            self.cipher
                .decrypt(aead_nonce, body)
                .map_err(|_| CryptoError {
                    message: "Packet failed integrity check.".into(),
                })?;

        Ok(Message {
            nonce,
            text: plaintext,
        })
    }
}

pub fn make_nonce_val(to_client: bool, seq: u64) -> u64 {
    let direction_bit = if to_client { DIRECTION_MASK } else { 0 };
    direction_bit | (seq & SEQUENCE_MASK)
}

pub fn nonce_is_to_client(val: u64) -> bool {
    val & DIRECTION_MASK != 0
}

pub fn nonce_seq(val: u64) -> u64 {
    val & SEQUENCE_MASK
}
