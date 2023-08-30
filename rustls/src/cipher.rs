#![allow(missing_docs)]

use std::collections::HashMap;
use crate::error::Error;
use crate::msgs::codec;
use crate::msgs::message::{BorrowedPlainMessage, OpaqueMessage, PlainMessage};

use ring::{aead, hkdf};


/// Objects with this trait can decrypt TLS messages.
pub trait MessageDecrypter: Send + Sync {
    /// Perform the decryption over the concerned TLS message.

    fn decrypt(&self, m: OpaqueMessage, seq: u64, connection_id: u32) -> Result<PlainMessage, Error>;
    fn derive_dec_connection_iv(&mut self, conn_id: u32);
}

/// Objects with this trait can encrypt TLS messages.
pub(crate) trait MessageEncrypter: Send + Sync {
    fn encrypt(&self, m: BorrowedPlainMessage, seq: u64, connection_id: u32) -> Result<OpaqueMessage, Error>;
    fn derive_enc_connection_iv(&mut self, conn_id: u32);
}

impl dyn MessageEncrypter {
    pub(crate) fn invalid() -> Box<dyn MessageEncrypter> {
        Box::new(InvalidMessageEncrypter {})
    }
}

impl dyn MessageDecrypter {
    pub(crate) fn invalid() -> Box<dyn MessageDecrypter> {
        Box::new(InvalidMessageDecrypter {})
    }
}

/// A write or read IV.
#[derive(Default)]
pub(crate) struct Iv(pub(crate) [u8; ring::aead::NONCE_LEN]);

impl Iv {
    #[cfg(feature = "tls12")]
    fn new(value: [u8; ring::aead::NONCE_LEN]) -> Self {
        Self(value)
    }

    #[cfg(feature = "tls12")]
    pub(crate) fn copy(value: &[u8]) -> Self {
        debug_assert_eq!(value.len(), ring::aead::NONCE_LEN);
        let mut iv = Self::new(Default::default());
        iv.0.copy_from_slice(value);
        iv
    }

    #[cfg(test)]
    pub(crate) fn value(&self) -> &[u8; 12] {
        &self.0
    }
}

pub(crate) struct IvLen;

impl hkdf::KeyType for IvLen {
    fn len(&self) -> usize {
        aead::NONCE_LEN
    }
}

impl From<hkdf::Okm<'_, IvLen>> for Iv {
    fn from(okm: hkdf::Okm<IvLen>) -> Self {
        let mut r = Self(Default::default());
        okm.fill(&mut r.0[..]).unwrap();
        r
    }
}

pub(crate) fn make_nonce(iv: &Iv, seq: u64) -> ring::aead::Nonce {
    let mut nonce = [0u8; ring::aead::NONCE_LEN];
    codec::put_u64(seq, &mut nonce[4..]);

    nonce
        .iter_mut()
        .zip(iv.0.iter())
        .for_each(|(nonce, iv)| {
            *nonce ^= *iv;
        });

    aead::Nonce::assume_unique_for_key(nonce)
}

pub(crate) fn derive_connection_iv(iv: &mut HashMap<u32, Iv>, connection_id: u32){
        let mut conn_id = [0u8; aead::NONCE_LEN];
        codec::put_u32(connection_id, &mut conn_id[..4]);

        conn_id
            .iter_mut()
            .zip(iv.get_mut(&0).unwrap().0.iter_mut())
            .for_each(|(conn_id, iv)| {
                *conn_id ^= *iv;
            });
        iv.insert(connection_id, Iv::copy(&conn_id));
    }



/// A `MessageEncrypter` which doesn't work.
struct InvalidMessageEncrypter {}

impl MessageEncrypter for InvalidMessageEncrypter {
    fn encrypt(&self, _m: BorrowedPlainMessage, _seq: u64, connection_id: u32) -> Result<OpaqueMessage, Error> {
        Err(Error::EncryptError)
    }

    fn derive_enc_connection_iv(&mut self, conn_id: u32) {

    }
}

/// A `MessageDecrypter` which doesn't work.
struct InvalidMessageDecrypter {}

impl MessageDecrypter for InvalidMessageDecrypter {
    fn decrypt(&self, _m: OpaqueMessage, _seq: u64, connection_id: u32) -> Result<PlainMessage, Error> {
        Err(Error::DecryptError)
    }

    fn derive_dec_connection_iv(&mut self, conn_id: u32) {

    }
}
