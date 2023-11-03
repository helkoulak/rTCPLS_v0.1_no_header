#![allow(missing_docs)]


use std::collections::HashMap;


use crate::error::Error;
use crate::msgs::codec;
use crate::msgs::message::{BorrowedOpaqueMessage, BorrowedPlainMessage, PlainMessage};

use ring::{aead, hkdf};
use siphasher::sip::SipHasher;


use crate::recvbuf::RecvBuf;
use crate::tcpls::frame::StreamFrameHeader;




/// Objects with this trait can decrypt TLS messages.
pub trait MessageDecrypter: Send + Sync {
    /// Perform the decryption over the concerned TLS message.

    fn decrypt(&self, m: BorrowedOpaqueMessage, seq: u64, conn_id: u32) -> Result<PlainMessage, Error>;
   fn decrypt_zc(&self, msg: BorrowedOpaqueMessage, seq: u64, conn_id: u32, recv_buf: &mut RecvBuf) -> Result<PlainMessage, Error>;
    fn derive_dec_conn_iv(&mut self, conn_id: u32);
}

/// Objects with this trait can encrypt TLS messages.
pub(crate) trait MessageEncrypter: Send + Sync {
    fn encrypt(&self, m: BorrowedPlainMessage, seq: u64, conn_id: u32) -> Result<Vec<u8>, Error>;
    fn encrypt_zc(&self, msg: BorrowedPlainMessage, seq: u64, conn_id: u32, tcpls_header: StreamFrameHeader) -> Result<Vec<u8>, Error>;
    fn derive_enc_conn_iv(&mut self, conn_id: u32);
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

pub(crate) fn derive_connection_iv(iv: &mut HashMap<u32, Iv>, conn_id: u32){
        let mut id = [0u8; aead::NONCE_LEN];
        codec::put_u32(conn_id, &mut id[..4]);

        id
            .iter_mut()
            .zip(iv.get_mut(&0).unwrap().0.iter_mut())
            .for_each(|(id, iv)| {
                *id ^= *iv;
            });
        iv.insert(conn_id, Iv::copy(&id));
    }

pub struct HeaderProtector{
    key: [u8;16],
    sip_hasher: SipHasher
}

impl HeaderProtector {
    pub fn new(aead_algorithm: &'static aead::Algorithm, secret: &hkdf::Prk) -> Self {

        let mut key= [0; 16];
        let x = secret.expand(&[b"tcpls header protection"],aead_algorithm).unwrap();
        x.fill(&mut key).unwrap();
        Self{
            key,
            sip_hasher: SipHasher::new_with_key(&key),
        }
    }

    /// Adds TCPLS Header Protection.
    ///
    /// `input` must reference the first 16 bytes of encrypted payload
    ///
    /// `header` must reference the header slice of the encrypted TLS record
    #[inline]
    pub fn encrypt_in_place(
        &mut self,
        input: &[u8],
        header: &mut [u8],
    ) -> Result<(), Error> {
       self.xor_in_place(input, header)
    }

    /// Removes QUIC Header Protection.
    ///
    /// `sample` must contain the sample of encrypted payload; see
    /// [Header Protection Sample].
    ///
    /// `first` must reference the first byte of the header, referred to as
    /// `packet[0]` in [Header Protection Application].
    ///
    /// `packet_number` must reference the Packet Number field; this is
    /// `packet[pn_offset:pn_offset+pn_length]` in [Header Protection Application].
    ///
    /// Returns an error without modifying anything if `sample` is not
    /// the correct length (see [Header Protection Sample] and [`Self::sample_len()`]),
    /// or `packet_number` is longer than allowed (see
    /// [Packet Number Encoding and Decoding]).
    ///
    /// Otherwise, `first` and `packet_number` will have the header protection removed.
    ///
    /// [Header Protection Application]: https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.1
    /// [Header Protection Sample]: https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.2
    /// [Packet Number Encoding and Decoding]: https://datatracker.ietf.org/doc/html/rfc9000#section-17.1
    #[inline]
    pub fn decrypt_in_place(
        &mut self,
        input: &[u8],
        header: &mut [u8],
    ) -> Result<(), Error> {
        self.xor_in_place(input, header)
    }

    fn xor_in_place(
        &mut self,
        input: &[u8],
        header: &mut [u8],
    ) -> Result<(), Error> {
        let out = self.sip_hasher.hash(input).to_be_bytes();
        for i in 0..header.len() {
            header[i] ^= out[i];
        }
        Ok(())
    }
}

/// A `MessageEncrypter` which doesn't work.
struct InvalidMessageEncrypter {}

impl MessageEncrypter for InvalidMessageEncrypter {
    fn encrypt(&self, m: BorrowedPlainMessage, seq: u64, connection_id: u32) -> Result<Vec<u8>, Error> {
        Err(Error::EncryptError)
    }

    fn encrypt_zc(&self, msg: BorrowedPlainMessage, seq: u64, conn_id: u32, tcpls_header: StreamFrameHeader) -> Result<Vec<u8>, Error> {
        todo!()
    }

    fn derive_enc_conn_iv(&mut self, conn_id: u32) {

    }
}

/// A `MessageDecrypter` which doesn't work.
struct InvalidMessageDecrypter {}

impl MessageDecrypter for InvalidMessageDecrypter {
    fn decrypt(&self, _m: BorrowedOpaqueMessage, _seq: u64, conn_id: u32) -> Result<PlainMessage, Error> {
        Err(Error::DecryptError)
    }

    fn decrypt_zc(&self, msg: BorrowedOpaqueMessage, seq: u64, conn_id: u32, output: &mut RecvBuf) -> Result<PlainMessage, Error> {
        todo!()
    }

    fn derive_dec_conn_iv(&mut self, stream_id: u32) {

    }
}
