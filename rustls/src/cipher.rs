#![allow(missing_docs)]


use std::collections::HashMap;

use crate::error::Error;
use crate::msgs::codec;
use crate::msgs::message::{BorrowedOpaqueMessage, BorrowedPlainMessage, PlainMessage};

use ring::{aead, hkdf};

use siphasher::sip128::SipHasher;
use crate::recvbuf::RecvBuf;
use crate::tcpls::frame::StreamFrameHeader;




/// Objects with this trait can decrypt TLS messages.
pub trait MessageDecrypter: Send + Sync {
    /// Perform the decryption over the concerned TLS message.

    fn decrypt(&self, m: BorrowedOpaqueMessage, seq: u64, connection_id: u32) -> Result<PlainMessage, Error>;
   fn decrypt_zc(&self, msg: BorrowedOpaqueMessage, seq: u64, conn_id: u32, recv_buf: &mut RecvBuf) -> Result<PlainMessage, Error>;
    fn derive_dec_stream_iv(&mut self, conn_id: u32);
}

/// Objects with this trait can encrypt TLS messages.
pub(crate) trait MessageEncrypter: Send + Sync {
    fn encrypt(&self, m: BorrowedPlainMessage, seq: u64, connection_id: u32) -> Result<Vec<u8>, Error>;
    fn encrypt_app_data(&self, msg: BorrowedPlainMessage, seq: u64, conn_id: u32, tcpls_header: StreamFrameHeader) -> Result<Vec<u8>, Error>;
    fn derive_enc_stream_iv(&mut self, conn_id: u32);
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

pub(crate) fn derive_stream_iv(iv: &mut HashMap<u32, Iv>, stream_id: u32){
        let mut id = [0u8; aead::NONCE_LEN];
        codec::put_u32(stream_id, &mut id[..4]);

        id
            .iter_mut()
            .zip(iv.get_mut(&0).unwrap().0.iter_mut())
            .for_each(|(id, iv)| {
                *id ^= *iv;
            });
        iv.insert(stream_id, Iv::copy(&id));
    }

pub struct HeaderProtector{
    key: [u8;16],
    sip_hasher128: SipHasher
}

impl HeaderProtector {
    pub fn new(aead_algorithm: &'static aead::Algorithm, secret: &hkdf::Prk) -> Self {

        let mut key= [0; 16];
        let x = secret.expand(&[b"tcpls header protection"],aead_algorithm).unwrap();
        x.fill(&mut key).unwrap();
        Self{
            key,
            sip_hasher128: SipHasher::new_with_key(&key),
        }
    }

    /// Adds QUIC Header Protection.
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
    /// or `packet_number` is longer than allowed (see [Packet Number Encoding and Decoding]).
    ///
    /// Otherwise, `first` and `packet_number` will have the header protection added.
    ///
    /// [Header Protection Application]: https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.1
    /// [Header Protection Sample]: https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.2
    /// [Packet Number Encoding and Decoding]: https://datatracker.ietf.org/doc/html/rfc9000#section-17.1
    #[inline]
    pub fn encrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        self.xor_in_place(sample, first, packet_number, false)
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
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        self.xor_in_place(sample, first, packet_number, true)
    }

    fn xor_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
        masked: bool,
    ) -> Result<(), Error> {
        // This implements [Header Protection Application] almost verbatim.

        let mask = self
            .0
            .new_mask(sample)
            .map_err(|_| Error::General("sample of invalid length".into()))?;

        // The `unwrap()` will not panic because `new_mask` returns a
        // non-empty result.
        let (first_mask, pn_mask) = mask.split_first().unwrap();

        // It is OK for the `mask` to be longer than `packet_number`,
        // but a valid `packet_number` will never be longer than `mask`.
        if packet_number.len() > pn_mask.len() {
            return Err(Error::General("packet number too long".into()));
        }

        // Infallible from this point on. Before this point, `first` and
        // `packet_number` are unchanged.

        const LONG_HEADER_FORM: u8 = 0x80;
        let bits = match *first & LONG_HEADER_FORM == LONG_HEADER_FORM {
            true => 0x0f,  // Long header: 4 bits masked
            false => 0x1f, // Short header: 5 bits masked
        };

        let first_plain = match masked {
            // When unmasking, use the packet length bits after unmasking
            true => *first ^ (first_mask & bits),
            // When masking, use the packet length bits before masking
            false => *first,
        };
        let pn_len = (first_plain & 0x03) as usize + 1;

        *first ^= first_mask & bits;
        for (dst, m) in packet_number
            .iter_mut()
            .zip(pn_mask)
            .take(pn_len)
        {
            *dst ^= m;
        }

        Ok(())
    }

    /// Expected sample length for the key's algorithm
    #[inline]
    pub fn sample_len(&self) -> usize {
        self.0.algorithm().sample_len()
    }
}

/// A `MessageEncrypter` which doesn't work.
struct InvalidMessageEncrypter {}

impl MessageEncrypter for InvalidMessageEncrypter {
    fn encrypt(&self, m: BorrowedPlainMessage, seq: u64, connection_id: u32) -> Result<Vec<u8>, Error> {
        Err(Error::EncryptError)
    }

    fn encrypt_app_data(&self, msg: BorrowedPlainMessage, seq: u64, conn_id: u32, tcpls_header: StreamFrameHeader) -> Result<Vec<u8>, Error> {
        todo!()
    }

    fn derive_enc_stream_iv(&mut self, conn_id: u32) {

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

    fn derive_dec_stream_iv(&mut self, stream_id: u32) {

    }
}
