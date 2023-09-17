use std::arch::asm;
use std::collections::HashMap;
use crate::cipher::{make_nonce, Iv, MessageDecrypter, MessageEncrypter, derive_connection_iv};
use crate::enums::ContentType;
use crate::enums::{CipherSuite, ProtocolVersion};
use crate::error::{Error, PeerMisbehaved};
use crate::msgs::base::Payload;
use crate::msgs::codec::Codec;
use crate::msgs::fragmenter::MAX_FRAGMENT_LEN;
use crate::msgs::message::{BorrowedOpaqueMessage, BorrowedPlainMessage, OpaqueMessage, PlainMessage};
use crate::suites::{BulkAlgorithm, CipherSuiteCommon, SupportedCipherSuite};

use ring::aead;

use std::fmt;
use crate::tcpls::frame::{TCPLS_STREAM_FRAME_MAX_OVERHEAD, StreamFrameHeader};

pub(crate) mod key_schedule;

/// The TLS1.3 ciphersuite TLS_CHACHA20_POLY1305_SHA256
pub static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(TLS13_CHACHA20_POLY1305_SHA256_INTERNAL);

pub(crate) static TLS13_CHACHA20_POLY1305_SHA256_INTERNAL: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        bulk: BulkAlgorithm::Chacha20Poly1305,
        aead_algorithm: &ring::aead::CHACHA20_POLY1305,
    },
    hkdf_algorithm: ring::hkdf::HKDF_SHA256,
    #[cfg(feature = "quic")]
    confidentiality_limit: u64::MAX,
    #[cfg(feature = "quic")]
    integrity_limit: 1 << 36,
};

/// The TLS1.3 ciphersuite TLS_AES_256_GCM_SHA384
pub static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
            bulk: BulkAlgorithm::Aes256Gcm,
            aead_algorithm: &ring::aead::AES_256_GCM,
        },
        hkdf_algorithm: ring::hkdf::HKDF_SHA384,
        #[cfg(feature = "quic")]
        confidentiality_limit: 1 << 23,
        #[cfg(feature = "quic")]
        integrity_limit: 1 << 52,
    });

/// The TLS1.3 ciphersuite TLS_AES_128_GCM_SHA256
pub static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(TLS13_AES_128_GCM_SHA256_INTERNAL);

pub(crate) static TLS13_AES_128_GCM_SHA256_INTERNAL: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
        bulk: BulkAlgorithm::Aes128Gcm,
        aead_algorithm: &ring::aead::AES_128_GCM,
    },
    hkdf_algorithm: ring::hkdf::HKDF_SHA256,
    #[cfg(feature = "quic")]
    confidentiality_limit: 1 << 23,
    #[cfg(feature = "quic")]
    integrity_limit: 1 << 52,
};

/// A TLS 1.3 cipher suite supported by rustls.
pub struct Tls13CipherSuite {
    /// Common cipher suite fields.
    pub common: CipherSuiteCommon,
    pub(crate) hkdf_algorithm: ring::hkdf::Algorithm,
    #[cfg(feature = "quic")]
    pub(crate) confidentiality_limit: u64,
    #[cfg(feature = "quic")]
    pub(crate) integrity_limit: u64,
}

impl Tls13CipherSuite {
    /// Which hash function to use with this suite.
    pub fn hash_algorithm(&self) -> &'static ring::digest::Algorithm {
        self.hkdf_algorithm
            .hmac_algorithm()
            .digest_algorithm()
    }

    /// Can a session using suite self resume from suite prev?
    pub fn can_resume_from(&self, prev: &'static Self) -> Option<&'static Self> {
        (prev.hash_algorithm() == self.hash_algorithm()).then(|| prev)
    }
}

impl From<&'static Tls13CipherSuite> for SupportedCipherSuite {
    fn from(s: &'static Tls13CipherSuite) -> Self {
        Self::Tls13(s)
    }
}

impl PartialEq for Tls13CipherSuite {
    fn eq(&self, other: &Self) -> bool {
        self.common.suite == other.common.suite
    }
}

impl fmt::Debug for Tls13CipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tls13CipherSuite")
            .field("suite", &self.common.suite)
            .field("bulk", &self.common.bulk)
            .finish()
    }
}

struct Tls13MessageEncrypter {
    enc_key: aead::LessSafeKey,
    iv: HashMap<u32, Iv>,
}

struct Tls13MessageDecrypter {
    dec_key: aead::LessSafeKey,
    iv: HashMap<u32, Iv>,
}

fn unpad_tls13(v: &mut Vec<u8>) -> ContentType {
    loop {
        match v.pop() {
            Some(0) => {}
            Some(content_type) => return ContentType::from(content_type),
            None => return ContentType::Unknown(0),
        }
    }
}

fn make_tls13_aad(len: usize) -> ring::aead::Aad<[u8; TLS13_AAD_SIZE]> {
    ring::aead::Aad::from([
        0x17, // ContentType::ApplicationData
        0x3,  // ProtocolVersion (major)
        0x3,  // ProtocolVersion (minor)
        (len >> 8) as u8,
        len as u8,
    ])
}

// https://datatracker.ietf.org/doc/html/rfc8446#section-5.2
const TLS13_AAD_SIZE: usize = 1 + 2 + 2;

impl MessageEncrypter for Tls13MessageEncrypter {
    fn encrypt(&self, msg: BorrowedPlainMessage, seq: u64, conn_id: u32) -> Result<OpaqueMessage, Error> {
        let mut payload;
        let mut total_len = msg.payload.len() + 1 + self.enc_key.algorithm().tag_len();
        match msg.typ {
            ContentType::ApplicationData => {
                let header_len = msg.stream_header.as_ref().unwrap().get_header_length();
                total_len += header_len;
                payload = Vec::with_capacity(total_len);
                payload.extend_from_slice(msg.payload);
                payload.extend_from_slice(vec![0; header_len].as_slice());
                let mut octets = octets::OctetsMut::with_slice_at_offset(&mut payload, msg.payload.len());
                msg.stream_header.unwrap().encode_stream_header(&mut octets).expect("encoding stream header failed");

            }
            _ => {
                payload = Vec::with_capacity(total_len);
                payload.extend_from_slice(msg.payload);
            }
        }

        msg.typ.encode(&mut payload);

        let nonce = make_nonce(self.iv.get(&conn_id).unwrap(), seq);
        let aad = make_tls13_aad(total_len);

        self.enc_key
            .seal_in_place_append_tag(nonce, aad, &mut payload)
            .map_err(|_| Error::General("encrypt failed".to_string()))?;

        Ok(OpaqueMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_2,
            payload: Payload::new(payload),
        })
    }

    fn derive_enc_connection_iv(&mut self, conn_id: u32) {
        if !self.iv.contains_key(&conn_id){
            derive_connection_iv(&mut self.iv, conn_id);
        }
    }

}

impl MessageDecrypter for Tls13MessageDecrypter {
    fn decrypt(&self, mut msg: BorrowedOpaqueMessage, seq: u64, conn_id: u32) -> Result<PlainMessage, Error> {
        let payload = msg.payload;
        if payload.len() < self.dec_key.algorithm().tag_len() {
            return Err(Error::DecryptError);
        }

        let nonce = make_nonce(self.iv.get(&conn_id).unwrap(), seq);
        let aad = make_tls13_aad(payload.len());
         let mut output= vec![0; payload.len()];


        let plain_len = self
            .dec_key
            .open_in_output(nonce, aad, payload,  &mut output)
            .map_err(|_| Error::DecryptError)?
            .len();

        output.truncate(plain_len);

        if output.len() > MAX_FRAGMENT_LEN + TCPLS_STREAM_FRAME_MAX_OVERHEAD + 1 {
            return Err(Error::PeerSentOversizedRecord);
        }

        msg.typ = unpad_tls13(&mut output);
        // strip TCPLS stream frame header if applicable
        if msg.typ == ContentType::ApplicationData {
            let mut b = octets::Octets::with_slice_reverse(& output);
            let header_size = StreamFrameHeader::get_header_size_reverse(&mut b);
            output.truncate(plain_len - header_size - 1);
        }
        if msg.typ == ContentType::Unknown(0) {
            return Err(PeerMisbehaved::IllegalTlsInnerPlaintext.into());
        }

        if output.len() > MAX_FRAGMENT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }

        msg.version = ProtocolVersion::TLSv1_3;
        Ok(PlainMessage{
            typ: msg.typ,
            version: msg.version,
            payload: Payload(output),
        })
    }

    fn derive_dec_connection_iv(&mut self, conn_id: u32) {
        if !self.iv.contains_key(&conn_id) {
            derive_connection_iv(&mut self.iv, conn_id);
        }
    }

}
