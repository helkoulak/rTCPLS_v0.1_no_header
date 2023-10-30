use std::collections::HashMap;
use crate::cipher::{make_nonce, Iv, MessageDecrypter, MessageEncrypter, derive_stream_iv, HeaderProtector};
use crate::enums::ContentType;
use crate::enums::{CipherSuite, ProtocolVersion};
use crate::error::{Error, PeerMisbehaved};
use crate::msgs::base::Payload;
use crate::msgs::codec::Codec;
use crate::msgs::fragmenter::{MAX_FRAGMENT_LEN, PACKET_OVERHEAD};
use crate::msgs::message::{BorrowedOpaqueMessage, BorrowedPlainMessage, PlainMessage};
use crate::suites::{BulkAlgorithm, CipherSuiteCommon, SupportedCipherSuite};

use ring::aead;

use std::fmt;
use crate::recvbuf::RecvBuf;
use crate::tcpls::frame::{TCPLS_HEADER_SIZE, StreamFrameHeader, TCPLS_MINIMUM_PAYLOAD_LENGTH};

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
    header_protector: Option<HeaderProtector>,
}

struct Tls13MessageDecrypter {
    dec_key: aead::LessSafeKey,
    iv: HashMap<u32, Iv>,
    header_protector: Option<HeaderProtector>,
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

fn unpad_tls13_from_slice(v: &mut [u8]) -> (ContentType, usize) {
    let mut last = v.len() - 1;
    loop {
        match v[last] {
            0 => last -= 1,
            content_type => {
                let typ = ContentType::from(content_type);
                v[last] = 0x00;
                return (typ, last)
            },
            _ => return (ContentType::Unknown(0), last),
        }
    }
}

fn make_tls13_aad_no_header(len: usize) -> ring::aead::Aad<[u8; TLS13_AAD_SIZE_NO_HEADER]> {
    ring::aead::Aad::from([
        0x17, // ContentType::ApplicationData
        0x3,  // ProtocolVersion (major)
        0x3,  // ProtocolVersion (minor)
        (len >> 8) as u8,
        len as u8,
        0x04,
    ])
}

fn prepare_output(header: & StreamFrameHeader, payload_length: usize) -> Vec<u8> {
    // Prepare output buffer
    let mut output = vec![0; PACKET_OVERHEAD + payload_length];
    // Application data
    output[0] = 0x17;
    // TLSv1_2
    output[1] = ((0x0303 >> 8) & 0xFF) as u8;
    output[2] = (0x0303 & 0xFF) as u8;
    // payload length
    output[3] = ((payload_length as u16 >> 8) & 0xFF) as u8;
    output[4] = (payload_length as u16 & 0xFF) as u8;
    // TCPLS header
    output[5] = header.typ;
    output[6] = ((header.length >> 8) & 0xFF) as u8;
    output[7] = (header.length & 0xFF) as u8;
    output[8] = ((header.offset >> 56) & 0xFF) as u8;
    output[9] = ((header.offset >> 48) & 0xFF) as u8;
    output[10] = ((header.offset >> 40) & 0xFF) as u8;
    output[11] = ((header.offset >> 32) & 0xFF) as u8;
    output[12] = ((header.offset >> 24) & 0xFF) as u8;
    output[13] = ((header.offset >> 16) & 0xFF) as u8;
    output[14] = ((header.offset >> 8) & 0xFF) as u8;
    output[15] = (header.offset  & 0xFF) as u8;
    output[16] = ((header.stream_id >> 8) & 0xFF) as u8;
    output[17] = (header.stream_id  & 0xFF) as u8;
    output
}

fn make_tls13_aad(header: &[u8]) -> ring::aead::Aad<[u8; TLS13_AAD_SIZE]> {
    ring::aead::Aad::from([header[0], header[1], header[2], header[3]
        , header[4], header[5], header[6], header[7]
        , header[8], header[9], header[10], header[11]
        , header[12], header[13], header[14], header[15]
        , header[16], header[17]])
}

// https://datatracker.ietf.org/doc/html/rfc8446#section-5.2
const TLS13_AAD_SIZE_NO_HEADER: usize = 1 + 2 + 2 + 1;
const TLS13_AAD_SIZE: usize = 1 + 2 + 2 + TCPLS_HEADER_SIZE;

impl MessageEncrypter for Tls13MessageEncrypter {
    fn encrypt(&self, m: BorrowedPlainMessage, seq: u64, stream_id: u32) -> Result<Vec<u8>, Error> {
        let mut payload_len = m.payload.len() + 1 + self.enc_key.algorithm().tag_len();
        let record_payload_length = payload_len + 1;
        let mut input = vec![0; payload_len];
        input.extend_from_slice(m.payload);
        m.typ.encode(&mut input);
        let nonce = make_nonce(self.iv.get(&stream_id).unwrap(), seq);

        let aad = make_tls13_aad_no_header(record_payload_length);

        // Prepare output buffer
        let mut output = vec![0; PACKET_OVERHEAD + record_payload_length];
        // Application data
        output[0] = 0x17;
        // TLSv1_2
        output[1] = ((0x0303 >> 8) & 0xFF) as u8;
        output[2] = (0x0303 & 0xFF) as u8;
        // payload length
        output[3] = (((record_payload_length) as u16 >> 8) & 0xFF) as u8;
        output[4] = ((record_payload_length) as u16 & 0xFF) as u8;
        // TCPLS header
        output[5] = 0x04;

        self.enc_key
            .seal_in_output_append_tag(nonce, aad, &input, &mut output, PACKET_OVERHEAD)
            .map_err(|_| Error::General("encrypt failed".to_string()))?;

        //Randomize tcpls header
        output[5] ^= output[6];

        Ok(output)
    }

    fn encrypt_zc(&self, msg: BorrowedPlainMessage, seq: u64, stream_id: u32, header: StreamFrameHeader) -> Result<Vec<u8>, Error> {
        // Impose a minimum length for payload to increase entropy for header protection hash function
        let padding_bytes = match  msg.payload.len() < TCPLS_MINIMUM_PAYLOAD_LENGTH {
            true => TCPLS_MINIMUM_PAYLOAD_LENGTH - msg.payload.len(),
            false => 0,
        };
        let mut payload_len = msg.payload.len() + padding_bytes + 1 + self.enc_key.algorithm().tag_len();
        let record_payload_length = payload_len + TCPLS_HEADER_SIZE;
        let mut input = vec![0; payload_len];
        input.extend_from_slice(msg.payload);
        msg.typ.encode(&mut input);
        if padding_bytes != 0 {
            input.extend_from_slice(vec![0;padding_bytes].as_slice());
        }

        let nonce = make_nonce(self.iv.get(&stream_id).unwrap(), seq);

       let mut output= prepare_output(&header, record_payload_length);

        let aad = make_tls13_aad(output.as_slice());


        self.enc_key
            .seal_in_output_append_tag(nonce, aad, &input, &mut output, PACKET_OVERHEAD + TCPLS_HEADER_SIZE)
            .map_err(|_| Error::General("encrypt failed".to_string()))?;

        // Take the first 16 bytes of encrypted input as input for hash function
        self.header_protector.unwrap().encrypt_in_place(&output[18..34], &mut output[5..18])?;

        Ok(output)
    }

    fn derive_enc_stream_iv(&mut self, stream_id: u32) {
        if !self.iv.contains_key(&stream_id){
            derive_stream_iv(&mut self.iv, stream_id);
        }
    }

}

impl MessageDecrypter for Tls13MessageDecrypter {
    fn decrypt(&self, mut msg: BorrowedOpaqueMessage, seq: u64, stream_id: u32) -> Result<PlainMessage, Error> {
        let payload = msg.payload;
        if payload.len() < self.dec_key.algorithm().tag_len() {
            return Err(Error::DecryptError);
        }

        let nonce = make_nonce(self.iv.get(&stream_id).unwrap(), seq);
        let aad = make_tls13_aad_no_header(payload.len());

        let mut output = &mut vec![0; payload.len()];

        let plain_len = self
            .dec_key
            .open_in_output(nonce, aad, payload,   output)
            .map_err(|_| Error::DecryptError)?
            .len();



       output.truncate(plain_len);


        if output.len() > MAX_FRAGMENT_LEN  + 1 {
            return Err(Error::PeerSentOversizedRecord);
        }

        msg.typ = unpad_tls13(output);

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
            payload: Payload::new(output.as_slice()),
        })
    }


    fn decrypt_zc(&self, mut msg: BorrowedOpaqueMessage, seq: u64, stream_id: u32, recv_buf: &mut RecvBuf) -> Result<PlainMessage, Error> {
        let payload = msg.payload;
        if payload.len() < self.dec_key.algorithm().tag_len() {
            return Err(Error::DecryptError);
        }

        let nonce = make_nonce(self.iv.get(&stream_id).unwrap(), seq);
        let aad = make_tls13_aad_no_header(payload.len());

        let mut output = recv_buf.get_mut();

        // output buffer must be at least as big as the input buffer
        if output.len() < payload.len() {
            return Err(Error::BufferTooShort);
        }

        let plain_len = self
            .dec_key
            .open_in_output(nonce, aad, payload, output)
            .map_err(|_| Error::DecryptError)?
            .len();

        // truncate tag
        for b in &mut output[plain_len.. plain_len + self.dec_key.algorithm().tag_len()] {
            *b = 0;
        }

        if output[..plain_len].len() > MAX_FRAGMENT_LEN + 1 {
            return Err(Error::PeerSentOversizedRecord);
        }


        let mut new_size = 0;
        (msg.typ, new_size)  = unpad_tls13_from_slice(output);

        let payload_len_no_type = output[..new_size].len();
        
        if msg.typ == ContentType::Unknown(0) {
            return Err(PeerMisbehaved::IllegalTlsInnerPlaintext.into());
        }

        if payload_len_no_type > MAX_FRAGMENT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }

        Ok(PlainMessage {
            typ: msg.typ,
            version: ProtocolVersion::TLSv1_3,
            payload: match msg.typ {
                ContentType::ApplicationData => Payload::new(Vec::new()),
                _ => Payload::new_from_vec(output[..new_size].to_vec()),

            },
        })
    }

    fn derive_dec_stream_iv(&mut self, stream_id: u32) {
        if !self.iv.contains_key(&stream_id) {
            derive_stream_iv(&mut self.iv, stream_id);
        }
    }

}
