use std::collections::HashMap;
use crate::cipher::{make_nonce, Iv, MessageDecrypter, MessageEncrypter, derive_connection_iv, HeaderProtector};
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
use std::io::Read;
use ring::rand::SecureRandom;
use octets::BufferError;
use crate::recvbuf::RecvBuf;
use crate::tcpls::frame::{TCPLS_HEADER_SIZE, StreamFrameHeader, SAMPLE_PAYLOAD_LENGTH};

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
    header_encrypter: HeaderProtector,
}

struct Tls13MessageDecrypter {
    dec_key: aead::LessSafeKey,
    iv: HashMap<u32, Iv>,
    header_decrypter: HeaderProtector,
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

fn make_tls13_aad_no_header(len: usize) -> ring::aead::Aad<[u8; TLS13_AAD_SIZE]> {
    ring::aead::Aad::from([
        0x17, // ContentType::ApplicationData
        0x3,  // ProtocolVersion (major)
        0x3,  // ProtocolVersion (minor)
        (len >> 8) as u8,
        len as u8,
    ])
}

fn prepare_output(header: & StreamFrameHeader, payload_length: usize) -> Result<Vec<u8>, BufferError> {
    // Prepare output buffer
    let mut output = vec![0; PACKET_OVERHEAD + payload_length];
    let mut b = octets::OctetsMut::with_slice(&mut output);
    //TLS record header
    // Application data
    b.put_u8(0x17)?;
    // TLSv1_2
    b.put_u16(0x0303)?;
    // payload length
    b.put_u16(payload_length as u16)?;
    // TCPLS header
    b.put_u32(header.chunk_num)?;
    b.put_u16(header.offset_step)?;
    b.put_u16(header.stream_id)?;
    Ok(output)
}

fn make_tls13_aad_for_enc(output_buf: &[u8]) -> ring::aead::Aad<[u8; TLS13_AAD_SIZE_WITH_TCPLS_HEADER]> {
    ring::aead::Aad::from([output_buf[0], output_buf[1], output_buf[2], output_buf[3]
        , output_buf[4], output_buf[5], output_buf[6], output_buf[7]
        , output_buf[8], output_buf[9], output_buf[10], output_buf[11]
        , output_buf[12]])
}

fn make_tls13_aad_for_dec(len: usize, header: & StreamFrameHeader ) -> ring::aead::Aad<[u8; TLS13_AAD_SIZE_WITH_TCPLS_HEADER]> {
    ring::aead::Aad::from([0x17, 0x3, 0x3, (len >> 8) as u8
        , len as u8, (header.chunk_num >> 24) as u8 , ( header.chunk_num >> 16) as u8, ( header.chunk_num >> 8) as u8
        , header.chunk_num as u8, (header.offset_step >> 8) as u8, header.offset_step as u8, (header.stream_id >> 8) as u8
        , header.stream_id as u8])
}

// https://datatracker.ietf.org/doc/html/rfc8446#section-5.2
const TLS13_AAD_SIZE: usize = 1 + 2 + 2 ;
const TLS13_AAD_SIZE_WITH_TCPLS_HEADER: usize = 1 + 2 + 2 + TCPLS_HEADER_SIZE;

const TCPLS_HEADER_OFFSET: usize = 5;

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

    fn encrypt_zc(&mut self, msg: BorrowedPlainMessage, seq: u64, conn_id: u32, header: &StreamFrameHeader) -> Result<Vec<u8>, Error> {
        let tag_length =  self.enc_key.algorithm().tag_len();
        let header_protecter = &mut self.header_encrypter;
        let mut payload_len = msg.payload.len() + 1 + tag_length;
        let record_payload_length = payload_len + TCPLS_HEADER_SIZE;
        let mut input = vec![0; payload_len];
        input.extend_from_slice(msg.payload);
        msg.typ.encode(&mut input);

        let nonce = make_nonce(self.iv.get(&conn_id).unwrap(), seq);

       let mut output= prepare_output(&header, record_payload_length).expect("output vector preparation failed");

        let aad = make_tls13_aad_for_enc(output.as_slice());

        self.enc_key
            .seal_in_output_append_tag(nonce, aad, &input, &mut output, PACKET_OVERHEAD + TCPLS_HEADER_SIZE)
            .map_err(|_| Error::General("encrypt failed".to_string()))?;

        // Take the LSBs of calculated tag as input sample for hash function
        let sample = output.rchunks(tag_length).next().unwrap();

        let mut i = TCPLS_HEADER_OFFSET;
        // Calculate hash(sample) XOR header
        for byte in header_protecter.calculate_hash(sample){
            output[i] ^= byte;
            i += 1;
        }


        Ok(output)
    }

    fn derive_enc_conn_iv(&mut self, conn_id: u32) {
        if !self.iv.contains_key(&conn_id){
            derive_connection_iv(&mut self.iv, conn_id);
        }
    }

    fn get_tag_length(&self) -> usize {
        self.enc_key.algorithm().tag_len()
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


    fn decrypt_zc(&self, mut msg: BorrowedOpaqueMessage, seq: u64, conn_id: u32, recv_buf: &mut RecvBuf, tcpls_header: &StreamFrameHeader) -> Result<PlainMessage, Error> {
        let payload = msg.payload;
        if payload.len() < self.dec_key.algorithm().tag_len() {
            return Err(Error::DecryptError);
        }

        let nonce = make_nonce(self.iv.get(&conn_id).unwrap(), seq);
        let aad = make_tls13_aad_for_dec(payload.len(), &tcpls_header);

        // output buffer must be at least as big as the input buffer
        if recv_buf.capacity() < payload.len() {
            return Err(Error::BufferTooShort);
        }

        let plain_len = self
            .dec_key
            .open_in_output(nonce, aad, payload, recv_buf.get_mut())
            .map_err(|_| Error::DecryptError)?
            .len();

        // truncate tag
        for b in &mut recv_buf.get_mut()[plain_len..] {
            *b = 0;
        }

        if recv_buf.get_mut()[..plain_len].len() > MAX_FRAGMENT_LEN + 1 {
            return Err(Error::PeerSentOversizedRecord);
        }


        let mut new_size = 0;
        (msg.typ, new_size)  = unpad_tls13_from_slice(recv_buf.get_mut());

        let payload_len_no_type = recv_buf.get_mut()[..new_size].len();
        
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
                _ => {
                    recv_buf.offset -= recv_buf.get_mut()[..new_size].len() as u64; // reduce offset as non app data will be overwritten
                    Payload::new_from_vec(recv_buf.get_mut()[..new_size].to_vec())
                },
            },
        })
    }

    fn derive_dec_conn_iv(&mut self, conn_id: u32) {
        if !self.iv.contains_key(&conn_id) {
            derive_connection_iv(&mut self.iv, conn_id);
        }
    }

    fn decrypt_header(&mut self, input: &[u8], header: &[u8]) -> Result<[u8; 8], Error> {
        self.header_decrypter.decrypt_in_output(input, header)
    }

}

#[test]
fn test_truncate_tag_unpad_tls13_from_slice() {
    let mut rng = ring::rand::SystemRandom::new();
    let mut array = [0u8;32];
    let zeros = [0u8;11];
    rng.fill(&mut array).unwrap();
    array[20] = ContentType::ApplicationData.get_u8();

    for b in &mut array[21..] {
        *b = 0;
    }

    let mut new_size = 0;
    let mut typ = ContentType::ChangeCipherSpec;
    (typ, new_size)  = unpad_tls13_from_slice(&mut array);

    assert_eq!(typ, ContentType::ApplicationData);
    assert_eq!(new_size , 20);
    assert_eq!(zeros, array[21..])

}