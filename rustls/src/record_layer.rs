use alloc::boxed::Box;
use core::num::NonZeroU64;
use std::collections::hash_map;
use octets::Octets;
use crate::ContentType;
use crate::crypto::cipher::{HeaderProtector, InboundOpaqueMessage, MessageDecrypter, MessageEncrypter};
use crate::error::Error;
#[cfg(feature = "logging")]
use crate::log::trace;
use crate::msgs::message::{InboundPlainMessage, OutboundOpaqueMessage, OutboundPlainMessage};
use crate::recvbuf::{RecvBuf, RecvBufMap};
use crate::tcpls::frame::{Frame, TCPLS_OVERHEAD, TcplsHeader};
use crate::tcpls::stream::{SimpleIdHashMap, StreamMap};

static SEQ_SOFT_LIMIT: u64 = 0x16909E7; //(((2 as f64).powf(24.5) as i64) - 0xFFFF) as u64; //0xffff_ffff_ffff_0000u64;
static SEQ_HARD_LIMIT: u64 = 0x16A09E6; //((2 as f64).powf(24.5) as i64) as u64; //0xffff_ffff_ffff_fffeu64;


#[derive(PartialEq)]
enum DirectionState {
    /// No keying material.
    Invalid,

    /// Keying material present, but not yet in use.
    Prepared,

    /// Keying material in use.
    Active,
}

/// Record layer that tracks decryption and encryption keys.
pub struct RecordLayer {
    message_encrypter: Box<dyn MessageEncrypter>,
    message_decrypter: Box<dyn MessageDecrypter>,

    encrypt_state: DirectionState,
    decrypt_state: DirectionState,
    // id of currently used stream
    conn_in_use: u32,
    next_offset: u64,
    pub streams: StreamMap,
    /*is_handshaking: bool,*/
    has_decrypted: bool,

    pub write_seq_map: WriteSeqMap,
    pub read_seq_map: ReadSeqMap,

    // Message encrypted with other keys may be encountered, so failures
    // should be swallowed by the caller.  This struct tracks the amount
    // of message size this is allowed for.
    trial_decryption_len: Option<usize>,


    early_data_requested: bool,
}

impl RecordLayer {
    /// Create new record layer with no keys.
    pub fn new() -> Self {
        Self {
            message_encrypter: <dyn MessageEncrypter>::invalid(),
            message_decrypter: <dyn MessageDecrypter>::invalid(),
            streams: StreamMap::new(),
            /*is_handshaking: true,*/
            has_decrypted: false,
            write_seq_map: WriteSeqMap::default() ,
            encrypt_state: DirectionState::Invalid,
            decrypt_state: DirectionState::Invalid,
            conn_in_use: 0,
            trial_decryption_len: None,
            read_seq_map: ReadSeqMap::default(),
            early_data_requested: false,
            next_offset: 0,
        }
    }

    /// Decrypt a TLS message.
    ///
    /// `encr` is a decoded message allegedly received from the peer.
    /// If it can be decrypted, its decryption is returned.  Otherwise,
    /// an error is returned.
    pub(crate) fn decrypt_incoming<'a>(
        &mut self,
        encr: InboundOpaqueMessage<'a>,
    ) -> Result<Option<Decrypted<'a>>, Error> {
        if self.decrypt_state != DirectionState::Active {
            return Ok(Some(Decrypted {
                want_close_before_decrypt: false,
                plaintext: encr.into_plain_message(),
            }));
        }

        // Set to `true` if the peer appears to getting close to encrypting
        // too many messages with this key.
        //
        // Perhaps if we send an alert well before their counter wraps, a
        // buggy peer won't make a terrible mistake here?
        //
        // Note that there's no reason to refuse to decrypt: the security
        // failure has already happened.
        let want_close_before_decrypt = 0 == SEQ_SOFT_LIMIT;

        let encrypted_len = encr.payload.len();
        match self
            .message_decrypter
            .decrypt(encr, 0)
        {
            Ok(plaintext) => {
                if !self.has_decrypted {
                    self.has_decrypted = true;
                }
                Ok(Some(Decrypted {
                    want_close_before_decrypt,
                    plaintext,
                }))
            }
            Err(Error::DecryptError) if self.doing_trial_decryption(encrypted_len) => {
                trace!("Dropping undecryptable message after aborted early_data");
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }


    /// Decrypt a TLS message.
    ///
    /// `encr` is a decoded message allegedly received from the peer.
    /// If it can be decrypted, its decryption is returned.  Otherwise,
    /// an error is returned.
    pub(crate) fn decrypt_incoming_tcpls<'a>(
        &mut self,
        encr: InboundOpaqueMessage<'a>,
        recv_map: &'a mut RecvBufMap,
    ) -> Result<Option<Decrypted<'a>>, Error> {
        if self.decrypt_state != DirectionState::Active {
            return Ok(Some(Decrypted {
                want_close_before_decrypt: false,
                plaintext: encr.into_plain_message(),
            }));
        }

        // Set to `true` if the peer appears to getting close to encrypting
        // too many messages with this key.
        //
        // Perhaps if we send an alert well before their counter wraps, a
        // buggy peer won't make a terrible mistake here?
        //
        // Note that there's no reason to refuse to decrypt: the security
        // failure has already happened.
        let read_seq = self.read_seq_map.get_or_create(self.conn_in_use as u64).read_seq;
        let want_close_before_decrypt = read_seq == SEQ_SOFT_LIMIT;

        let encrypted_len = encr.payload.len();
        match self
            .message_decrypter
            .decrypt_tcpls(encr, read_seq, self.conn_in_use)
        {
            Ok(plaintext) => {
                self.read_seq_map.get_or_create(self.conn_in_use as u64).read_seq += 1;
                if plaintext.typ == ContentType::ApplicationData {
                    let mut b = Octets::with_slice_reverse(plaintext.payload);
                    let strm_hdr = Frame::parse(&mut b).unwrap();
                    match strm_hdr {
                        Frame::Stream {
                            length,
                            offset,
                            stream_id, ..
                        } => {
                            let mut recv_stream = recv_map.get_or_create(stream_id as u64, None);
                            if recv_stream.offset != offset {
                                stream_header = strm_hdr;
                                return Ok(None);
                            } else {
                                if recv_stream.capacity() < plaintext.payload.len(){
                                    return Err(Error::BufferTooShort);
                                }
                                recv_stream.clone_buffer(plaintext.payload);
                                recv_stream.offset += length as u64;
                            }
                        },
                        _ => {}
                    };


                }
                if !self.has_decrypted {
                    self.has_decrypted = true;
                }
                Ok(Some(Decrypted {
                    want_close_before_decrypt,
                    plaintext,
                }))
            }
            Err(Error::DecryptError) if self.doing_trial_decryption(encrypted_len) => {
                trace!("Dropping undecryptable message after aborted early_data");
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }

    /// Encrypt a TLS message.
    ///
    /// `plain` is a TLS message we'd like to send.  This function
    /// panics if the requisite keying material hasn't been established yet.
    pub(crate) fn encrypt_outgoing(
        &mut self,
        plain: OutboundPlainMessage,
    ) -> OutboundOpaqueMessage {
        debug_assert!(self.encrypt_state == DirectionState::Active);
        assert!(!self.encrypt_exhausted());
        let stream_id = self.conn_in_use;
        let seq = self.write_seq_map.get_or_create(stream_id as u64).write_seq;
        self.write_seq_map.get_or_create(stream_id as u64).write_seq += 1;
        self.message_encrypter
            .encrypt(plain, seq)
            .unwrap()
    }

    /// Encrypt a TLS message.
    ///
    /// `plain` is a TLS message we'd like to send.  This function
    /// panics if the requisite keying material hasn't been established yet.
    pub(crate) fn encrypt_outgoing_tcpls(
        &mut self,
        plain: OutboundPlainMessage,
        frame_header: Option<Frame>
    ) -> OutboundOpaqueMessage {
        debug_assert!(self.encrypt_state == DirectionState::Active);
        assert!(!self.encrypt_exhausted());
        let conn_id = self.conn_in_use;
        let seq = self.write_seq_map.get_or_create(conn_id as u64).write_seq;
        self.write_seq_map.get_or_create(conn_id as u64).write_seq += 1;
        self.message_encrypter
            .encrypt_tcpls(plain, seq, conn_id, frame_header)
            .unwrap()
    }

    pub fn get_tag_length(&self) -> usize {
        self.message_encrypter.get_tag_length()
    }

    pub fn set_early_data_request(&mut self, early_requested: bool) {
        self.early_data_requested = early_requested;
    }
    pub fn early_data_request(&self) -> bool {
        self.early_data_requested
    }

    /// Prepare to use the given `MessageEncrypter` for future message encryption.
    /// It is not used until you call `start_encrypting`.
    pub(crate) fn prepare_message_encrypter(&mut self, cipher: Box<dyn MessageEncrypter>) {
        self.message_encrypter = cipher;
        self.write_seq_map.reset_write_seq();
        self.encrypt_state = DirectionState::Prepared;
    }

    /// Prepare to use the given `MessageDecrypter` for future message decryption.
    /// It is not used until you call `start_decrypting`.
    pub(crate) fn prepare_message_decrypter(&mut self, cipher: Box<dyn MessageDecrypter>) {
        self.message_decrypter = cipher;
        self.read_seq_map.reset_read_seq();
        self.decrypt_state = DirectionState::Prepared;
    }

    /// Start using the `MessageEncrypter` previously provided to the previous
    /// call to `prepare_message_encrypter`.
    pub(crate) fn start_encrypting(&mut self) {
        debug_assert!(self.encrypt_state == DirectionState::Prepared);
        self.encrypt_state = DirectionState::Active;
    }

    /// Start using the `MessageDecrypter` previously provided to the previous
    /// call to `prepare_message_decrypter`.
    pub(crate) fn start_decrypting(&mut self) {
        debug_assert!(self.decrypt_state == DirectionState::Prepared);
        self.decrypt_state = DirectionState::Active;
    }

    /// Set and start using the given `MessageEncrypter` for future outgoing
    /// message encryption.
    pub(crate) fn set_message_encrypter(&mut self, cipher: Box<dyn MessageEncrypter>) {
        self.prepare_message_encrypter(cipher);
        self.start_encrypting();
    }

    /// Set and start using the given `MessageDecrypter` for future incoming
    /// message decryption.
    pub(crate) fn set_message_decrypter(&mut self, cipher: Box<dyn MessageDecrypter>) {
        self.prepare_message_decrypter(cipher);
        self.start_decrypting();
        self.trial_decryption_len = None;
    }

    /// Set and start using the given `MessageDecrypter` for future incoming
    /// message decryption, and enable "trial decryption" mode for when TLS1.3
    /// 0-RTT is attempted but rejected by the server.
    pub(crate) fn set_message_decrypter_with_trial_decryption(
        &mut self,
        cipher: Box<dyn MessageDecrypter>,
        max_length: usize,
    ) {
        self.prepare_message_decrypter(cipher);
        self.start_decrypting();
        self.trial_decryption_len = Some(max_length);
    }

    pub(crate) fn finish_trial_decryption(&mut self) {
        self.trial_decryption_len = None;
    }

    /// Return true if we are getting close to encrypting too many
    /// messages with our encryption key.
    pub(crate) fn wants_close_before_encrypt(&mut self) -> bool {
        self.write_seq_map.get_or_create(self.conn_in_use as u64).write_seq == SEQ_SOFT_LIMIT
    }

    /// Return true if we outright refuse to do anything with the
    /// encryption key.
    pub(crate) fn encrypt_exhausted(&mut self) -> bool {
        self.write_seq_map.get_or_create(self.conn_in_use as u64).write_seq >= SEQ_HARD_LIMIT
    }

    pub(crate) fn is_encrypting(&self) -> bool {
        self.encrypt_state == DirectionState::Active
    }

    pub(crate) fn is_decrypting(&self) -> bool {
        self.decrypt_state == DirectionState::Active
    }

    /// Return true if we have ever decrypted a message. This is used in place
    /// of checking the read_seq since that will be reset on key updates.
    pub(crate) fn has_decrypted(&self) -> bool {
        self.has_decrypted
    }

    pub(crate) fn write_seq(& self) -> u64 {
        self.write_seq_map.get(self.conn_in_use as u64).write_seq
    }
    ///Get id of TCP connection in use
    pub fn get_conn_id(& self) -> u32 {
        self.conn_in_use
    }
    /// Returns the number of remaining write sequences
    pub(crate) fn remaining_write_seq(&mut self) -> Option<NonZeroU64> {
        SEQ_SOFT_LIMIT
            .checked_sub( self.write_seq_map.get_or_create(self.conn_in_use as u64).write_seq)
            .and_then(NonZeroU64::new)
    }

    pub(crate) fn read_seq(& self) -> u64 {
        self.read_seq_map.get(self.conn_in_use as u64).read_seq
    }

    pub(crate) fn encrypted_len(&self, payload_len: usize) -> usize {
        self.message_encrypter
            .encrypted_payload_len(payload_len)
    }

    fn doing_trial_decryption(&mut self, requested: usize) -> bool {
        match self
            .trial_decryption_len
            .and_then(|value| value.checked_sub(requested))
        {
            Some(remaining) => {
                self.trial_decryption_len = Some(remaining);
                true
            }
            _ => false,
        }
    }

   /* pub(crate) fn set_not_handshaking(&mut self) {
        self.is_handshaking = false;
    }*/

    pub(crate) fn enc_dec_for_connection(&mut self, conn_id: u32) {
        self.conn_in_use = conn_id;
    }
}

/// Result of decryption.
#[derive(Debug)]
pub(crate) struct Decrypted<'a> {
    /// Whether the peer appears to be getting close to encrypting too many messages with this key.
    pub(crate) want_close_before_decrypt: bool,
    /// The decrypted message.
    pub(crate) plaintext: InboundPlainMessage<'a>,
}
#[derive(Default)]
pub(crate) struct WriteSeqMap {
    map: SimpleIdHashMap<WriteSeq>,
}

impl WriteSeqMap {
    pub(crate) fn get_or_create(&mut self, stream_id: u64) -> &mut WriteSeq {
        match self.map.entry(stream_id) {
            hash_map::Entry::Vacant(v) => {
                v.insert(WriteSeq::new(stream_id))
            },
            hash_map::Entry::Occupied(v) => v.into_mut(),
        }
    }

    pub(crate) fn get(&self, stream_id: u64) -> & WriteSeq {
        self.map.get(&stream_id).unwrap()
    }

    pub(crate) fn reset_write_seq(&mut self) {
        for seq in self.map.iter_mut() {
            seq.1.write_seq = 0;
        }
    }

}

#[derive(Default)]
pub(crate) struct ReadSeqMap {
    map: SimpleIdHashMap<ReadSeq>,
}

impl ReadSeqMap {
    pub(crate) fn get_or_create(&mut self, stream_id: u64) -> &mut ReadSeq {
        match self.map.entry(stream_id) {
            hash_map::Entry::Vacant(v) => {
                v.insert(ReadSeq::new(stream_id))
            },
            hash_map::Entry::Occupied(v) => v.into_mut(),
        }
    }

    pub(crate) fn get(&self, stream_id: u64) -> & ReadSeq {
        self.map.get(&stream_id).unwrap()
    }

    pub(crate) fn reset_read_seq(&mut self) {
        for seq in self.map.iter_mut() {
            seq.1.read_seq = 0;
        }
    }

}
#[derive(Default)]
pub(crate) struct WriteSeq {
    id: u64,
    write_seq: u64,
}

impl WriteSeq {
    pub(crate) fn new(id: u64) -> Self {
        Self {
            id,
            write_seq: 0,
        }
    }

}
pub(crate) struct ReadSeq {
    id: u64,
    read_seq: u64,
}

impl ReadSeq {
    pub(crate) fn new(id: u64) -> Self {
        Self {
            id,
            read_seq: 0,
        }
    }

}

#[cfg(test)]
mod tests {
    use std::prelude::v1::Vec;
    use crate::ContentType::ApplicationData;
    use crate::recvbuf::RecvBufMap;
    use super::*;

    #[test]
    fn test_has_decrypted() {
        use crate::{ContentType, ProtocolVersion};

        struct PassThroughDecrypter;
        impl MessageDecrypter for PassThroughDecrypter {
            fn decrypt<'a>(
                &mut self,
                m: InboundOpaqueMessage<'a>,
                _: u64,
            ) -> Result<InboundPlainMessage<'a>, Error> {
                Ok(m.into_plain_message())
            }

            fn decrypt_tcpls<'a, 'b>(&mut self, msg: InboundOpaqueMessage<'a>, seq: u64, conn_id: u32, recv_buf: &'b mut RecvBuf, tcpls_header: &TcplsHeader) -> Result<InboundPlainMessage<'a>, Error> {
                Ok(InboundPlainMessage{
                    version: ProtocolVersion::TLSv1_3,
                    payload: &[],
                    typ: ApplicationData,
                })
            }

        }

        let mut app_buffs = RecvBufMap::new();
        let mut rev_buf = app_buffs.get_or_create(0, None);

        // A record layer starts out invalid, having never decrypted.
        let mut record_layer = RecordLayer::new();
        assert!(matches!(
            record_layer.decrypt_state,
            DirectionState::Invalid
        ));
        assert_eq!(record_layer.read_seq_map.get_or_create(0).read_seq, 0);
        assert!(!record_layer.has_decrypted());

        // Preparing the record layer should update the decrypt state, but shouldn't affect whether it
        // has decrypted.
        record_layer.prepare_message_decrypter(Box::new(PassThroughDecrypter));
        assert!(matches!(
            record_layer.decrypt_state,
            DirectionState::Prepared
        ));
        assert_eq!(record_layer.read_seq_map.get_or_create(0).read_seq, 0);
        assert!(!record_layer.has_decrypted());

        // Starting decryption should update the decrypt state, but not affect whether it has decrypted.
        record_layer.start_decrypting();
        assert!(matches!(record_layer.decrypt_state, DirectionState::Active));
        assert_eq!(record_layer.read_seq_map.get_or_create(0).read_seq, 0);
        assert!(!record_layer.has_decrypted());

        // Decrypting a message should update the read_seq and track that we have now performed
        // a decryption.
        record_layer
            .decrypt_incoming_tcpls(InboundOpaqueMessage::new(
                ContentType::Handshake,
                ProtocolVersion::TLSv1_2,
                &mut [0xC0, 0xFF, 0xEE],
            ), &mut rev_buf)
            .unwrap();
        assert!(matches!(record_layer.decrypt_state, DirectionState::Active));
        assert_eq!(record_layer.read_seq_map.get_or_create(0).read_seq, 1);
        assert!(record_layer.has_decrypted());

        // Resetting the record layer message decrypter (as if a key update occurred) should reset
        // the read_seq number, but not our knowledge of whether we have decrypted previously.
        record_layer.set_message_decrypter(Box::new(PassThroughDecrypter));
        assert!(matches!(record_layer.decrypt_state, DirectionState::Active));
        assert_eq!(record_layer.read_seq_map.get_or_create(0).read_seq, 0);
        assert!(record_layer.has_decrypted());
    }
}