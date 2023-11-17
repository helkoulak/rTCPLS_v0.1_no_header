use std::collections::hash_map;
use crate::cipher::{MessageDecrypter, MessageEncrypter};
use crate::error::Error;
use crate::msgs::message::{BorrowedOpaqueMessage, BorrowedPlainMessage, PlainMessage};

#[cfg(feature = "logging")]
use crate::log::trace;
use crate::recvbuf::RecvBuf;
use crate::tcpls::frame::{Frame, TcplsHeader};
use crate::tcpls::stream::{DEFAULT_STREAM_ID, SimpleIdHashMap, StreamMap};

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
    stream_in_use: u16,
    is_handshaking: bool,
    // Message encrypted with other keys may be encountered, so failures
    // should be swallowed by the caller.  This struct tracks the amount
    // of message size this is allowed for.
    trial_decryption_len: Option<usize>,

    pub streams: StreamMap,
}

impl RecordLayer {
    /// Create new record layer with no keys.
    pub fn new() -> Self {
        Self {
            message_encrypter: <dyn MessageEncrypter>::invalid(),
            message_decrypter: <dyn MessageDecrypter>::invalid(),
            encrypt_state: DirectionState::Invalid,
            decrypt_state: DirectionState::Invalid,
            stream_in_use: 0,
            is_handshaking: true,
            trial_decryption_len: None,
            streams: StreamMap::new(),
        }
    }

    pub(crate) fn is_encrypting(&self) -> bool {
        self.encrypt_state == DirectionState::Active
    }

    pub(crate) fn set_not_handshaking(&mut self) {
        self.is_handshaking = false;
    }

    #[cfg(feature = "secret_extraction")]
    pub(crate) fn write_seq(&self) -> u64 {
        self.seq_map.as_ref(DEFAULT_STREAM_ID).write_seq
    }

    #[cfg(feature = "secret_extraction")]
    pub(crate) fn read_seq(&self) -> u64 {
        self.seq_map.as_ref(DEFAULT_STREAM_ID).read_seq
    }

    pub(crate) fn encrypt_for_stream(&mut self, stream_id: u16) {
        self.stream_in_use = stream_id;
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

    /// Prepare to use the given `MessageEncrypter` for future message encryption.
    /// It is not used until you call `start_encrypting`.
    pub(crate) fn prepare_message_encrypter(&mut self, cipher: Box<dyn MessageEncrypter>) {
        self.message_encrypter = cipher;
        self.encrypt_state = DirectionState::Prepared;
    }

    /// Prepare to use the given `MessageDecrypter` for future message decryption.
    /// It is not used until you call `start_decrypting`.
    pub(crate) fn prepare_message_decrypter(&mut self, cipher: Box<dyn MessageDecrypter>) {
        self.message_decrypter = cipher;
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
    pub(crate) fn wants_close_before_encrypt(&self) -> bool {
        self.streams.get(self.stream_in_use).unwrap().write_seq == SEQ_SOFT_LIMIT
    }

    /// Return true if we outright refuse to do anything with the
    /// encryption key.
    pub(crate) fn encrypt_exhausted(&self) -> bool {
        self.streams.get(self.stream_in_use).unwrap().write_seq >= SEQ_HARD_LIMIT
    }

    /*pub fn create_new_seq_space(&mut self, stream_id: u16) {
        self.seq_map.create_new_seq_space(stream_id);
    }*/

    pub fn get_stream_in_use(& self) -> u16 {
        self.stream_in_use
    }

    pub fn decrypt_header(&mut self, input: &[u8], header: & [u8]) -> Result<[u8; 8], Error> {
        self.message_decrypter.decrypt_header(input, header)
    }

    pub fn get_tag_length(&self) -> usize {
        self.message_encrypter.get_tag_length()
    }



    /// Decrypt a TLS message.
    ///
    /// `encr` is a decoded message allegedly received from the peer.
    /// If it can be decrypted, its decryption is returned.  Otherwise,
    /// an error is returned.
    pub(crate) fn decrypt_incoming_zc(
        &mut self,
        encr: BorrowedOpaqueMessage,
        recv_buf: &mut RecvBuf,
        tcpls_header: &TcplsHeader,
    ) -> Result<Option<Decrypted>, Error> {
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

        let stream_id = tcpls_header.stream_id;
        let want_close_before_decrypt = recv_buf.read_seq == SEQ_SOFT_LIMIT;

        let encrypted_len = encr.payload.len();

        match self
            .message_decrypter
            .decrypt_zc(encr, recv_buf.read_seq, stream_id as u32, recv_buf, &tcpls_header)
        {
            Ok(plaintext) => {
                recv_buf.read_seq += 1;
                if recv_buf.id > 0 {
                    recv_buf.next_recv_pkt_num += 1;
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

    pub(crate) fn encrypt_outgoing_zc(&mut self, plain: BorrowedPlainMessage, tcpls_header: &TcplsHeader, frame_header: Option<Frame>) -> Vec<u8> {
        debug_assert!(self.encrypt_state == DirectionState::Active);
        assert!(!self.encrypt_exhausted());
        let stream_id = self.stream_in_use;
        let seq = self.streams.get(stream_id).unwrap().write_seq;
        self.streams.get_mut(stream_id).unwrap().write_seq += 1;

        self.message_encrypter
            .encrypt_zc(plain, seq, stream_id as u32, tcpls_header, frame_header)
            .unwrap()
    }

}

    /*/// The sequence number space for an open tcp connection
    #[derive(Default)]
    pub(crate) struct RecSeqNumSpace {
        stream_id: u16,
        write_seq: u64,
        read_seq: u64,
    }*/

    /*impl RecSeqNumSpace {
        pub(crate)  fn new(stream_id: u16) -> Self {
            Self{
                stream_id,
                ..Default::default()
            }

        }

    }


    /// The sequence number space for all open tcp connections
    #[derive(Default)]
    pub(crate) struct RecSeqNumMap{
        seq_num_map: SimpleIdHashMap<RecSeqNumSpace>,
    }
    impl RecSeqNumMap {
        /// Calling new creates the first seq num space along with the establishment of TLS session
        pub(crate) fn new() -> Self {
            let mut map = SimpleIdHashMap::default();
            let seq = RecSeqNumSpace::new(DEFAULT_STREAM_ID);
            map.insert(DEFAULT_STREAM_ID as u64, seq);
            Self {
                seq_num_map: map,
            }
        }

        pub(crate) fn get_or_create(&mut self, stream_id: u16) -> &mut RecSeqNumSpace {
            match self.seq_num_map.entry(stream_id as u64) {
                hash_map::Entry::Vacant(v) => {
                    v.insert(RecSeqNumSpace::new(stream_id))
                },
                hash_map::Entry::Occupied(v) => v.into_mut(),
            }
        }

        /// Creates a new sequence space or do nothing if already exists
        pub(crate) fn create_new_seq_space(&mut self, stream_id: u16) {
           if !self.seq_num_map.contains_key(&(stream_id as u64)){
               self.seq_num_map.insert(stream_id as u64, RecSeqNumSpace::new(stream_id));
           }
        }

        pub(crate) fn as_ref(&self, stream_id: u16) -> & RecSeqNumSpace {
            match self.seq_num_map.get(&(stream_id as u64)) {
                Some(seq_space) => seq_space,
                None => panic!("sequence space not found"),
            }
        }

        pub(crate) fn as_mut_ref(&mut self, stream_id: u16) -> &mut RecSeqNumSpace {
            match self.seq_num_map.get_mut(&(stream_id as u64)) {
                Some(seq_space) => seq_space,
                None => panic!("sequence space not found"),
            }
        }

    }*/

/// Result of decryption.
#[derive(Debug)]
pub struct Decrypted {
    /// Whether the peer appears to be getting close to encrypting too many messages with this key.
    pub want_close_before_decrypt: bool,
    /// The decrypted message.
    pub plaintext: PlainMessage,
}