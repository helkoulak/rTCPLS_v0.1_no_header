use std::collections::hash_map;
use crate::cipher::{MessageDecrypter, MessageEncrypter};
use crate::error::Error;
use crate::msgs::message::{BorrowedOpaqueMessage, BorrowedPlainMessage, PlainMessage};

#[cfg(feature = "logging")]
use crate::log::trace;
use crate::recvbuf::RecvBuf;
use crate::tcpls::frame::StreamFrameHeader;
use crate::tcpls::stream::SimpleIdHashMap;

static SEQ_SOFT_LIMIT: u64 = 0xffff_ffff_ffff_0000u64;
static SEQ_HARD_LIMIT: u64 = 0xffff_ffff_ffff_fffeu64;

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
    seq_map: RecSeqNumMap,
    encrypt_state: DirectionState,
    decrypt_state: DirectionState,
    /// id of currently used stream
    stream_in_use: u64,

    is_handshaking: bool,

    // Message encrypted with other keys may be encountered, so failures
    // should be swallowed by the caller.  This struct tracks the amount
    // of message size this is allowed for.
    trial_decryption_len: Option<usize>,
}

impl RecordLayer {
    /// Create new record layer with no keys.
    pub fn new() -> Self {
        Self {
            message_encrypter: <dyn MessageEncrypter>::invalid(),
            message_decrypter: <dyn MessageDecrypter>::invalid(),
            seq_map: RecSeqNumMap::new(),
            encrypt_state: DirectionState::Invalid,
            decrypt_state: DirectionState::Invalid,
            stream_in_use: 0,
            is_handshaking: true,
            trial_decryption_len: None,
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
        self.seq_map.as_ref(self.stream_in_use as u32).write_seq
    }

    #[cfg(feature = "secret_extraction")]
    pub(crate) fn read_seq(&self) -> u64 {
        self.seq_map.as_ref(self.stream_in_use as u32).read_seq
    }

    pub(crate) fn set_stream_in_use(&mut self, stream_id: u64) {
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
        let stream_id = self.stream_in_use;
        self.message_encrypter = cipher;
        self.seq_map.get_or_create(stream_id as u32).write_seq = 0;
        self.encrypt_state = DirectionState::Prepared;
    }

    /// Prepare to use the given `MessageDecrypter` for future message decryption.
    /// It is not used until you call `start_decrypting`.
    pub(crate) fn prepare_message_decrypter(&mut self, cipher: Box<dyn MessageDecrypter>) {
        let stream_id = self.stream_in_use;
        self.message_decrypter = cipher;
        self.seq_map.get_or_create(stream_id as u32).read_seq = 0;
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
        self.seq_map.as_ref(self.stream_in_use as u32).write_seq == SEQ_SOFT_LIMIT
    }

    /// Return true if we outright refuse to do anything with the
    /// encryption key.
    pub(crate) fn encrypt_exhausted(&self) -> bool {
        self.seq_map.as_ref(self.stream_in_use as u32).write_seq >= SEQ_HARD_LIMIT
    }

    pub(crate) fn create_new_seq_space(&mut self, stream_id: u32) {
        self.seq_map.create_new_seq_space(stream_id);
    }

    pub fn get_stream_in_use(& self) -> u64 {
        self.stream_in_use
    }

    /// Decrypt a TLS message.
    ///
    /// `encr` is a decoded message allegedly received from the peer.
    /// If it can be decrypted, its decryption is returned.  Otherwise,
    /// an error is returned.
    pub(crate) fn decrypt_incoming(
        &mut self,
        encr: BorrowedOpaqueMessage,
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

        let stream_id = self.stream_in_use;
        let want_close_before_decrypt = self.seq_map.seq_num_map.get(&stream_id).unwrap().read_seq == SEQ_SOFT_LIMIT;


        let encrypted_len = encr.payload.len();

        /// prepare crypto context for the specified stream
        /// if IV already exists for the specified stream, the function does nothing
        if !self.is_handshaking && stream_id != 0 {
            self.message_decrypter.derive_dec_stream_iv(stream_id as u32);
        }
        match self
            .message_decrypter
            .decrypt(encr, self.seq_map.seq_num_map.get(&stream_id).unwrap().read_seq, stream_id as u32)
        {
            Ok(plaintext) => {
                self.seq_map.seq_num_map.get_mut(&stream_id).unwrap().read_seq += 1;
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
    pub(crate) fn decrypt_incoming_zc(
        &mut self,
        encr: BorrowedOpaqueMessage,
        recv_buf: &mut RecvBuf,
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

        let stream_id = self.stream_in_use;
        let want_close_before_decrypt = self.seq_map.seq_num_map.get(&stream_id).unwrap().read_seq == SEQ_SOFT_LIMIT;


        let encrypted_len = encr.payload.len();

        /// prepare crypto context for the specified connection
        /// if IV already exists for the specified connection, the function does nothing
        if !self.is_handshaking && stream_id != 0 {
            self.message_decrypter.derive_dec_stream_iv(stream_id as u32);
        }
        match self
            .message_decrypter
            .decrypt_zc(encr, self.seq_map.seq_num_map.get(&stream_id).unwrap().read_seq, stream_id as u32, recv_buf)
        {
            Ok(plaintext) => {
                self.seq_map.seq_num_map.get_mut(&stream_id).unwrap().read_seq += 1;
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
    pub(crate) fn encrypt_outgoing(&mut self, plain: BorrowedPlainMessage) -> Vec<u8> {
        debug_assert!(self.encrypt_state == DirectionState::Active);
        assert!(!self.encrypt_exhausted());
        let stream_id = self.stream_in_use;
        let seq = self.seq_map.seq_num_map.get(&stream_id).unwrap().write_seq;
        self.seq_map.seq_num_map.get_mut(&stream_id).unwrap().write_seq += 1;
        /// prepare crypto context for the specified connection
        if !self.is_handshaking && stream_id != 0 {
            self.message_encrypter.derive_enc_stream_iv(stream_id as u32);
        }
        self.message_encrypter
            .encrypt(plain, seq, stream_id as u32)
            .unwrap()
    }


    pub(crate) fn encrypt_outgoing_app_data(&mut self, plain: BorrowedPlainMessage, tcpls_header: StreamFrameHeader) -> Vec<u8> {
        debug_assert!(self.encrypt_state == DirectionState::Active);
        assert!(!self.encrypt_exhausted());
        let stream_id = self.stream_in_use;
        let seq = self.seq_map.seq_num_map.get(&stream_id).unwrap().write_seq;
        self.seq_map.seq_num_map.get_mut(&stream_id).unwrap().write_seq += 1;
        /// prepare crypto context for the specified connection
        if !self.is_handshaking && stream_id != 0 {
            self.message_encrypter.derive_enc_stream_iv(stream_id as u32);
        }
        self.message_encrypter
            .encrypt_app_data(plain, seq, stream_id as u32, tcpls_header)
            .unwrap()
    }

}

    /// The sequence number space for an open tcp connection
    pub(crate) struct RecSeqNumSpace {
        stream_id: u32,
        write_seq: u64,
        read_seq: u64,
    }

    impl RecSeqNumSpace {
        pub(crate)  fn new(stream_id: u32) -> Self {
            Self{
                stream_id,
                read_seq: 0,
                write_seq: 0,
            }

        }

    }


    /// The sequence number space for all open tcp connections
    #[derive(Default)]
    pub(crate) struct RecSeqNumMap{
        seq_num_map: SimpleIdHashMap<RecSeqNumSpace>,
    }
    impl RecSeqNumMap {
        pub(crate) fn new() -> RecSeqNumMap {
            RecSeqNumMap {
                ..Default::default()
            }
        }

        pub(crate) fn get_or_create(&mut self, stream_id: u32) -> &mut RecSeqNumSpace {
            match self.seq_num_map.entry(stream_id as u64) {
                hash_map::Entry::Vacant(v) => {
                    v.insert(RecSeqNumSpace::new(stream_id))
                },
                hash_map::Entry::Occupied(v) => v.into_mut(),
            }
        }

        /// Creates a new sequence space or do nothing if already exists
        pub(crate) fn create_new_seq_space(&mut self, stream_id: u32) {
           if !self.seq_num_map.contains_key(&(stream_id as u64)){
               self.seq_num_map.insert(stream_id as u64, RecSeqNumSpace::new(stream_id));
           }
        }

        pub(crate) fn as_ref(&self, stream_id: u32) -> & RecSeqNumSpace {
            match self.seq_num_map.get(&(stream_id as u64)) {
                Some(seq_space) => seq_space,
                None => panic!("sequence space not found"),
            }
        }

    }

/// Result of decryption.
#[derive(Debug)]
pub struct Decrypted {
    /// Whether the peer appears to be getting close to encrypting too many messages with this key.
    pub want_close_before_decrypt: bool,
    /// The decrypted message.
    pub plaintext: PlainMessage,
}