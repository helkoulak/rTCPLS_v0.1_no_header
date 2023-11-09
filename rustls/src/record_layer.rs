use std::collections::hash_map;
use crate::cipher::{MessageDecrypter, MessageEncrypter};
use crate::error::Error;
use crate::msgs::message::{BorrowedOpaqueMessage, BorrowedPlainMessage, PlainMessage};

#[cfg(feature = "logging")]
use crate::log::trace;
use crate::recvbuf::RecvBuf;
use crate::tcpls::frame::StreamFrameHeader;
use crate::tcpls::stream::SimpleIdHashMap;

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
    seq_map: RecSeqNumMap,
    encrypt_state: DirectionState,
    decrypt_state: DirectionState,
    // id of currently used tcp connection
    conn_in_use: u32,
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
            conn_in_use: 0,
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
        self.seq_map.as_ref(self.conn_in_use).write_seq
    }

    #[cfg(feature = "secret_extraction")]
    pub(crate) fn read_seq(&self) -> u64 {
        self.seq_map.as_ref(self.conn_in_use).read_seq
    }

    pub(crate) fn set_conn_in_use(&mut self, conn_id: u32) {
        self.conn_in_use = conn_id;
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
        let conn_id = self.conn_in_use;
        self.message_encrypter = cipher;
        self.seq_map.as_mut_ref(conn_id).write_seq = 0;
        self.encrypt_state = DirectionState::Prepared;
    }

    /// Prepare to use the given `MessageDecrypter` for future message decryption.
    /// It is not used until you call `start_decrypting`.
    pub(crate) fn prepare_message_decrypter(&mut self, cipher: Box<dyn MessageDecrypter>) {
        let conn_id = self.conn_in_use;
        self.message_decrypter = cipher;
        self.seq_map.as_mut_ref(conn_id).read_seq = 0;
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
        self.seq_map.as_ref(self.conn_in_use).write_seq == SEQ_SOFT_LIMIT
    }

    /// Return true if we outright refuse to do anything with the
    /// encryption key.
    pub(crate) fn encrypt_exhausted(&self) -> bool {
        self.seq_map.as_ref(self.conn_in_use).write_seq >= SEQ_HARD_LIMIT
    }

    pub fn create_new_seq_space(&mut self, conn_id: u32) {
        self.seq_map.create_new_seq_space(conn_id);
    }

    pub fn get_conn_in_use(& self) -> u32 {
        self.conn_in_use
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

        let conn_id = self.conn_in_use;
        let want_close_before_decrypt = self.seq_map.as_ref(conn_id).read_seq == SEQ_SOFT_LIMIT;


        let encrypted_len = encr.payload.len();

        /// prepare crypto context for the specified tcp connection
        /// if IV already exists for the specified tcp connection, the function does nothing
        if !self.is_handshaking && conn_id != 0 {
            self.message_decrypter.derive_dec_conn_iv(conn_id);
        }
        match self
            .message_decrypter
            .decrypt(encr, self.seq_map.as_ref(conn_id).read_seq, conn_id)
        {
            Ok(plaintext) => {
                self.seq_map.as_mut_ref(conn_id).read_seq += 1;
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
        tcpls_header: &StreamFrameHeader,
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

        //TODO accordingly decryption of TCPLS header should happen at this point not before to avoid unnecessary processing
        // in case data is already in plaintext
        let conn_id = self.conn_in_use;
        let want_close_before_decrypt = self.seq_map.as_ref(conn_id).read_seq == SEQ_SOFT_LIMIT;


        let encrypted_len = encr.payload.len();

        /// prepare crypto context for the specified connection
        /// if IV already exists for the specified connection, the function does nothing
        if !self.is_handshaking && conn_id != 0 {
            self.message_decrypter.derive_dec_conn_iv(conn_id);
        }
        match self
            .message_decrypter
            .decrypt_zc(encr, self.seq_map.as_ref(conn_id).read_seq, conn_id, recv_buf, &tcpls_header)
        {
            Ok(plaintext) => {
                self.seq_map.as_mut_ref(conn_id).read_seq += 1;
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

    /// Encrypt a TLS message.
    ///
    /// `plain` is a TLS message we'd like to send.  This function
    /// panics if the requisite keying material hasn't been established yet.
    pub(crate) fn encrypt_outgoing(&mut self, plain: BorrowedPlainMessage) -> Vec<u8> {
        debug_assert!(self.encrypt_state == DirectionState::Active);
        assert!(!self.encrypt_exhausted());
        let conn_id = self.conn_in_use;
        let seq = self.seq_map.as_ref(conn_id).write_seq;
        self.seq_map.as_mut_ref(conn_id).write_seq += 1;
        /// prepare crypto context for the specified connection
        if !self.is_handshaking && conn_id != 0 {
            self.message_encrypter.derive_enc_conn_iv(conn_id);
        }
        self.message_encrypter
            .encrypt(plain, seq, conn_id)
            .unwrap()
    }


    pub(crate) fn encrypt_outgoing_zc(&mut self, plain: BorrowedPlainMessage, tcpls_header: &StreamFrameHeader) -> Vec<u8> {
        debug_assert!(self.encrypt_state == DirectionState::Active);
        assert!(!self.encrypt_exhausted());
        let conn_id = self.conn_in_use;
        let seq = self.seq_map.as_ref(conn_id).write_seq;
        self.seq_map.as_mut_ref(conn_id).write_seq += 1;
        /// prepare crypto context for the specified connection
        if !self.is_handshaking && conn_id != 0 {
            self.message_encrypter.derive_enc_conn_iv(conn_id);
        }
        self.message_encrypter
            .encrypt_zc(plain, seq, conn_id, tcpls_header)
            .unwrap()
    }

}

    /// The sequence number space for an open tcp connection
    #[derive(Default)]
    pub(crate) struct RecSeqNumSpace {
        connection_id: u32,
        write_seq: u64,
        read_seq: u64,
    }

    impl RecSeqNumSpace {
        pub(crate)  fn new(conn_id: u32) -> Self {
            Self{
                connection_id: conn_id,
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
            let seq = RecSeqNumSpace::new(0);
            map.insert(0, seq);
            Self {
                seq_num_map: map,
            }
        }

        pub(crate) fn get_or_create(&mut self, conn_id: u32) -> &mut RecSeqNumSpace {
            match self.seq_num_map.entry(conn_id as u64) {
                hash_map::Entry::Vacant(v) => {
                    v.insert(RecSeqNumSpace::new(conn_id))
                },
                hash_map::Entry::Occupied(v) => v.into_mut(),
            }
        }

        /// Creates a new sequence space or do nothing if already exists
        pub(crate) fn create_new_seq_space(&mut self, conn_id: u32) {
           if !self.seq_num_map.contains_key(&(conn_id as u64)){
               self.seq_num_map.insert(conn_id as u64, RecSeqNumSpace::new(conn_id));
           }
        }

        pub(crate) fn as_ref(&self, conn_id: u32) -> & RecSeqNumSpace {
            match self.seq_num_map.get(&(conn_id as u64)) {
                Some(seq_space) => seq_space,
                None => panic!("sequence space not found"),
            }
        }

        pub(crate) fn as_mut_ref(&mut self, conn_id: u32) -> &mut RecSeqNumSpace {
            match self.seq_num_map.get_mut(&(conn_id as u64)) {
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