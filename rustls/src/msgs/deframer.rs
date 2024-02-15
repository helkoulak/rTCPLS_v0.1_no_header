
use std::collections::{BTreeMap, hash_map};
use std::io;
use std::ops::Range;

use super::base::Payload;
use super::codec::Codec;
use super::message::{MAX_WIRE_SIZE, PlainMessage};
use crate::enums::{ContentType, ProtocolVersion};
use crate::error::{Error, InvalidMessage, PeerMisbehaved};
use crate::msgs::codec;
use crate::msgs::message::{BorrowedOpaqueMessage, MessageError};
use crate::record_layer::{Decrypted, RecordLayer};
use crate::recvbuf::{RecvBuf, RecvBufMap};
use crate::tcpls::frame::{TcplsHeader, TCPLS_HEADER_SIZE};
use crate::tcpls::stream::SimpleIdHashMap;


/// This deframer works to reconstruct TLS messages from a stream of arbitrary-sized reads.
///
/// It buffers incoming data into a `Vec` through `read()`, and returns messages through `pop()`.
/// QUIC connections will call `push()` to append handshake payload data directly.
#[derive(Default)]
pub struct MessageDeframer {

    /// Id of active TCP connection
    id: u64,

    /// Set if the peer is not talking TLS, but some other
    /// protocol.  The caller should abort the connection, because
    /// the deframer cannot recover.
    last_error: Option<Error>,

    /// Buffer of data read from the socket, in the process of being parsed into messages.
    ///
    /// For buffer size management, checkout out the `read()` method.
    buf: Vec<u8>,

    /// If we're in the middle of joining a handshake payload, this is the metadata.
    joining_hs: Option<HandshakePayloadMeta>,

    /// What size prefix of `buf` is used.
    used: usize,

    /// Info of records delivered
    pub(crate) record_info: BTreeMap<u64, RangeBufInfo>,

    /// Range of offsets of processed data in deframer buffer.
    /// Contiguous range of bytes will be discarded if >= DISCARD_THRESHOLD
    pub(crate) processed_range: Range<u64>,
}

impl MessageDeframer {
    pub fn new(id: u64) -> MessageDeframer {
        MessageDeframer{
            id,
            ..Default::default()
        }
    }


        /// Return any decrypted messages that the deframer has been able to parse.
    ///
    /// Returns an `Error` if the deframer failed to parse some message contents or if decryption
    /// failed, `Ok(None)` if no full message is buffered or if trial decryption failed, and
    /// `Ok(Some(_))` if a valid message was found and decrypted successfully.
    pub fn pop(&mut self, record_layer: &mut RecordLayer, app_buffers: &mut RecvBufMap) -> Result<Option<Deframed>, Error> {
        if let Some(last_err) = self.last_error.clone() {
            return Err(last_err);
        } else if self.used == 0 {
            return Ok(None);
        }
        let mut start = 0;
        let tag_len = record_layer.get_tag_length();
        let mut header_decoded = TcplsHeader::default();
        let mut payload_offset = 0;
        let mut payload_length = 0;
        let mut end = 0;
        let mut recv_buf = &mut RecvBuf::default();

        // We loop over records we've received but not processed yet.
        // For records that decrypt as `Handshake`, we keep the current state of the joined
        // handshake message payload in `self.joining_hs`, appending to it as we see records.
        let expected_len = loop {
            start = match &self.joining_hs {
                Some(meta) => {
                    match meta.expected_len {
                        // We're joining a handshake payload, and we've seen the full payload.
                        Some(len) if len <= meta.payload.len() => break len,
                        // Not enough data, and we can't parse any more out of the buffer (QUIC).
                        _ if meta.quic => return Ok(None),
                        // Try parsing some more of the encrypted buffered data.
                        _ => meta.message.end,
                    }
                }
                None => {
                        if !self.record_info.is_empty(){
                            for (offset, info) in self.record_info.iter() {
                                if (app_buffers.get_or_create_recv_buffer(info.id as u64, None).next_recv_pkt_num == info.chunk_num && !info.processed) {
                                    end = *offset as usize;
                                    break
                                }
                                else {
                                    end = *offset as usize + info.len;
                                    continue
                                }
                            }
                        }
                    end
                },
            };


                // Does our `buf` contain a full message?  It does if it is big enough to
                // contain a header, and that header has a length which falls within `buf`.
                // If so, deframe it and place the message onto the frames output queue.
                let mut rd = codec::Reader::init(&self.buf[start..self.used]);
                let m = match BorrowedOpaqueMessage::read(&mut rd) {
                    Ok((ct, ver, offset, len)) => {
                        payload_offset = start + offset;
                        payload_length = len;
                        BorrowedOpaqueMessage {
                            typ: ct,
                            version: ver,
                            payload: & self.buf[payload_offset..payload_offset + payload_length],
                        }
                    },
                    Err(msg_err) => {
                        let err_kind = match msg_err {
                            MessageError::TooShortForHeader | MessageError::TooShortForLength => {
                                return Ok(None)
                            }
                            MessageError::InvalidEmptyPayload => InvalidMessage::InvalidEmptyPayload,
                            MessageError::MessageTooLarge => InvalidMessage::MessageTooLarge,
                            MessageError::InvalidContentType => InvalidMessage::InvalidContentType,
                            MessageError::UnknownProtocolVersion => {
                                InvalidMessage::UnknownProtocolVersion
                            }
                        };

                        return Err(self.set_err(err_kind));
                    }
                };


            // If we're in the middle of joining a handshake payload and the next message is not of
                // type handshake, yield an error. Return CCS messages immediately without decrypting.
                end = start + rd.used();
                if m.typ == ContentType::ChangeCipherSpec && self.joining_hs.is_none() {
                    // This is unencrypted. We check the contents later.
                    let plain = m.into_plain_message();
                    self.discard(start, (end - start));
                    return Ok(Some(Deframed {
                        want_close_before_decrypt: false,
                        aligned: true,
                        trial_decryption_finished: false,
                        message: plain,
                    }));
                }

            // Consider header protection in case dec/enc state is active
            if tag_len != 0 {
                // Take the LSBs of calculated tag as input sample for hash function
                let sample = m.payload.rchunks(tag_len).next().unwrap();
                // Decode tcpls header and choose recv_buf accordingly
                header_decoded =
                    TcplsHeader::decode_tcpls_header_from_slice(
                        &record_layer.decrypt_header(sample, &m.payload[..TCPLS_HEADER_SIZE]).expect("decrypting header failed")
                    );
            }
            if m.typ != ContentType::Handshake {
                self.record_info.insert(start as u64, RangeBufInfo::from(header_decoded.chunk_num, header_decoded.stream_id, end - start));
            }
            recv_buf = app_buffers.get_or_create_recv_buffer(header_decoded.stream_id as u64, None);

                if recv_buf.next_recv_pkt_num != header_decoded.chunk_num {
                    continue
                }


            // Decrypt the encrypted message (if necessary).
            let msg = match record_layer.decrypt_incoming_zc(m, recv_buf, &header_decoded) {
                Ok(Some(decrypted)) => {
                    let Decrypted {
                        want_close_before_decrypt,
                        plaintext,
                    } = decrypted;
                    debug_assert!(!want_close_before_decrypt);
                    plaintext
                }
                // This was rejected early data, discard it. If we currently have a handshake
                // payload in progress, this counts as interleaved, so we error out.
                Ok(None) if self.joining_hs.is_some() => {
                    return Err(self.set_err(
                        PeerMisbehaved::RejectedEarlyDataInterleavedWithHandshakeMessage,
                    ));
                }
                Ok(None) => {
                    self.discard(start, (end - start));
                    continue;
                }
                Err(e) => return Err(e),
            };
            if msg.typ == ContentType::Handshake && !self.record_info.is_empty(){
                self.record_info.remove(&(start as u64));
            }

            if self.joining_hs.is_some() && msg.typ != ContentType::Handshake {
                // "Handshake messages MUST NOT be interleaved with other record
                // types.  That is, if a handshake message is split over two or more
                // records, there MUST NOT be any other records between them."
                // https://www.rfc-editor.org/rfc/rfc8446#section-5.1
                return Err(self.set_err(PeerMisbehaved::MessageInterleavedWithHandshakeMessage));
            }

            // If it's not a handshake message, just return it -- no joining necessary.
            if msg.typ != ContentType::Handshake {
                if msg.typ == ContentType::ApplicationData {
                    app_buffers.insert_readable(record_layer.get_stream_in_use() as u64);
                }

                self.record_info.get_mut(&(start as u64)).unwrap().processed = true;
                match self.calculate_discard_range() {
                   true =>
                       self.discard(self.processed_range.start as usize,
                                    (self.processed_range.end - self.processed_range.start) as usize),
                    false => (),
                };
                //
                return Ok(Some(Deframed {
                    want_close_before_decrypt: false,
                    aligned: true,
                    trial_decryption_finished: false,
                    message: msg,
                }));
            }

            // If we don't know the payload size yet or if the payload size is larger
            // than the currently buffered payload, we need to wait for more data.
            match self.append_hs(msg.version, &msg.payload.0, end, false)? {
                HandshakePayloadState::Blocked => return Ok(None),
                HandshakePayloadState::Complete(len) => break len,
                HandshakePayloadState::Continue => continue,
            }
        };

        let meta = self.joining_hs.as_mut().unwrap(); // safe after calling `append_hs()`

        // We can now wrap the complete handshake payload in a `PlainMessage`, to be returned.
        let message = PlainMessage {
            typ: ContentType::Handshake,
            version: meta.version,
            payload: Payload::new(&self.buf[meta.payload.start..meta.payload.start + expected_len]),
        };

        // But before we return, update the `joining_hs` state to skip past this payload.
        if meta.payload.len() > expected_len {
            // If we have another (beginning of) a handshake payload left in the buffer, update
            // the payload start to point past the payload we're about to yield, and update the
            // `expected_len` to match the state of that remaining payload.
            meta.payload.start += expected_len;
            meta.expected_len = payload_size(&self.buf[meta.payload.start..meta.payload.end])?;
        } else {
            // Otherwise, we've yielded the last handshake payload in the buffer, so we can
            // discard all of the bytes that we're previously buffered as handshake data.
            let end = meta.message.end;
            self.joining_hs = None;
            self.discard(start, (end - start));
        }

        Ok(Some(Deframed {
            want_close_before_decrypt: false,
            aligned: self.joining_hs.is_none(),
            trial_decryption_finished: true,
             message,
        }))
    }



    /// Fuses this deframer's error and returns the set value.
    ///
    /// Any future calls to `pop` will return `err` again.
    fn set_err(&mut self, err: impl Into<Error>) -> Error {
        let err = err.into();
        self.last_error = Some(err.clone());
        err
    }

    /// Allow pushing handshake messages directly into the buffer.
    #[cfg(feature = "quic")]
    pub fn push(&mut self, version: ProtocolVersion, payload: &[u8]) -> Result<(), Error> {
        if self.used > 0 && self.joining_hs.is_none() {
            return Err(Error::General(
                "cannot push QUIC messages into unrelated connection".into(),
            ));
        } else if let Err(err) = self.prepare_read() {
            return Err(Error::General(err.into()));
        }

        let end = self.used + payload.len();
        self.append_hs(version, payload, end, true)?;
        self.used = end;
        Ok(())
    }

    /// Write the handshake message contents into the buffer and update the metadata.
    ///
    /// Returns true if a complete message is found.
    fn append_hs(
        &mut self,
        version: ProtocolVersion,
        payload: &[u8],
        end: usize,
        quic: bool,
    ) -> Result<HandshakePayloadState, Error> {
        let meta = match &mut self.joining_hs {
            Some(meta) => {
                debug_assert_eq!(meta.quic, quic);

                // We're joining a handshake message to the previous one here.
                // Write it into the buffer and update the metadata.

                let dst = &mut self.buf[meta.payload.end..meta.payload.end + payload.len()];
                dst.copy_from_slice(payload);
                meta.message.end = end;
                meta.payload.end += payload.len();

                // If we haven't parsed the payload size yet, try to do so now.
                if meta.expected_len.is_none() {
                    meta.expected_len =
                        payload_size(&self.buf[meta.payload.start..meta.payload.end])?;
                }

                meta
            }
            None => {
                // We've found a new handshake message here.
                // Write it into the buffer and create the metadata.

                let expected_len = payload_size(payload)?;
                let dst = &mut self.buf[..payload.len()];
                dst.copy_from_slice(payload);
                self.joining_hs
                    .insert(HandshakePayloadMeta {
                        message: Range { start: 0, end },
                        payload: Range {
                            start: 0,
                            end: payload.len(),
                        },
                        version,
                        expected_len,
                        quic,
                    })
            }
        };

        Ok(match meta.expected_len {
            Some(len) if len <= meta.payload.len() => HandshakePayloadState::Complete(len),
            _ => match self.used > meta.message.end {
                true => HandshakePayloadState::Continue,
                false => HandshakePayloadState::Blocked,
            },
        })
    }

    /// Read some bytes from `rd`, and add them to our internal buffer.
    #[allow(clippy::comparison_chain)]
    pub fn read(&mut self, rd: &mut dyn io::Read) -> io::Result<usize> {
        if let Err(err) = self.prepare_read() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, err));
        }

        // Try to do the largest reads possible. Note that if
        // we get a message with a length field out of range here,
        // we do a zero length read.  That looks like an EOF to
        // the next layer up, which is fine.
        let new_bytes = rd.read(&mut self.buf[self.used..])?;
        self.used += new_bytes;
        Ok(new_bytes)
    }

    pub fn bytes_to_read(& self) -> usize {
        self.used
    }

    /// Resize the internal `buf` if necessary for reading more bytes.
    fn prepare_read(&mut self) -> Result<(), &'static str> {
        // We allow a maximum of 64k of buffered data for handshake messages only. Enforce this
        // by varying the maximum allowed buffer size here based on whether a prefix of a
        // handshake payload is currently being buffered. Given that the first read of such a
        // payload will only ever be 4k bytes, the next time we come around here we allow a
        // larger buffer size. Once the large message and any following handshake messages in
        // the same flight have been consumed, `pop()` will call `discard()` to reset `used`.
        // At this point, the buffer resizing logic below should reduce the buffer size.
        let allow_max = match self.joining_hs {
            Some(_) => MAX_HANDSHAKE_SIZE as usize,
            None => MAX_WIRE_SIZE,
        };

        if self.used >= allow_max {
            return Err("message buffer full");
        }

        // If we can and need to increase the buffer size to allow a 4k read, do so. After
        // dealing with a large handshake message (exceeding `OpaqueMessage::MAX_WIRE_SIZE`),
        // make sure to reduce the buffer size again (large messages should be rare).
        // Also, reduce the buffer size if there are neither full nor partial messages in it,
        // which usually means that the other side suspended sending data.
        let need_capacity = Ord::min(allow_max, self.used + READ_SIZE);
        if need_capacity > self.buf.len() {
            self.buf.resize(need_capacity, 0);
        } else if self.used == 0 || self.buf.len() > allow_max {
            self.buf.resize(need_capacity, 0);
            self.buf.shrink_to(need_capacity);
        }

        Ok(())
    }

    /// Returns true if we have messages for the caller
    /// to process, either whole messages in our output
    /// queue or partial messages in our buffer.
    pub fn has_pending(&self) -> bool {
        self.used > 0
    }

    /// Calculate range where data was processed and can be discarded.
    /// Contiguous data range grows to the left or right depending on adjacent processed records.
    /// Range will only be saved in self.processed_range if range >= DISCARD_THRESHOLD.
    pub fn calculate_discard_range(&mut self) -> bool{
        let mut contiguous = true;
        while contiguous {
            for (offset, info) in self.record_info.iter() {
                let entry_start = *offset;
                let entry_end = *offset + info.len as u64;
                if info.processed {
                    // Initiate range with first processed entry found and build upon
                    if self.processed_range.start == 0 && self.processed_range.end == 0 {
                        self.processed_range.start = entry_start;
                        self.processed_range.end = entry_end;
                    }
                    // expand to the right
                    if entry_start == self.processed_range.end  {
                        self.processed_range.end = entry_end;
                     }
                    // expand to the left
                    if (entry_end == self.processed_range.start) {
                        self.processed_range.start = entry_start;
                    }
                }
            }
            contiguous = false;
        }
        if !((self.processed_range.end - self.processed_range.start) >= DISCARD_THRESHOLD as u64) {
            self.processed_range.end = 0;
            self.processed_range.start = 0;
            false
        }else { true }
    }

    /// Discard `taken` bytes from the start of our buffer.
    pub fn discard(&mut self, start: usize, taken: usize) {
        let mut new_record_info: BTreeMap<u64, RangeBufInfo > = BTreeMap::new();
        let mut next_start = 0;
        #[allow(clippy::comparison_chain)]
        if taken < self.used {
            /* Before:
             * +----------+----------+----------+
             * | taken    | pending  |xxxxxxxxxx|
             * +----------+----------+----------+
             * 0          ^ taken    ^ self.used
             *
             * After:
             * +----------+----------+----------+
             * | pending  |xxxxxxxxxxxxxxxxxxxxx|
             * +----------+----------+----------+
             * 0          ^ self.used
             */
            // If the last record stored in buffer was consumed
            if (start + taken) == self.used {
                self.used = start;
            } else {
                self.buf
                    .copy_within(start + taken..self.used, start);
                self.used -= taken;
            }

        } else if taken == self.used {
            self.used = 0;
        }
        // Build a new record_info BTreeMap excluding the discarded range
        for entry in self.record_info.iter()
            .filter(|&(key, info)| *key < self.processed_range.start || *key >= self.processed_range.end) {
            if *entry.0 == self.processed_range.end {
                new_record_info.insert(self.processed_range.start, RangeBufInfo{
                    chunk_num: entry.1.chunk_num,
                    len: entry.1.len,
                    id: entry.1.id,
                    processed: entry.1.processed,
                });
                next_start = self.processed_range.start + entry.1.len as u64;
                continue
            }

            if *entry.0 > self.processed_range.end {
                new_record_info.insert(next_start, RangeBufInfo{
                    chunk_num: entry.1.chunk_num,
                    len: entry.1.len,
                    id: entry.1.id,
                    processed: entry.1.processed,
                });
                next_start += entry.1.len as u64;
                continue
            }
            new_record_info.insert(*entry.0, RangeBufInfo{
                chunk_num: entry.1.chunk_num,
                len: entry.1.len,
                id: entry.1.id,
                processed: entry.1.processed,
            });
        }
        self.record_info = new_record_info;
        self.processed_range.start = 0;
        self.processed_range.end   = 0;
    }
}

#[derive(Default)]
pub struct MessageDeframerMap {
    deframers: SimpleIdHashMap<MessageDeframer>,
}

impl MessageDeframerMap {
    pub fn new() -> MessageDeframerMap {
        MessageDeframerMap {
            ..Default::default()
        }
    }

    pub(crate) fn get_or_create_deframer(&mut self, conn_id: u64) -> &mut MessageDeframer {
        match self.deframers.entry(conn_id) {
            hash_map::Entry::Vacant(v) => {
                v.insert(MessageDeframer::new(conn_id))
            },
            hash_map::Entry::Occupied(v) => v.into_mut(),
        }
    }


}

enum HandshakePayloadState {
    /// Waiting for more data.
    Blocked,
    /// We have a complete handshake message.
    Complete(usize),
    /// More records available for processing.
    Continue,
}

struct HandshakePayloadMeta {
    /// The range of bytes from the deframer buffer that contains data processed so far.
    ///
    /// This will need to be discarded as the last of the handshake message is `pop()`ped.
    message: Range<usize>,
    /// The range of bytes from the deframer buffer that contains payload.
    payload: Range<usize>,
    /// The protocol version as found in the decrypted handshake message.
    version: ProtocolVersion,
    /// The expected size of the handshake payload, if available.
    ///
    /// If the received payload exceeds 4 bytes (the handshake payload header), we update
    /// `expected_len` to contain the payload length as advertised (at most 16_777_215 bytes).
    expected_len: Option<usize>,
    /// True if this is a QUIC handshake message.
    ///
    /// In the case of QUIC, we get a plaintext handshake data directly from the CRYPTO stream,
    /// so there's no need to unwrap and decrypt the outer TLS record. This is implemented
    /// by directly calling `MessageDeframer::push()` from the connection.
    quic: bool,
}

/// Determine the expected length of the payload as advertised in the header.
///
/// Returns `Err` if the advertised length is larger than what we want to accept
/// (`MAX_HANDSHAKE_SIZE`), `Ok(None)` if the buffer is too small to contain a complete header,
/// and `Ok(Some(len))` otherwise.
fn payload_size(buf: &[u8]) -> Result<Option<usize>, Error> {
    if buf.len() < HEADER_SIZE {
        return Ok(None);
    }

    let (header, _) = buf.split_at(HEADER_SIZE);
    match codec::u24::read_bytes(&header[1..]) {
        Ok(len) if len.0 > MAX_HANDSHAKE_SIZE => Err(Error::InvalidMessage(
            InvalidMessage::HandshakePayloadTooLarge,
        )),
        Ok(len) => Ok(Some(HEADER_SIZE + usize::from(len))),
        _ => Ok(None),
    }
}

#[derive(Clone, Debug, Default)]
pub struct RangeBufInfo {
    /// The id of the stream this record belongs to
    pub(crate) id: u16,

    /// The chunk number of record.
    pub(crate) chunk_num: u32,

    /// Length of chunk
    pub(crate) len: usize,

    /// If record already processed
    pub(crate) processed: bool,
}

impl RangeBufInfo {
    pub fn from(chunk_num: u32, id: u16, len: usize) -> RangeBufInfo {
        RangeBufInfo {
            id,
            chunk_num,
            len,
            processed: false,
        }
    }
}

/*impl Ord for RangeBufInfo {
    /*fn cmp(&self, other: &Self) -> Ordering {
        self.start_off.cmp(&other.start_off)
    }*/
}

impl PartialOrd for RangeBufInfo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for RangeBufInfo {
    fn eq(&self, other: &Self) -> bool {
        self.start_off == other.start_off
    }
}*/

#[derive(Debug)]
pub struct Deframed {
    pub want_close_before_decrypt: bool,
    pub aligned: bool,
    pub trial_decryption_finished: bool,
    pub message: PlainMessage,
}

#[derive(Debug)]
pub enum DeframerError {
    HandshakePayloadSizeTooLarge,
}

const HEADER_SIZE: usize = 1 + 3;

/// TLS allows for handshake messages of up to 16MB.  We
/// restrict that to 64KB to limit potential for denial-of-
/// service.
const MAX_HANDSHAKE_SIZE: u32 = 0xffff;

const READ_SIZE: usize = 4096;

const DISCARD_THRESHOLD: usize =  READ_SIZE ;


#[cfg(test)]
mod tests {
    use std::cmp::Ordering;
    use super::{DISCARD_THRESHOLD, MessageDeframer};
    use crate::msgs::message::{MAX_WIRE_SIZE, Message};
    use crate::record_layer::RecordLayer;
    use crate::{ContentType, Error, InvalidMessage};

    use std::io;
    use crate::recvbuf::RecvBufMap;

    const FIRST_MESSAGE: &[u8] = include_bytes!("../testdata/deframer-test.1.bin");
    const SECOND_MESSAGE: &[u8] = include_bytes!("../testdata/deframer-test.2.bin");

    const EMPTY_APPLICATIONDATA_MESSAGE: &[u8] =
        include_bytes!("../testdata/deframer-empty-applicationdata.bin");

    const INVALID_EMPTY_MESSAGE: &[u8] = include_bytes!("../testdata/deframer-invalid-empty.bin");
    const INVALID_CONTENTTYPE_MESSAGE: &[u8] =
        include_bytes!("../testdata/deframer-invalid-contenttype.bin");
    const INVALID_VERSION_MESSAGE: &[u8] =
        include_bytes!("../testdata/deframer-invalid-version.bin");
    const INVALID_LENGTH_MESSAGE: &[u8] = include_bytes!("../testdata/deframer-invalid-length.bin");

    fn input_bytes(d: &mut MessageDeframer, bytes: &[u8]) -> io::Result<usize> {
        let mut rd = io::Cursor::new(bytes);
        d.read(&mut rd)
    }

    fn input_bytes_concat(
        d: &mut MessageDeframer,
        bytes1: &[u8],
        bytes2: &[u8],
    ) -> io::Result<usize> {
        let mut bytes = vec![0u8; bytes1.len() + bytes2.len()];
        bytes[..bytes1.len()].clone_from_slice(bytes1);
        bytes[bytes1.len()..].clone_from_slice(bytes2);
        let mut rd = io::Cursor::new(&bytes);
        d.read(&mut rd)
    }

    struct ErrorRead {
        error: Option<io::Error>,
    }

    impl ErrorRead {
        fn new(error: io::Error) -> Self {
            Self { error: Some(error) }
        }
    }

    impl io::Read for ErrorRead {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = i as u8;
            }

            let error = self.error.take().unwrap();
            Err(error)
        }
    }

    fn input_error(d: &mut MessageDeframer) {
        let error = io::Error::from(io::ErrorKind::TimedOut);
        let mut rd = ErrorRead::new(error);
        d.read(&mut rd)
            .expect_err("error not propagated");
    }

    fn input_whole_incremental(d: &mut MessageDeframer, bytes: &[u8]) {
        let before = d.used;

        for i in 0..bytes.len() {
            assert_len(1, input_bytes(d, &bytes[i..i + 1]));
            assert!(d.has_pending());
        }

        assert_eq!(before + bytes.len(), d.used);
    }

    fn assert_len(want: usize, got: io::Result<usize>) {
        if let Ok(gotval) = got {
            assert_eq!(gotval, want);
        } else {
            panic!("read failed, expected {:?} bytes", want);
        }
    }

    fn pop_first(d: &mut MessageDeframer, rl: &mut RecordLayer) {
        let m = d.pop(rl, &mut RecvBufMap::new()).unwrap().unwrap().message;
        assert_eq!(m.typ, ContentType::Handshake);
        Message::try_from(m).unwrap();
    }

    fn pop_second(d: &mut MessageDeframer, rl: &mut RecordLayer) {
        let m = d.pop(rl, &mut RecvBufMap::new()).unwrap().unwrap().message;
        assert_eq!(m.typ, ContentType::Alert);
        Message::try_from(m).unwrap();
    }

    #[test]
    fn check_incremental() {
        let mut d = MessageDeframer::default();
        assert!(!d.has_pending());
        input_whole_incremental(&mut d, FIRST_MESSAGE);
        assert!(d.has_pending());

        let mut rl = RecordLayer::new();
        pop_first(&mut d, &mut rl);
        assert!(!d.has_pending());
        assert!(d.last_error.is_none());
    }

    #[test]
    fn check_incremental_2() {
        let mut d = MessageDeframer::default();
        assert!(!d.has_pending());
        input_whole_incremental(&mut d, FIRST_MESSAGE);
        assert!(d.has_pending());
        input_whole_incremental(&mut d, SECOND_MESSAGE);
        assert!(d.has_pending());

        let mut rl = RecordLayer::new();
        pop_first(&mut d, &mut rl);
        assert!(d.has_pending());
        pop_second(&mut d, &mut rl);
        assert!(d.has_pending()); // Buffer content is < DISCARD_THRESHOLD
        assert!(d.last_error.is_none());
    }

    #[test]
    fn check_whole() {
        let mut d = MessageDeframer::default();
        assert!(!d.has_pending());
        assert_len(FIRST_MESSAGE.len(), input_bytes(&mut d, FIRST_MESSAGE));
        assert!(d.has_pending());

        let mut rl = RecordLayer::new();
        pop_first(&mut d, &mut rl);
        assert!(!d.has_pending());
        assert!(d.last_error.is_none());
    }

    #[test]
    fn check_whole_2() {
        let mut d = MessageDeframer::default();
        assert!(!d.has_pending());
        assert_len(FIRST_MESSAGE.len(), input_bytes(&mut d, FIRST_MESSAGE));
        assert_len(SECOND_MESSAGE.len(), input_bytes(&mut d, SECOND_MESSAGE));

        let mut rl = RecordLayer::new();
        pop_first(&mut d, &mut rl);
        pop_second(&mut d, &mut rl);
        assert!(d.has_pending());
        assert!(d.last_error.is_none());
    }

    #[test]
    fn test_two_in_one_read() {
        let mut d = MessageDeframer::default();
        assert!(!d.has_pending());
        assert_len(
            FIRST_MESSAGE.len() + SECOND_MESSAGE.len(),
            input_bytes_concat(&mut d, FIRST_MESSAGE, SECOND_MESSAGE),
        );

        let mut rl = RecordLayer::new();
        pop_first(&mut d, &mut rl);
        pop_second(&mut d, &mut rl);
        assert!(d.has_pending());
        assert!(d.last_error.is_none());
    }

    #[test]
    fn test_two_in_one_read_shortest_first() {
        let mut d = MessageDeframer::default();
        assert!(!d.has_pending());
        assert_len(
            FIRST_MESSAGE.len() + SECOND_MESSAGE.len(),
            input_bytes_concat(&mut d, SECOND_MESSAGE, FIRST_MESSAGE),
        );

        let mut rl = RecordLayer::new();
        pop_second(&mut d, &mut rl);
        pop_first(&mut d, &mut rl);
        assert!(d.has_pending());
        assert!(d.last_error.is_none());
    }

    #[test]
    fn test_incremental_with_nonfatal_read_error() {
        let mut d = MessageDeframer::default();
        assert_len(3, input_bytes(&mut d, &FIRST_MESSAGE[..3]));
        input_error(&mut d);
        assert_len(
            FIRST_MESSAGE.len() - 3,
            input_bytes(&mut d, &FIRST_MESSAGE[3..]),
        );

        let mut rl = RecordLayer::new();
        pop_first(&mut d, &mut rl);
        assert!(!d.has_pending());
        assert!(d.last_error.is_none());
    }

    #[test]
    fn test_invalid_contenttype_errors() {
        let mut d = MessageDeframer::default();
        assert_len(
            INVALID_CONTENTTYPE_MESSAGE.len(),
            input_bytes(&mut d, INVALID_CONTENTTYPE_MESSAGE),
        );

        let mut rl = RecordLayer::new();
        assert_eq!(
            d.pop(&mut rl, &mut RecvBufMap::new()).unwrap_err(),
            Error::InvalidMessage(InvalidMessage::InvalidContentType)
        );
    }

    #[test]
    fn test_invalid_version_errors() {
        let mut d = MessageDeframer::default();
        assert_len(
            INVALID_VERSION_MESSAGE.len(),
            input_bytes(&mut d, INVALID_VERSION_MESSAGE),
        );

        let mut rl = RecordLayer::new();
        assert_eq!(
            d.pop(&mut rl, &mut RecvBufMap::new()).unwrap_err(),
            Error::InvalidMessage(InvalidMessage::UnknownProtocolVersion)
        );
    }

    #[test]
    fn test_invalid_length_errors() {
        let mut d = MessageDeframer::default();
        assert_len(
            INVALID_LENGTH_MESSAGE.len(),
            input_bytes(&mut d, INVALID_LENGTH_MESSAGE),
        );

        let mut rl = RecordLayer::new();
        assert_eq!(
            d.pop(&mut rl, &mut RecvBufMap::new()).unwrap_err(),
            Error::InvalidMessage(InvalidMessage::MessageTooLarge)
        );
    }

    #[test]
    fn test_empty_applicationdata() {
        let mut d = MessageDeframer::default();
        assert_len(
            EMPTY_APPLICATIONDATA_MESSAGE.len(),
            input_bytes(&mut d, EMPTY_APPLICATIONDATA_MESSAGE),
        );

        let mut rl = RecordLayer::new();
        let m = d.pop(&mut rl, &mut RecvBufMap::new()).unwrap().unwrap().message;
        assert_eq!(m.typ, ContentType::ApplicationData);
        assert_eq!(m.payload.0.len(), 0);
        assert!(d.has_pending());
        assert!(d.last_error.is_none());
    }

    #[test]
    fn test_invalid_empty_errors() {
        let mut d = MessageDeframer::default();
        assert_len(
            INVALID_EMPTY_MESSAGE.len(),
            input_bytes(&mut d, INVALID_EMPTY_MESSAGE),
        );

        let mut rl = RecordLayer::new();
        assert_eq!(
            d.pop(&mut rl, &mut RecvBufMap::new()).unwrap_err(),
            Error::InvalidMessage(InvalidMessage::InvalidEmptyPayload)
        );
        // CorruptMessage has been fused
        assert_eq!(
            d.pop(&mut rl, &mut RecvBufMap::new()).unwrap_err(),
            Error::InvalidMessage(InvalidMessage::InvalidEmptyPayload)
        );
    }

   #[test]
    fn test_limited_buffer() {
        const PAYLOAD_LEN: usize = 16_384 * 2;
        let mut message = Vec::with_capacity(MAX_WIRE_SIZE);
        message.push(0x17); // ApplicationData
        message.extend(&[0x03, 0x04]); // ProtocolVersion
        message.extend((PAYLOAD_LEN as u16).to_be_bytes()); // payload length
        message.extend(&[0; PAYLOAD_LEN]);

        let mut d = MessageDeframer::default();
        assert_len(4096, input_bytes(&mut d, &message));
        assert_len(4096, input_bytes(&mut d, &message));
        assert_len(4096, input_bytes(&mut d, &message));
        assert_len(4096, input_bytes(&mut d, &message));
        assert_len(4096, input_bytes(&mut d, &message));
        assert_len(4096, input_bytes(&mut d, &message));
        assert_len(4096, input_bytes(&mut d, &message));
       assert_len(4096, input_bytes(&mut d, &message));
       assert_len(4096, input_bytes(&mut d, &message));
       assert_len(10, input_bytes(&mut d, &message));
        assert!(input_bytes(&mut d, &message).is_err());
    }
    #[test]
    fn discard_processed_data_if_threshold_reached(){
        let mut receive_map = RecvBufMap::new();
        const PAYLOAD_LEN1: usize = 3000;
        const PAYLOAD_LEN2: usize = DISCARD_THRESHOLD;
        let mut message1 = Vec::with_capacity(17000);
        message1.push(0x17); // ApplicationData
        message1.extend(&[0x03, 0x04]); // ProtocolVersion
        message1.extend((PAYLOAD_LEN1 as u16).to_be_bytes()); // payload length
        message1.extend(&[0; PAYLOAD_LEN1]);


        let mut message2 = Vec::with_capacity(17000);
        message2.push(0x17); // ApplicationData
        message2.extend(&[0x03, 0x04]); // ProtocolVersion
        message2.extend((PAYLOAD_LEN2 as u16).to_be_bytes()); // payload length
        message2.extend(&[0; PAYLOAD_LEN2]);

        let mut d = MessageDeframer::default();
        let mut rl = RecordLayer::new();

        rl.set_not_handshaking();

        // 3000 is < DISCARD_THRESHOLD -> no discard
        d.buf.extend_from_slice(message1.as_slice());
        d.used += message1.len();
        d.pop(&mut rl, &mut receive_map).unwrap();
        assert!(d.has_pending());

        d.buf.extend_from_slice(message2.as_slice());
        d.used += message2.len();

        // After writing this message, deframer will have data >= threshold and must discard it
        d.pop(&mut rl, &mut receive_map).unwrap();
        assert!(!d.has_pending());

    }
}
