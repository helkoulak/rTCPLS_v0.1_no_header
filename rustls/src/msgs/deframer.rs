use alloc::vec::Vec;
use core::ops::Range;
use core::slice::SliceIndex;
use std::collections::{hash_map, BTreeMap};
#[cfg(feature = "std")]
use std::io;

use crate::enums::{ContentType, ProtocolVersion};
use crate::error::{Error, InvalidMessage, PeerMisbehaved};
use crate::msgs::codec;
#[cfg(feature = "std")]

use crate::msgs::message::{InboundOpaqueMessage, InboundPlainMessage, MessageError, MAX_DEFRAMER_CAP, MAX_PAYLOAD};
use crate::record_layer::{Decrypted, RecordLayer};

use crate::tcpls::stream::SimpleIdHashMap;

use super::codec::Codec;

/// This deframer works to reconstruct TLS messages from a stream of arbitrary-sized reads.
///
/// It buffers incoming data into a `Vec` through `read()`, and returns messages through `pop()`.
/// QUIC connections will call `push()` to append handshake payload data directly.
#[derive(Default)]
pub struct MessageDeframer {

    /// Set if the peer is not talking TLS, but some other
    /// protocol.  The caller should abort the connection, because
    /// the deframer cannot recover.
    last_error: Option<Error>,


    /// If we're in the middle of joining a handshake payload, this is the metadata.
    joining_hs: Option<HandshakePayloadMeta>,

    pub(crate) record_info: SimpleIdHashMap<BTreeMap<usize, RangeBufInfo>>,

    pub(crate) current_conn_id: u64,

    pub(crate) processed_ranges: SimpleIdHashMap<Vec<Range<usize>>>,

    /// Range of dicard area in deframer buffer.
    pub(crate) discard_range: Range<usize>,

    pub(crate) discard_threshold: usize,

    pub(crate) used: usize,

    ///Start and end offsets of the next record to be processed
    pub(crate) conn_current_off: SimpleIdHashMap<Range<usize>>,
}

impl MessageDeframer {

    pub fn pop_unbuffered<'b>(
        &mut self,
        record_layer: &mut RecordLayer,
        negotiated_version: Option<ProtocolVersion>,
        buffer: &mut DeframerSliceBuffer<'b>,
    ) -> Result<Option<Deframed<'b>>, Error> {
        if let Some(last_err) = self.last_error.clone() {
            return Err(last_err);
        } else if buffer.is_empty() {
            return Ok(None);
        }

        // We loop over records we've received but not processed yet.
        // For records that decrypt as `Handshake`, we keep the current state of the joined
        // handshake message payload in `self.joining_hs`, appending to it as we see records.
        let expected_len = loop {
            let start = match &self.joining_hs {
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
                None => 0,
            };

            // Does our `buf` contain a full message?  It does if it is big enough to
            // contain a header, and that header has a length which falls within `buf`.
            // If so, deframe it and place the message onto the frames output queue.
            let mut rd = codec::ReaderMut::init(buffer.filled_get_mut(start..));
            let m = match InboundOpaqueMessage::read(&mut rd) {
                Ok(m) => m,
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

            // Return CCS messages and early plaintext alerts immediately without decrypting.
            let end = start + rd.used();
            let version_is_tls13 = matches!(negotiated_version, Some(ProtocolVersion::TLSv1_3));
            let allowed_plaintext = match m.typ {
                // CCS messages are always plaintext.
                ContentType::ChangeCipherSpec => true,
                // Alerts are allowed to be plaintext if-and-only-if:
                // * The negotiated protocol version is TLS 1.3. - In TLS 1.2 it is unambiguous when
                //   keying changes based on the CCS message. Only TLS 1.3 requires these heuristics.
                // * We have not yet decrypted any messages from the peer - if we have we don't
                //   expect any plaintext.
                // * The payload size is indicative of a plaintext alert message.
                ContentType::Alert
                if version_is_tls13
                    && !record_layer.has_decrypted()
                    && m.payload.len() <= 2 =>
                    {
                        true
                    }
                // In other circumstances, we expect all messages to be encrypted.
                _ => false,
            };
            if self.joining_hs.is_none() && allowed_plaintext {
                let InboundOpaqueMessage {
                    typ,
                    version,
                    payload,
                } = m;
                let raw_payload_slice = RawSlice::from(&*payload);
                // This is unencrypted. We check the contents later.
                buffer.queue_discard(end);
                let message = InboundPlainMessage {
                    typ,
                    version,
                    payload: buffer.take(raw_payload_slice),
                };
                return Ok(Some(Deframed {
                    want_close_before_decrypt: false,
                    aligned: true,
                    trial_decryption_finished: false,
                    message,
                }));
            }

            // Decrypt the encrypted message (if necessary).
            let (typ, version, plain_payload_slice) = match record_layer.decrypt_incoming(m) {
                Ok(Some(decrypted)) => {
                    let Decrypted {
                        want_close_before_decrypt,
                        plaintext:
                        InboundPlainMessage {
                            typ,
                            version,
                            payload,
                        },
                    } = decrypted;
                    debug_assert!(!want_close_before_decrypt);
                    (typ, version, RawSlice::from(payload))
                }
                // This was rejected early data, discard it. If we currently have a handshake
                // payload in progress, this counts as interleaved, so we error out.
                Ok(None) if self.joining_hs.is_some() => {
                    return Err(self.set_err(
                        PeerMisbehaved::RejectedEarlyDataInterleavedWithHandshakeMessage,
                    ));
                }
                Ok(None) => {
                    buffer.queue_discard(end);
                    continue;
                }
                Err(e) => return Err(e),
            };

            if self.joining_hs.is_some() && typ != ContentType::Handshake {
                // "Handshake messages MUST NOT be interleaved with other record
                // types.  That is, if a handshake message is split over two or more
                // records, there MUST NOT be any other records between them."
                // https://www.rfc-editor.org/rfc/rfc8446#section-5.1
                return Err(self.set_err(PeerMisbehaved::MessageInterleavedWithHandshakeMessage));
            }

            // If it's not a handshake message, just return it -- no joining necessary.
            if typ != ContentType::Handshake {
                buffer.queue_discard(end);
                let message = InboundPlainMessage {
                    typ,
                    version,
                    payload: buffer.take(plain_payload_slice),
                };
                return Ok(Some(Deframed {
                    want_close_before_decrypt: false,
                    aligned: true,
                    trial_decryption_finished: false,
                    message,
                }));
            }

            // If we don't know the payload size yet or if the payload size is larger
            // than the currently buffered payload, we need to wait for more data.
            let src = buffer.raw_slice_to_filled_range(plain_payload_slice);
            match self.append_hs(version, InternalPayload(src), end, 0, buffer)? {
                HandshakePayloadState::Blocked => return Ok(None),
                HandshakePayloadState::Complete(len) => break len,
                HandshakePayloadState::Continue => continue,
            }
        };

        let meta = self.joining_hs.as_mut().unwrap(); // safe after calling `append_hs()`

        // We can now wrap the complete handshake payload in a `PlainMessage`, to be returned.
        let typ = ContentType::Handshake;
        let version = meta.version;
        let raw_payload = RawSlice::from(
            buffer.filled_get(meta.payload.start..meta.payload.start + expected_len),
        );

        // But before we return, update the `joining_hs` state to skip past this payload.
        if meta.payload.len() > expected_len {
            // If we have another (beginning of) a handshake payload left in the buffer, update
            // the payload start to point past the payload we're about to yield, and update the
            // `expected_len` to match the state of that remaining payload.
            meta.payload.start += expected_len;
            meta.expected_len =
                payload_size(buffer.filled_get(meta.payload.start..meta.payload.end))?;
        } else {
            // Otherwise, we've yielded the last handshake payload in the buffer, so we can
            // discard all of the bytes that we're previously buffered as handshake data.
            let end = meta.message.end;
            self.joining_hs = None;
            buffer.queue_discard(end);
        }

        let message = InboundPlainMessage {
            typ,
            version,
            payload: buffer.take(raw_payload),
        };

        Ok(Some(Deframed {
            want_close_before_decrypt: false,
            aligned: self.joining_hs.is_none(),
            trial_decryption_finished: true,
            message,
        }))
    }

    /// Return any decrypted messages that the deframer has been able to parse.
    ///
    /// Returns an `Error` if the deframer failed to parse some message contents or if decryption
    /// failed, `Ok(None)` if no full message is buffered or if trial decryption failed, and
    /// `Ok(Some(_))` if a valid message was found and decrypted successfully.
    pub fn pop<'b>(
        &mut self,
        record_layer: &mut RecordLayer,
        negotiated_version: Option<ProtocolVersion>,
        buffer: &mut DeframerSliceBuffer<'b>,
    ) -> Result<Option<Deframed<'b>>, Error> {
        if let Some(last_err) = self.last_error.clone() {
            return Err(last_err);
        } else if buffer.used == 0{
            return Ok(None);
        }

        let conn_id = self.current_conn_id;
        let mut start: usize;
        let mut end: usize;

        // We loop over records we've received but not processed yet.
        // For records that decrypt as `Handshake`, we keep the current state of the joined
        // handshake message payload in `self.joining_hs`, appending to it as we see records.
        let expected_len = loop {
            start = self.conn_current_off
                .entry(conn_id)
                .or_insert(Range::default()) // Insert `None` if `conn_id` does not exist
                .start;



            // Does our `buf` contain a full message?  It does if it is big enough to
            // contain a header, and that header has a length which falls within `buf`.
            // If so, deframe it and place the message onto the frames output queue.
            let mut rd = codec::ReaderMut::init(buffer.get_mut(start));
            let m = match InboundOpaqueMessage::read(&mut rd) {
                Ok(m) => m,
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

            // Return CCS messages and early plaintext alerts immediately without decrypting.
            end = start + rd.used();
            let version_is_tls13 = matches!(negotiated_version, Some(ProtocolVersion::TLSv1_3));
            let allowed_plaintext = match m.typ {
                // CCS messages are always plaintext.
                ContentType::ChangeCipherSpec => true,
                // Alerts are allowed to be plaintext if-and-only-if:
                // * The negotiated protocol version is TLS 1.3. - In TLS 1.2 it is unambiguous when
                //   keying changes based on the CCS message. Only TLS 1.3 requires these heuristics.
                // * We have not yet decrypted any messages from the peer - if we have we don't
                //   expect any plaintext.
                // * The payload size is indicative of a plaintext alert message.
                ContentType::Alert
                if version_is_tls13
                    && !record_layer.has_decrypted()
                    && m.payload.len() <= 2 =>
                    {
                        true
                    }
                // In other circumstances, we expect all messages to be encrypted.
                _ => false,
            };
            if self.joining_hs.is_none() && allowed_plaintext {
                let InboundOpaqueMessage {
                    typ,
                    version,
                    payload,
                } = m;
                let raw_payload_slice = RawSlice::from(&*payload);

                let message = InboundPlainMessage {
                    typ,
                    version,
                    payload: buffer.take(raw_payload_slice),
                };
                // This is unencrypted. We check the contents later.
                self.processed_ranges.entry(conn_id)
                    .or_insert_with(Vec::new)
                    .push(start..end);
                return Ok(Some(Deframed {
                    want_close_before_decrypt: false,
                    aligned: true,
                    trial_decryption_finished: false,
                    message,
                }));
            }

            // Decrypt the encrypted message (if necessary).
            let (typ, version, plain_payload_slice) = match record_layer.decrypt_incoming_tcpls(m) {
                Ok(Some(decrypted)) => {
                    let Decrypted {
                        want_close_before_decrypt,
                        plaintext:
                        InboundPlainMessage {
                            typ,
                            version,
                            payload,
                        },
                    } = decrypted;
                    debug_assert!(!want_close_before_decrypt);
                    (typ, version, RawSlice::from(payload))
                }
                // This was rejected early data, discard it. If we currently have a handshake
                // payload in progress, this counts as interleaved, so we error out.
                Ok(None) if self.joining_hs.is_some() => {
                    return Err(self.set_err(
                        PeerMisbehaved::RejectedEarlyDataInterleavedWithHandshakeMessage,
                    ));
                }
                Ok(None) => {
                    self.processed_ranges.entry(conn_id)
                        .or_insert_with(Vec::new)
                        .push(start..end);
                    continue;
                }
                Err(e) => {
                    return Err(e)
                },
            };

            if self.joining_hs.is_some() && typ != ContentType::Handshake {
                // "Handshake messages MUST NOT be interleaved with other record
                // types.  That is, if a handshake message is split over two or more
                // records, there MUST NOT be any other records between them."
                // https://www.rfc-editor.org/rfc/rfc8446#section-5.1
                return Err(self.set_err(PeerMisbehaved::MessageInterleavedWithHandshakeMessage));
            }

            // If it's not a handshake message, just return it -- no joining necessary.
            if typ != ContentType::Handshake {
                self.conn_current_off.get_mut(&conn_id).unwrap().start = start;
                self.conn_current_off.get_mut(&conn_id).unwrap().end = end;
                let message = InboundPlainMessage {
                    typ,
                    version,
                    payload: buffer.take(plain_payload_slice),
                };
                return Ok(Some(Deframed {
                    want_close_before_decrypt: false,
                    aligned: true,
                    trial_decryption_finished: false,
                    message,
                }));
            }

            // If we don't know the payload size yet or if the payload size is larger
            // than the currently buffered payload, we need to wait for more data.
            let src = buffer.raw_slice_to_filled_range(plain_payload_slice);
            match self.append_hs(version, InternalPayload(src), end, start, buffer)? {
                HandshakePayloadState::Blocked => return Ok(None),
                HandshakePayloadState::Complete(len) => break len,
                HandshakePayloadState::Continue => {
                    self.processed_ranges
                        .entry(conn_id)
                        .or_insert_with(Vec::new)
                        .push(start..end);
                    self.conn_current_off
                        .entry(conn_id)
                        .or_insert(Range::default()) // Insert `None` if `conn_id` does not exist
                        .start = end ;

                    continue
                },
            }
        };

        let meta = self.joining_hs.as_mut().unwrap(); // safe after calling `append_hs()`

        // We can now wrap the complete handshake payload in a `PlainMessage`, to be returned.
        let typ = ContentType::Handshake;
        let version = meta.version;
        let raw_payload = RawSlice::from(
            buffer.filled_get(meta.payload.start..meta.payload.start + expected_len),
        );

        // But before we return, update the `joining_hs` state to skip past this payload.
        if meta.payload.len() > expected_len {
            // If we have another (beginning of) a handshake payload left in the buffer, update
            // the payload start to point past the payload we're about to yield, and update the
            // `expected_len` to match the state of that remaining payload.
            meta.payload.start += expected_len;
            meta.expected_len =
                payload_size(buffer.filled_get(meta.payload.start..meta.payload.end))?;
        } else {
            // Otherwise, we've yielded the last handshake payload in the buffer, so we can
            // discard all the bytes that we're previously buffered as handshake data.

            self.processed_ranges
                .entry(conn_id)
                .or_insert_with(Vec::new)
                .push(meta.message.start..meta.message.end);
            self.joining_hs = None;
        }

        let message = InboundPlainMessage {
            typ,
            version,
            payload: buffer.take(raw_payload),
        };

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


    /// Write the handshake message contents into the buffer and update the metadata.
    ///
    /// Returns true if a complete message is found.
    fn append_hs<'a, P: AppendPayload<'a>, B: DeframerBuffer<'a, P>>(
        &mut self,
        version: ProtocolVersion,
        payload: P,
        end: usize,
        start: usize,
        buffer: &mut B,
    ) -> Result<HandshakePayloadState, Error> {
        let meta = match &mut self.joining_hs {
            Some(meta) => {
                debug_assert_eq!(meta.quic, P::QUIC);

                // We're joining a handshake message to the previous one here.
                // Write it into the buffer and update the metadata.

                buffer.copy(&payload, meta.payload.end);
                meta.message.end = end;
                meta.payload.end += payload.len();

                // If we haven't parsed the payload size yet, try to do so now.
                if meta.expected_len.is_none() {
                    meta.expected_len =
                        payload_size(buffer.filled_get(meta.payload.start..meta.payload.end))?;
                }

                meta
            }
            None => {
                // We've found a new handshake message here.
                // Write it into the buffer and create the metadata.

                let expected_len = payload.size(buffer)?;
                buffer.copy(&payload, 0);
                self.joining_hs
                    .insert(HandshakePayloadMeta {
                        message: Range { start, end },
                        payload: Range {
                            start: 0,
                            end: payload.len(),
                        },
                        version,
                        expected_len,
                        quic: P::QUIC,
                    })
            }
        };

        Ok(match meta.expected_len {
            Some(len) if len <= meta.payload.len() => HandshakePayloadState::Complete(len),
            _ => match buffer.len() > meta.message.end {
                true => HandshakePayloadState::Continue,
                false => HandshakePayloadState::Blocked,
            },
        })
    }

    pub fn calculate_discard_range(&mut self) {
        if self.used < self.discard_threshold {
            return;
        }
        let conn_id = self.current_conn_id;
        if !self.processed_ranges.contains_key(&conn_id){
            return;
        }
        let mut initial_discard_range: Range::<usize> = { self.discard_range.start.. self.discard_range.end};
        loop {
            for range in self.processed_ranges.get(&conn_id).unwrap().iter() {
                let entry_start = range.start;
                let entry_end = range.end;

                // Initiate range with first processed entry found and build upon
                if self.discard_range.start == 0 && self.discard_range.end == 0 {
                    self.discard_range.start = entry_start;
                    self.discard_range.end = entry_end;
                    continue
                }
                // expand to the right
                if entry_start == self.discard_range.end  {
                    self.discard_range.end = entry_end;
                    continue
                }
                // expand to the left
                if entry_end == self.discard_range.start {
                    self.discard_range.start = entry_start;
                    continue
                }
            }
            if initial_discard_range.start == self.discard_range.start && initial_discard_range.end == self.discard_range.end {
                break
            }else {
                initial_discard_range.start = self.discard_range.start;
                initial_discard_range.end = self.discard_range.end;

            }
        }

    }

    pub fn rearrange_record_info(&mut self) {
        let conn_id = self.current_conn_id;
        let discard_len = self.discard_range.end - self.discard_range.start;
        let mut record_info_new: BTreeMap<usize, RangeBufInfo> = BTreeMap::default();
        let mut processed_ranges_new: Vec<Range<usize>> = Vec::new();
        if let Some(record_map) = self.record_info.get_mut(&conn_id) {
            for (offset, info) in record_map.iter().filter(|(&offset, _)| offset < self.discard_range.start || offset >= self.discard_range.end) {
                record_info_new.insert(
                    match *offset >= self.discard_range.end {
                        true => { *offset - discard_len },
                        false => *offset,
                    },
                    RangeBufInfo {
                        offset: info.offset,
                        plain_len: info.plain_len,
                        id: info.id,
                        processed: info.processed,
                        enc_len: info.enc_len,
                        fin: info.fin,
                    },
                );
            }
            *record_map = record_info_new;
        }



        if let Some(ranges) = self.processed_ranges.get_mut(&conn_id) {
            for range in ranges.iter().filter(|&x| x.end <= self.discard_range.start || x.start >= self.discard_range.end){
                processed_ranges_new.push(match range.end <= self.discard_range.start {
                    true => range.start..range.end,
                    false => range.start - discard_len..range.end - discard_len,
                })
            }
            *ranges = processed_ranges_new
        }


        self.discard_range.start = 0;
        self.discard_range.end   = 0;
    }



    pub fn currently_joining_hs(&self) -> bool {
        self.joining_hs.is_some()
    }

    pub fn discard_range_is_empty(&self) -> bool {
        self.discard_range.is_empty()
    }

    pub fn delete_proc_record_info(&mut self) {
        let conn_id = self.current_conn_id;
        match self.record_info.get_mut(&conn_id) {
            Some(records) => {
                match self.processed_ranges.get(&conn_id) {
                    Some(ranges) => {
                        for range in ranges {
                            records.remove(&range.start);
                        }
                    },
                    None => return,
                };

            },
            None => return,
        }
    }

}

#[cfg(feature = "std")]
impl MessageDeframer {
    /// Allow pushing handshake messages directly into the buffer.
    pub(crate) fn push(
        &mut self,
        version: ProtocolVersion,
        payload: &[u8],
        buffer: &mut DeframerVecBuffer,
    ) -> Result<(), Error> {
        if !buffer.is_empty() && self.joining_hs.is_none() {
            return Err(Error::General(
                "cannot push QUIC messages into unrelated connection".into(),
            ));
        } else if let Err(err) = buffer.prepare_read(self.joining_hs.is_some()) {
            return Err(Error::General(err.into()));
        }

        let end = buffer.len() + payload.len();
        self.append_hs(version, ExternalPayload(payload), end, 0, buffer)?;
        Ok(())
    }

    /// Read some bytes from `rd`, and add them to our internal buffer.
    #[allow(clippy::comparison_chain)]
    pub fn read(
        &mut self,
        rd: &mut dyn io::Read,
        buffer: &mut DeframerVecBuffer,
    ) -> io::Result<usize> {
        if let Err(err) = buffer.prepare_read(self.joining_hs.is_some()) {

            return Err(io::Error::new(io::ErrorKind::InvalidData, err));
        }

        // Try to do the largest reads possible. Note that if
        // we get a message with a length field out of range here,
        // we do a zero length read.  That looks like an EOF to
        // the next layer up, which is fine.

        let new_bytes = rd.read(buffer.unfilled())?;
        buffer.advance(new_bytes);
        Ok(new_bytes)
    }
}

trait AppendPayload<'a>: Sized {
    const QUIC: bool;

    fn len(&self) -> usize;

    fn size<B: DeframerBuffer<'a, Self>>(
        &self,
        internal_buffer: &B,
    ) -> Result<Option<usize>, Error>;
}

struct ExternalPayload<'a>(&'a [u8]);

impl<'a> AppendPayload<'a> for ExternalPayload<'a> {
    const QUIC: bool = true;

    fn len(&self) -> usize {
        self.0.len()
    }

    fn size<B: DeframerBuffer<'a, Self>>(&self, _: &B) -> Result<Option<usize>, Error> {
        payload_size(self.0)
    }
}

struct InternalPayload(Range<usize>);

impl<'a> AppendPayload<'a> for InternalPayload {
    const QUIC: bool = false;

    fn len(&self) -> usize {
        self.0.end - self.0.start
    }

    fn size<B: DeframerBuffer<'a, Self>>(
        &self,
        internal_buffer: &B,
    ) -> Result<Option<usize>, Error> {
        payload_size(internal_buffer.filled_get(self.0.clone()))
    }
}

#[derive(Default, Debug)]
pub struct DeframerVecBuffer {
    /// Id of related TCP connection
    id: u64,
    /// Buffer of data read from the socket, in the process of being parsed into messages.
    ///
    /// For buffer size management, checkout out the [`DeframerVecBuffer::prepare_read()`] method.
    buf: Vec<u8>,

    /// What size prefix of `buf` is used.
    used: usize,

    ///Maximum number of bytes the buffer can hold
    cap: usize,
}

impl DeframerVecBuffer {
    pub fn new(id: u64) -> DeframerVecBuffer {
        DeframerVecBuffer{
            id,
            cap: MAX_DEFRAMER_CAP,
            ..Default::default()
        }
    }
    /// Borrows the initialized contents of this buffer and tracks pending discard operations via
    /// the `discard` reference
    pub fn borrow(&mut self) -> DeframerSliceBuffer {
        DeframerSliceBuffer::new(&mut self.buf[..self.used], self.used)
    }
    /// Discard `taken` bytes from the start of our buffer.
    pub fn discard(&mut self, start: usize, taken: usize) {

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

            if (start + taken) == self.used {
                self.used = start;
            } else {
                self.buf.copy_within(start + taken..self.used, start);
                self.used -= taken;
            }

        } else if taken == self.used {
            self.used = 0;
        }
    }

    pub fn set_deframer_cap(&mut self, cap: usize) {
        self.cap = cap;
    }
    /*fn copy_within<T>(slice: &mut [T], src: usize, dst: usize, count: usize) {
        assert!(src + count <= slice.len());
        assert!(dst + count <= slice.len());

        unsafe {
            ptr::copy(slice.as_ptr().add(src), slice.as_mut_ptr().add(dst), count);
        }
    }*/
    pub fn calculate_discard_threshold(&self) -> usize {
        self.cap - MAX_PAYLOAD as usize
    }
}

#[cfg(feature = "std")]
impl DeframerVecBuffer {
    /// Returns true if there are messages for the caller to process
    pub fn has_pending(&self) -> bool {
        !self.is_empty()
    }

    /// Resize the internal `buf` if necessary for reading more bytes.
    fn prepare_read(&mut self, _is_joining_hs: bool) -> Result<(), &'static str> {


        if self.used >= self.cap {
            return Err("message buffer full");
        }

        let need_capacity = Ord::min(self.cap, self.used + READ_SIZE);
        if need_capacity > self.buf.len() {
            self.buf.resize(need_capacity, 0);
        } else if self.used == 0 || self.buf.len() > self.cap {
            self.buf.resize(need_capacity, 0);
            self.buf.shrink_to(need_capacity);
        }

        Ok(())
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn advance(&mut self, num_bytes: usize) {
        self.used += num_bytes;
    }

    fn unfilled(&mut self) -> &mut [u8] {
        &mut self.buf[self.used..]
    }
}

#[cfg(feature = "std")]
impl FilledDeframerBuffer for DeframerVecBuffer {
    fn filled_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.used]
    }

    fn filled(&self) -> &[u8] {
        &self.buf[..self.used]
    }

    fn get_mut(&mut self, index: usize) -> &mut [u8] {
        &mut self.buf[index..]
    }
}

#[cfg(feature = "std")]
impl DeframerBuffer<'_, InternalPayload> for DeframerVecBuffer {
    fn copy(&mut self, payload: &InternalPayload, at: usize) {
        self.borrow().copy(payload, at)
    }
}

#[cfg(feature = "std")]
impl<'a> DeframerBuffer<'a, ExternalPayload<'a>> for DeframerVecBuffer {
    fn copy(&mut self, payload: &ExternalPayload<'a>, _at: usize) {
        let len = payload.len();
        self.unfilled()[..len].copy_from_slice(payload.0);
        self.advance(len);
    }
}

/// A borrowed version of [`DeframerVecBuffer`] that tracks discard operations
#[derive(Debug)]
pub struct DeframerSliceBuffer<'a> {
    // a fully initialized buffer that will be deframed
    buf: &'a mut [u8],
    // number of bytes to discard from the front of `buf` at a later time
    discard: usize,
    taken: usize,
    used: usize,

}

impl<'a> DeframerSliceBuffer<'a> {
    pub fn new(buf: &'a mut [u8], used: usize) -> Self {
        Self {
            buf,
            discard: 0,
            taken: 0,
            used,
        }
    }

    /// Tracks a pending discard operation of `num_bytes`
    pub fn queue_discard(&mut self, num_bytes: usize) {
        self.discard += num_bytes;
    }

    /// Returns the number of bytes that need to be discarded
    pub fn pending_discard(&self) -> usize {
        self.discard
    }

    pub fn get_used(&self) -> usize {
        self.used
    }

    pub fn get_slice(&self, start: usize, len: usize) -> &[u8] {
        & self.buf[start..start+len]
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Remove a `RawSlice` range from the deframer buffer, returning a mutable reference to the
    /// removed portion.
    ///
    /// Safety: the caller *must* ensure that the `RawSlice` refers to a range from the same
    /// allocation as the deframer's buffer.
    fn take(&mut self, raw: RawSlice) -> &'a mut [u8] {
        let start = (raw.ptr as usize)
            .checked_sub(self.buf.as_ptr() as usize)
            .unwrap();
        let end = start + raw.len;

        let (taken, rest) = core::mem::take(&mut self.buf).split_at_mut(end);
        self.buf = rest;
        self.taken += end;

        &mut taken[start..]
    }

    /// Converts a raw slice to a filled range based on the offset and length.
    ///
    /// Safety: the caller *must* ensure that the `RawSlice` refers to a range from the same
    /// allocation as the deframer's buffer.
    fn raw_slice_to_filled_range(&self, raw: RawSlice) -> Range<usize> {
        let adjust = self.discard - self.taken;
        let start = ((raw.ptr as usize).checked_sub(self.buf.as_ptr() as usize)).unwrap() - adjust;
        let end = start + raw.len;
        start..end
    }
}

impl FilledDeframerBuffer for DeframerSliceBuffer<'_> {
    fn filled_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.discard - self.taken..]
    }

    fn filled(&self) -> &[u8] {
        &self.buf[self.discard - self.taken..]
    }

    fn get_mut(&mut self, index: usize) -> &mut [u8] {
        &mut self.buf[index..]
    }


}

impl DeframerBuffer<'_, InternalPayload> for DeframerSliceBuffer<'_> {
    fn copy(&mut self, payload: &InternalPayload, at: usize) {
        let buf = self.filled_mut();
        buf.copy_within(payload.0.clone(), at)
    }
}

pub(crate) struct RawSlice {
    ptr: *const u8,
    len: usize,
}

impl From<&'_ [u8]> for RawSlice {
    fn from(value: &'_ [u8]) -> Self {
        Self {
            ptr: value.as_ptr(),
            len: value.len(),
        }
    }
}

trait DeframerBuffer<'a, P: AppendPayload<'a>>: FilledDeframerBuffer {
    /// Copies from the `src` buffer into this buffer at the requested index
    ///
    /// If `QUIC` is true the data will be copied into the *un*filled section of the buffer
    ///
    /// If `QUIC` is false the data will be copied into the filled section of the buffer
    fn copy(&mut self, payload: &P, at: usize);
}

trait FilledDeframerBuffer {
    fn filled_get_mut<I: SliceIndex<[u8]>>(&mut self, index: I) -> &mut I::Output {
        self.filled_mut()
            .get_mut(index)
            .unwrap()
    }

    fn filled_mut(&mut self) -> &mut [u8];

    fn filled_get<I>(&self, index: I) -> &I::Output
    where
        I: SliceIndex<[u8]>,
    {
        self.filled().get(index).unwrap()
    }

    fn len(&self) -> usize {
        self.filled().len()
    }

    fn filled(&self) -> &[u8];

    fn get_mut(&mut self, index: usize) -> &mut [u8];


}

/*#[derive(Clone, Debug, Default)]
pub(crate) struct RecordsInfoMap {
    records: BTreeMap<u32, StreamInfoMap>
}

impl RecordsInfoMap {
    pub(crate) fn create_stream_record_info(&mut self, record: & [u8], len: u16, offset: u64, stream_id: u32) {
        match self.records.contains_key(&stream_id) {
          true => {
              self.records.get_mut(&stream_id).unwrap().insert_record(record, len, offset);
          },
          false => {
              let mut stream_map = StreamInfoMap::default();
              stream_map.insert_record(record, len, offset);
              self.records.insert(stream_id, stream_map);
          },
        };
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

}*/

/*#[derive(Clone, Debug, Default)]
pub(crate) struct StreamInfoMap {
    stream_records: SimpleIdHashMap<RecordInfo>
}

impl StreamInfoMap {
    pub(crate) fn insert_record(&mut self, record: &[u8], len: u16, offset: u64) {
        self.stream_records.insert(offset, RecordInfo::from(record.to_vec(), len));
    }


}*/
/*#[derive(Clone, Debug, Default)]
pub(crate) struct RecordInfo {
    /// Received record copied from deframer buffer if out of order
    pub(crate)  record: Vec<u8>,

    /// Length of chunk
    pub(crate) len: u16,

    pub(crate) processed: bool,
}

impl RecordInfo {
    pub(crate) fn from(record: Vec<u8>, len: u16) -> RecordInfo {
        RecordInfo {
            record,
            len,
            processed: false,
        }
    }
}*/


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

    if buf.len() < HANDSHAKE_HEADER_SIZE {
        return Ok(None);
    }

    let (header, _) = buf.split_at(HANDSHAKE_HEADER_SIZE);
    match codec::u24::read_bytes(&header[1..]) {
        Ok(len) if len.0 > MAX_HANDSHAKE_SIZE => Err(Error::InvalidMessage(
            InvalidMessage::HandshakePayloadTooLarge,
        )),

        Ok(len) => Ok(Some(HANDSHAKE_HEADER_SIZE + usize::from(len))),
        _ => Ok(None),
    }
}


#[derive(Debug)]
pub struct Deframed<'a> {
    pub(crate) want_close_before_decrypt: bool,
    pub(crate) aligned: bool,
    pub(crate) trial_decryption_finished: bool,
    pub message: InboundPlainMessage<'a>,
}

const HANDSHAKE_HEADER_SIZE: usize = 1 + 3;


/// TLS allows for handshake messages of up to 16MB.  We
/// restrict that to 64KB to limit potential for denial-of-
/// service.
const MAX_HANDSHAKE_SIZE: u32 = 0xffff;


#[cfg(feature = "std")]
const READ_SIZE: usize = 4096;


#[derive(Default)]
pub(crate) struct MessageDeframerMap {
    deframers: SimpleIdHashMap<DeframerVecBuffer>,
}

impl MessageDeframerMap {
    pub(crate) fn new() -> MessageDeframerMap {
        MessageDeframerMap {
            ..Default::default()
        }
    }

    pub(crate) fn get_or_create_def_vec_buff(&mut self, conn_id: u64) -> &mut DeframerVecBuffer {
        match self.deframers.entry(conn_id) {
            hash_map::Entry::Vacant(v) => {
                v.insert(DeframerVecBuffer::new(conn_id))
            },
            hash_map::Entry::Occupied(v) => v.into_mut(),
        }
    }
    /// Return ids of deframer buffers that have data received from socket
    pub(crate) fn get_keys(&self) -> Vec<u64> {
        let mut keys: Vec<u64> = Vec::new();
        for d in &self.deframers{
            if d.1.used > 0 {
                keys.push(d.1.id)
            }
        }
        keys
    }

}

#[derive(Clone, Debug, Default)]
pub(crate) struct RangeBufInfo {
    /// The id of the stream this record belongs to
    pub(crate) id: u16,

    /// The chunk number of record.
    pub(crate) offset: u64,

    /// Length of chunk
    pub(crate) plain_len: usize,

    /// Length of chunk encrypted
    pub(crate) enc_len: usize,

    ///Whether copied in app buffers
    pub(crate) processed: bool,

    pub(crate) fin: bool,

}

impl RangeBufInfo {
    pub(crate) fn from(offset: u64, id: u16, plain_len: usize, enc_len: usize, processed: bool, fin: bool) -> Self {
        Self {
            id,
            offset,
            plain_len,
            enc_len,
            processed,
            fin,
        }
    }
}


#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use std::prelude::v1::*;
    use std::vec;

    use crate::crypto::cipher::PlainMessage;
    use crate::msgs::message::Message;

    use super::*;

    #[test]
    fn check_incremental() {
        let mut d = BufferedDeframer::new();
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
        let mut d = BufferedDeframer::new();
        assert!(!d.has_pending());
        input_whole_incremental(&mut d, FIRST_MESSAGE);
        assert!(d.has_pending());
        input_whole_incremental(&mut d, SECOND_MESSAGE);
        assert!(d.has_pending());

        let mut rl = RecordLayer::new();
        pop_first(&mut d, &mut rl);
        assert!(d.has_pending());
        pop_second(&mut d, &mut rl);
        assert!(!d.has_pending());
        assert!(d.last_error.is_none());
    }

    #[test]
    fn check_whole() {
        let mut d = BufferedDeframer::new();
        assert!(!d.has_pending());
        assert_len(FIRST_MESSAGE.len(), d.input_bytes(FIRST_MESSAGE));
        assert!(d.has_pending());

        let mut rl = RecordLayer::new();
        pop_first(&mut d, &mut rl);
        assert!(!d.has_pending());
        assert!(d.last_error.is_none());
    }

    #[test]
    fn check_whole_2() {
        let mut d = BufferedDeframer::new();
        assert!(!d.has_pending());
        assert_len(FIRST_MESSAGE.len(), d.input_bytes(FIRST_MESSAGE));
        assert_len(SECOND_MESSAGE.len(), d.input_bytes(SECOND_MESSAGE));

        let mut rl = RecordLayer::new();
        pop_first(&mut d, &mut rl);
        pop_second(&mut d, &mut rl);
        assert!(!d.has_pending());
        assert!(d.last_error.is_none());
    }

    #[test]
    fn test_two_in_one_read() {
        let mut d = BufferedDeframer::new();
        assert!(!d.has_pending());
        assert_len(
            FIRST_MESSAGE.len() + SECOND_MESSAGE.len(),
            d.input_bytes_concat(FIRST_MESSAGE, SECOND_MESSAGE),
        );

        let mut rl = RecordLayer::new();
        pop_first(&mut d, &mut rl);
        pop_second(&mut d, &mut rl);
        assert!(!d.has_pending());
        assert!(d.last_error.is_none());
    }

    #[test]
    fn test_two_in_one_read_shortest_first() {
        let mut d = BufferedDeframer::new();
        assert!(!d.has_pending());
        assert_len(
            FIRST_MESSAGE.len() + SECOND_MESSAGE.len(),
            d.input_bytes_concat(SECOND_MESSAGE, FIRST_MESSAGE),
        );

        let mut rl = RecordLayer::new();
        pop_second(&mut d, &mut rl);
        pop_first(&mut d, &mut rl);
        assert!(!d.has_pending());
        assert!(d.last_error.is_none());
    }

    #[test]
    fn test_incremental_with_nonfatal_read_error() {
        let mut d = BufferedDeframer::new();
        assert_len(3, d.input_bytes(&FIRST_MESSAGE[..3]));
        input_error(&mut d);
        assert_len(FIRST_MESSAGE.len() - 3, d.input_bytes(&FIRST_MESSAGE[3..]));

        let mut rl = RecordLayer::new();
        pop_first(&mut d, &mut rl);
        assert!(!d.has_pending());
        assert!(d.last_error.is_none());
    }

    #[test]
    fn test_invalid_contenttype_errors() {
        let mut d = BufferedDeframer::new();
        assert_len(
            INVALID_CONTENTTYPE_MESSAGE.len(),
            d.input_bytes(INVALID_CONTENTTYPE_MESSAGE),
        );

        let mut rl = RecordLayer::new();
        assert_eq!(
            d.pop_error(&mut rl, None),
            Error::InvalidMessage(InvalidMessage::InvalidContentType)
        );
    }

    #[test]
    fn test_invalid_version_errors() {
        let mut d = BufferedDeframer::new();
        assert_len(
            INVALID_VERSION_MESSAGE.len(),
            d.input_bytes(INVALID_VERSION_MESSAGE),
        );

        let mut rl = RecordLayer::new();
        assert_eq!(
            d.pop_error(&mut rl, None),
            Error::InvalidMessage(InvalidMessage::UnknownProtocolVersion)
        );
    }

    #[test]
    fn test_invalid_length_errors() {
        let mut d = BufferedDeframer::new();
        assert_len(
            INVALID_LENGTH_MESSAGE.len(),
            d.input_bytes(INVALID_LENGTH_MESSAGE),
        );

        let mut rl = RecordLayer::new();
        assert_eq!(
            d.pop_error(&mut rl, None),
            Error::InvalidMessage(InvalidMessage::MessageTooLarge)
        );
    }

    #[test]
    fn test_empty_applicationdata() {
        let mut d = BufferedDeframer::new();
        assert_len(
            EMPTY_APPLICATIONDATA_MESSAGE.len(),
            d.input_bytes(EMPTY_APPLICATIONDATA_MESSAGE),
        );

        let mut rl = RecordLayer::new();
        let m = d.pop_message(&mut rl, None);
        assert_eq!(m.typ, ContentType::ApplicationData);
        assert_eq!(m.payload.bytes().len(), 0);
        assert!(!d.has_pending());
        assert!(d.last_error.is_none());
    }

    #[test]
    fn test_invalid_empty_errors() {
        let mut d = BufferedDeframer::new();
        assert_len(
            INVALID_EMPTY_MESSAGE.len(),
            d.input_bytes(INVALID_EMPTY_MESSAGE),
        );

        let mut rl = RecordLayer::new();
        assert_eq!(
            d.pop_error(&mut rl, None),
            Error::InvalidMessage(InvalidMessage::InvalidEmptyPayload)
        );
        // CorruptMessage has been fused
        assert_eq!(
            d.pop_error(&mut rl, None),
            Error::InvalidMessage(InvalidMessage::InvalidEmptyPayload)
        );
    }



    fn input_error(d: &mut BufferedDeframer) {
        let error = io::Error::from(io::ErrorKind::TimedOut);
        let mut rd = ErrorRead::new(error);
        d.read(&mut rd)
            .expect_err("error not propagated");
    }

    fn input_whole_incremental(d: &mut BufferedDeframer, bytes: &[u8]) {
        let before = d.buffer.len();

        for i in 0..bytes.len() {
            assert_len(1, d.input_bytes(&bytes[i..i + 1]));
            assert!(d.has_pending());
        }

        assert_eq!(before + bytes.len(), d.buffer.len());
    }

    fn pop_first(d: &mut BufferedDeframer, rl: &mut RecordLayer) {
        let m = d.pop_message(rl, None);
        assert_eq!(m.typ, ContentType::Handshake);
        Message::try_from(m).unwrap();
    }

    fn pop_second(d: &mut BufferedDeframer, rl: &mut RecordLayer) {
        let m = d.pop_message(rl, None);
        assert_eq!(m.typ, ContentType::Alert);
        Message::try_from(m).unwrap();
    }

    // buffered version to ease testing
    #[derive(Default)]
    struct BufferedDeframer {
        inner: MessageDeframer,
        buffer: DeframerVecBuffer,
    }

    impl BufferedDeframer {
        fn new() -> Self {
            Self {
                inner: MessageDeframer::default(),
                buffer: DeframerVecBuffer::new(0)
            }
        }
        fn input_bytes(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let mut rd = io::Cursor::new(bytes);
            self.read(&mut rd)
        }

        fn input_bytes_concat(&mut self, bytes1: &[u8], bytes2: &[u8]) -> io::Result<usize> {
            let mut bytes = vec![0u8; bytes1.len() + bytes2.len()];
            bytes[..bytes1.len()].clone_from_slice(bytes1);
            bytes[bytes1.len()..].clone_from_slice(bytes2);
            let mut rd = io::Cursor::new(&bytes);
            self.read(&mut rd)
        }

        fn pop_error(
            &mut self,
            record_layer: &mut RecordLayer,
            negotiated_version: Option<ProtocolVersion>,
        ) -> Error {
            let mut deframer_buffer = self.buffer.borrow();
            let err = self
                .inner
                .pop(record_layer, negotiated_version, &mut deframer_buffer)
                .unwrap_err();
            let discard = deframer_buffer.pending_discard();
            self.buffer.discard(discard, 0);
            err
        }

        fn pop_message(
            &mut self,
            record_layer: &mut RecordLayer,
            negotiated_version: Option<ProtocolVersion>,
        ) -> PlainMessage {
            let mut deframer_buffer = self.buffer.borrow();
            let m = self
                .inner
                .pop_unbuffered(record_layer, negotiated_version, &mut deframer_buffer)
                .unwrap()
                .unwrap()
                .message
                .into_owned();
            let discard = deframer_buffer.pending_discard();
            self.buffer.discard(0, discard);
            m
        }

        fn read(&mut self, rd: &mut dyn io::Read) -> io::Result<usize> {
            self.inner.read(rd, &mut self.buffer)
        }

        fn has_pending(&self) -> bool {
            self.buffer.has_pending()
        }
    }

    // grant access to the `MessageDeframer.last_error` field
    impl core::ops::Deref for BufferedDeframer {
        type Target = MessageDeframer;

        fn deref(&self) -> &Self::Target {
            &self.inner
        }
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


    fn assert_len(want: usize, got: io::Result<usize>) {
        assert_eq!(Some(want), got.ok())
    }

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

}
