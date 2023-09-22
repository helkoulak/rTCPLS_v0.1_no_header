// Copyright (C) 2018-2019, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


use std::collections::{hash_map, HashMap, HashSet};
use crate::Error;
use crate::vecbuf::ChunkVecBuffer;

pub const DEFAULT_BUFFER_LIMIT: usize = 64 * 1024;


pub struct Stream {

    pub stream_id: u32,

    /**
     * the stream should be cleaned up the next time tcpls_send is called
     */
    pub marked_for_close: bool,

    /**
     * Whether we still have to initialize the aead context for this stream.
     * That may happen if this stream is created before the handshake took place.
     */
    pub aead_initialized: bool,

    /// buffers the decryption of the received TLS records
    pub        received_plaintext: ChunkVecBuffer,
    /// buffers data to be sent if TLS handshake is still ongoing
    pub(crate) sendable_plaintext: ChunkVecBuffer,
    /// buffers encrypted TLS records that to be sent on the TCP socket
    pub(crate) sendable_tls: ChunkVecBuffer,

}

impl Stream {
    pub fn new(id: u32) -> Self {
        Self{
            stream_id: id,
            marked_for_close: false,
            aead_initialized: false,
            received_plaintext: ChunkVecBuffer::new(Some(DEFAULT_BUFFER_LIMIT)),
            sendable_plaintext: ChunkVecBuffer::new(Some(DEFAULT_BUFFER_LIMIT)),
            sendable_tls: ChunkVecBuffer::new(Some(DEFAULT_BUFFER_LIMIT)),
        }
    }
}

/// A simple no-op hasher for Stream IDs.
///

#[derive(Default)]
pub struct StreamIdHasher {
    id: u64,
}

impl std::hash::Hasher for StreamIdHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.id
    }

    #[inline]
    fn write_u64(&mut self, id: u64) {
        self.id = id;
    }

    #[inline]
    fn write(&mut self, _: &[u8]) {
        // We need a default write() for the trait but stream IDs will always
        // be a u64 so we just delegate to write_u64.
        unimplemented!()
    }
}

type BuildStreamIdHasher = std::hash::BuildHasherDefault<StreamIdHasher>;

pub type StreamIdHashMap<V> = HashMap<u64, V, BuildStreamIdHasher>;
pub type StreamIdHashSet = HashSet<u64, BuildStreamIdHasher>;

/// Keeps track of TCPLS streams and enforces stream limits.
#[derive(Default)]
pub struct StreamMap {
    /// Map of streams indexed by stream ID.
    streams: StreamIdHashMap<Stream>,
}

impl StreamMap {


    pub fn new() -> Self {
        let mut map = HashMap::new();
        let stream = Stream::new(0);
        map.insert(0, stream);
        Self {
            streams: map,
        }

    }

    // Returns the stream with the given ID if it exists.
    pub fn get(&self, id: u64) -> Option<&Stream> {
        self.streams.get(&id)
    }

    /// Returns the mutable stream with the given ID if it exists.
    pub fn get_mut(&mut self, id: u64) -> Option<&mut Stream> {
        self.streams.get_mut(&id)
    }

    /// Returns the mutable stream with the given ID if it exists, or creates
    /// a new one otherwise.
    ///
    /// The `local` parameter indicates whether the stream's creation was
    /// requested by the local application rather than the peer, and is
    /// used to validate the requested stream ID, and to select the initial
    /// flow control values from the local and remote transport parameters
    /// (also passed as arguments).
    ///
    /// This also takes care of enforcing both local and the peer's stream
    /// count limits. If one of these limits is violated, the `StreamLimit`
    /// error is returned.
    pub(crate) fn get_or_create(
        &mut self, id: u64, local_params: &crate::TransportParams,
        peer_params: &crate::TransportParams, local: bool, is_server: bool,
        version: u32,
    ) -> Result<&mut Stream, E> {
        let (stream, is_new_and_writable) = match self.streams.entry(id) {
            hash_map::Entry::Vacant(v) => {
                // Stream has already been closed and garbage collected.
                if self.collected.contains(&id) {
                    return Err(Error::Done);
                }

                if local != is_local(id, is_server) {
                    return Err(Error::InvalidStreamState(id));
                }

                let (max_rx_data, max_tx_data) = match (local, is_bidi(id)) {
                    // Locally-initiated bidirectional stream.
                    (true, true) => (
                        local_params.initial_max_stream_data_bidi_local,
                        peer_params.initial_max_stream_data_bidi_remote,
                    ),

                    // Locally-initiated unidirectional stream.
                    (true, false) => (0, peer_params.initial_max_stream_data_uni),

                    // Remotely-initiated bidirectional stream.
                    (false, true) => (
                        local_params.initial_max_stream_data_bidi_remote,
                        peer_params.initial_max_stream_data_bidi_local,
                    ),

                    // Remotely-initiated unidirectional stream.
                    (false, false) =>
                        (local_params.initial_max_stream_data_uni, 0),
                };

                // The two least significant bits from a stream id identify the
                // type of stream. Truncate those bits to get the sequence for
                // that stream type.
                //
                // Note, in V3, client's bidi stream start at 4.
                let stream_sequence = if version == crate::PROTOCOL_VERSION_V3 {
                    if is_bidi(id) && is_even(id) {
                        (id >> 2).checked_sub(1).unwrap_or(0)
                    } else {
                        id >> 2
                    }
                } else {
                    id >> 2
                };

                // Enforce stream count limits.
                match (is_local(id, is_server), is_bidi(id)) {
                    (true, true) => {
                        let n = std::cmp::max(
                            self.local_opened_streams_bidi,
                            stream_sequence + 1,
                        );

                        if n > self.peer_max_streams_bidi {
                            return Err(Error::StreamLimit);
                        }

                        self.local_opened_streams_bidi = n;
                    },

                    (true, false) => {
                        let n = std::cmp::max(
                            self.local_opened_streams_uni,
                            stream_sequence + 1,
                        );

                        if n > self.peer_max_streams_uni {
                            return Err(Error::StreamLimit);
                        }

                        self.local_opened_streams_uni = n;
                    },

                    (false, true) => {
                        let n = std::cmp::max(
                            self.peer_opened_streams_bidi,
                            stream_sequence + 1,
                        );

                        if n > self.local_max_streams_bidi {
                            return Err(Error::StreamLimit);
                        }
                        self.peer_opened_streams_bidi = n;
                    },

                    (false, false) => {
                        let n = std::cmp::max(
                            self.peer_opened_streams_uni,
                            stream_sequence + 1,
                        );

                        if n > self.local_max_streams_uni {
                            return Err(Error::StreamLimit);
                        }

                        self.peer_opened_streams_uni = n;
                    },
                };
                let s = Stream::new(
                    max_rx_data,
                    max_tx_data,
                    is_bidi(id),
                    local,
                    self.max_stream_window,
                    version,
                );

                let is_writable = s.is_writable();

                (v.insert(s), is_writable)
            },

            hash_map::Entry::Occupied(v) => (v.into_mut(), false),
        };

        // Newly created stream might already be writable due to initial flow
        // control limits.
        if is_new_and_writable {
            self.writable.insert(id);
        }

        Ok(stream)
    }

    /// Pushes the stream ID to the back of the flushable streams queue with
    /// the specified urgency.
    ///
    /// Note that the caller is responsible for checking that the specified
    /// stream ID was not in the queue already before calling this.
    ///
    /// Queueing a stream multiple times simultaneously means that it might be
    /// unfairly scheduled more often than other streams, and might also cause
    /// spurious cycles through the queue, so it should be avoided.
    pub fn push_flushable(&mut self, stream_id: u64, urgency: u8, incr: bool) {
        // Push the element to the back of the queue corresponding to the given
        // urgency. If the queue doesn't exist yet, create it first.
        let queues = self
            .flushable
            .entry(urgency)
            .or_insert_with(|| (BinaryHeap::new(), VecDeque::new()));

        if !incr {
            // Non-incremental streams are scheduled in order of their stream ID.
            queues.0.push(std::cmp::Reverse(stream_id))
        } else {
            // Incremental streams are scheduled in a round-robin fashion.
            queues.1.push_back(stream_id)
        };
    }

    /// Returns the first stream ID from the flushable streams
    /// queue with the highest urgency.
    ///
    /// Note that if the stream is no longer flushable after sending some of its
    /// outstanding data, it needs to be removed from the queue.
    pub fn peek_flushable(&mut self) -> Option<u64> {
        self.flushable.iter_mut().next().and_then(|(_, queues)| {
            queues.0.peek().map(|x| x.0).or_else(|| {
                // When peeking incremental streams, make sure to move the current
                // stream to the end of the queue so they are pocesses in a round
                // robin fashion
                if let Some(current_incremental) = queues.1.pop_front() {
                    queues.1.push_back(current_incremental);
                    Some(current_incremental)
                } else {
                    None
                }
            })
        })
    }

    /// Remove the last peeked stream
    pub fn remove_flushable(&mut self) {
        let mut top_urgency = self
            .flushable
            .first_entry()
            .expect("Remove previously peeked stream");

        let queues = top_urgency.get_mut();
        queues.0.pop().map(|x| x.0).or_else(|| queues.1.pop_back());
        // Remove the queue from the list of queues if it is now empty, so that
        // the next time `pop_flushable()` is called the next queue with elements
        // is used.
        if queues.0.is_empty() && queues.1.is_empty() {
            top_urgency.remove();
        }
    }

    /// Adds or removes the stream ID to/from the readable streams set.
    ///
    /// If the stream was already in the list, this does nothing.
    pub fn mark_readable(&mut self, stream_id: u64, readable: bool) {
        if readable {
            self.readable.insert(stream_id);
        } else {
            self.readable.remove(&stream_id);
        }
    }

    /// Adds or removes the stream ID to/from the writable streams set.
    ///
    /// This should also be called anytime a new stream is created, in addition
    /// to when an existing stream becomes writable (or stops being writable).
    ///
    /// If the stream was already in the list, this does nothing.
    pub fn mark_writable(&mut self, stream_id: u64, writable: bool) {
        if writable {
            self.writable.insert(stream_id);
        } else {
            self.writable.remove(&stream_id);
        }
    }

    /// Adds or removes the stream ID to/from the almost full streams set.
    ///
    /// If the stream was already in the list, this does nothing.
    pub fn mark_almost_full(&mut self, stream_id: u64, almost_full: bool) {
        if almost_full {
            self.almost_full.insert(stream_id);
        } else {
            self.almost_full.remove(&stream_id);
        }
    }

    /// Adds or removes the stream ID to/from the blocked streams set with the
    /// given offset value.
    ///
    /// If the stream was already in the list, this does nothing.
    pub fn mark_blocked(&mut self, stream_id: u64, blocked: bool, off: u64) {
        if blocked {
            self.blocked.insert(stream_id, off);
        } else {
            self.blocked.remove(&stream_id);
        }
    }

    /// Adds or removes the stream ID to/from the reset streams set with the
    /// given error code and final size values.
    ///
    /// If the stream was already in the list, this does nothing.
    pub fn mark_reset(
        &mut self, stream_id: u64, reset: bool, error_code: u64, final_size: u64,
    ) {
        if reset {
            self.reset.insert(stream_id, (error_code, final_size));
        } else {
            self.reset.remove(&stream_id);
        }
    }

    /// Adds or removes the stream ID to/from the stopped streams set with the
    /// given error code.
    ///
    /// If the stream was already in the list, this does nothing.
    pub fn mark_stopped(
        &mut self, stream_id: u64, stopped: bool, error_code: u64,
    ) {
        if stopped {
            self.stopped.insert(stream_id, error_code);
        } else {
            self.stopped.remove(&stream_id);
        }
    }

    /// Updates the peer's maximum bidirectional stream count limit.
    pub fn update_peer_max_streams_bidi(&mut self, v: u64) {
        self.peer_max_streams_bidi = cmp::max(self.peer_max_streams_bidi, v);
    }

    /// Updates the peer's maximum unidirectional stream count limit.
    pub fn update_peer_max_streams_uni(&mut self, v: u64) {
        self.peer_max_streams_uni = cmp::max(self.peer_max_streams_uni, v);
    }

    /// Commits the new max_streams_bidi limit.
    pub fn update_max_streams_bidi(&mut self) {
        self.local_max_streams_bidi = self.local_max_streams_bidi_next;
    }

    /// Returns the current max_streams_bidi limit.
    pub fn max_streams_bidi(&self) -> u64 {
        self.local_max_streams_bidi
    }

    /// Returns the new max_streams_bidi limit.
    pub fn max_streams_bidi_next(&mut self) -> u64 {
        self.local_max_streams_bidi_next
    }

    /// Commits the new max_streams_uni limit.
    pub fn update_max_streams_uni(&mut self) {
        self.local_max_streams_uni = self.local_max_streams_uni_next;
    }

    /// Returns the new max_streams_uni limit.
    pub fn max_streams_uni_next(&mut self) -> u64 {
        self.local_max_streams_uni_next
    }

    /// Returns the number of bidirectional streams that can be created
    /// before the peer's stream count limit is reached.
    pub fn peer_streams_left_bidi(&self) -> u64 {
        self.peer_max_streams_bidi - self.local_opened_streams_bidi
    }

    /// Returns the number of unidirectional streams that can be created
    /// before the peer's stream count limit is reached.
    pub fn peer_streams_left_uni(&self) -> u64 {
        self.peer_max_streams_uni - self.local_opened_streams_uni
    }

    /// Drops completed stream.
    ///
    /// This should only be called when Stream::is_complete() returns true for
    /// the given stream.
    pub fn collect(&mut self, stream_id: u64, local: bool) {
        if !local {
            // If the stream was created by the peer, give back a max streams
            // credit.
            if is_bidi(stream_id) {
                self.local_max_streams_bidi_next =
                    self.local_max_streams_bidi_next.saturating_add(1);
            } else {
                self.local_max_streams_uni_next =
                    self.local_max_streams_uni_next.saturating_add(1);
            }
        }

        self.mark_readable(stream_id, false);
        self.mark_writable(stream_id, false);

        self.streams.remove(&stream_id);
        self.collected.insert(stream_id);
    }

    /// In case a stream is created before the packet could have been
    /// authenticated; we need to collect it without remembering it.
    pub fn collect_on_recv_error(&mut self, stream_id: u64) {
        self.mark_readable(stream_id, false);
        self.mark_writable(stream_id, false);
        self.streams.remove(&stream_id);
    }

    /// Creates an iterator over streams that have outstanding data to read.
    pub fn readable(&self) -> StreamIter {
        StreamIter::from(&self.readable)
    }

    /// Creates an iterator over streams that can be written to.
    pub fn writable(&self) -> StreamIter {
        StreamIter::from(&self.writable)
    }

    /// Creates an iterator over streams that need to send MAX_STREAM_DATA.
    pub fn almost_full(&self) -> StreamIter {
        StreamIter::from(&self.almost_full)
    }

    /// Creates an iterator over streams that need to send STREAM_DATA_BLOCKED.
    pub fn blocked(&self) -> hash_map::Iter<u64, u64> {
        self.blocked.iter()
    }

    /// Creates an iterator over streams that need to send RESET_STREAM.
    pub fn reset(&self) -> hash_map::Iter<u64, (u64, u64)> {
        self.reset.iter()
    }

    /// Creates an iterator over streams that need to send STOP_SENDING.
    pub fn stopped(&self) -> hash_map::Iter<u64, u64> {
        self.stopped.iter()
    }

    /// Returns true if the stream has been collected.
    pub fn is_collected(&self, stream_id: u64) -> bool {
        self.collected.contains(&stream_id)
    }

    /// Returns true if there are any streams that have data to write.
    pub fn has_flushable(&self) -> bool {
        !self.flushable.is_empty()
    }

    /// Returns true if there are any streams that have data to read.
    pub fn has_readable(&self) -> bool {
        !self.readable.is_empty()
    }

    /// Returns true if there are any streams that need to update the local
    /// flow control limit.
    pub fn has_almost_full(&self) -> bool {
        !self.almost_full.is_empty()
    }

    /// Returns true if there are any streams that are blocked.
    pub fn has_blocked(&self) -> bool {
        !self.blocked.is_empty()
    }

    /// Returns true if there are any streams that are reset.
    pub fn has_reset(&self) -> bool {
        !self.reset.is_empty()
    }

    /// Returns true if there are any streams that need to send STOP_SENDING.
    pub fn has_stopped(&self) -> bool {
        !self.stopped.is_empty()
    }

    /// Returns true if the max bidirectional streams count needs to be updated
    /// by sending a MAX_STREAMS frame to the peer.
    pub fn should_update_max_streams_bidi(&self) -> bool {
        self.local_max_streams_bidi_next != self.local_max_streams_bidi &&
            self.local_max_streams_bidi_next / 2 >
                self.local_max_streams_bidi - self.peer_opened_streams_bidi
    }

    /// Returns true if the max unidirectional streams count needs to be updated
    /// by sending a MAX_STREAMS frame to the peer.
    pub fn should_update_max_streams_uni(&self) -> bool {
        self.local_max_streams_uni_next != self.local_max_streams_uni &&
            self.local_max_streams_uni_next / 2 >
                self.local_max_streams_uni - self.peer_opened_streams_uni
    }

    /// Returns the number of active streams in the map.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.streams.len()
    }

    /// Rewind the Stream_id's receive buffer of num bytes
    pub fn rewind_recv_buf(&mut self, _stream_id: u64, _num: usize) -> Result<()> {
        Ok(())
    }

   

}
