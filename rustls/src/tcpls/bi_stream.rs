use std::collections::HashMap;
use crate::vecbuf::ChunkVecBuffer;

pub const DEFAULT_BUFFER_LIMIT: usize = 64 * 1024;


pub struct BiStream {

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
    pub(crate) received_plaintext: ChunkVecBuffer,
    /// buffers data to be sent if TLS handshake is still ongoing
    pub(crate) sendable_plaintext: ChunkVecBuffer,
    /// buffers encrypted TLS records that to be sent on the TCP socket
    pub(crate) sendable_tls: ChunkVecBuffer,

}

impl BiStream {
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

pub struct StreamMap {
    pub streams: HashMap<u32, BiStream>,
}

impl StreamMap {

    /// Build stream map with 0 as the id for default tcp connection
    pub fn build_stream_map() -> Self {
        let mut map = HashMap::new();
        let stream = BiStream::new(0);
        map.insert(0, stream);
        Self {
            streams: map,
        }

    }

    pub fn open_stream(&mut self, id: u32){

        self.streams.insert(id, BiStream::new(id));
    }

   

}
