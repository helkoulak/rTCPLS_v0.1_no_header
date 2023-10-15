use std::cmp;
use crate::tcpls::stream::DEFAULT_BUFFER_LIMIT;

/// This is the receive buffer of a stream
#[derive(Default)]
pub struct RecvBuffer {
    id: u64,
    data: Vec<u8>,
    /// where the next chunk will be appended
    pub offset: usize,

    // Length of last copied data chunk
    len: usize,

    /// indicates to which offset data within outbuf has already been marked consumed by the
    /// application. V3 specific.
    consumed: usize,
}

impl RecvBuffer {
    /// create a new instance of RecvBuffer
    pub fn new(stream_id: u64, capacity: Option<usize>) -> RecvBuffer {
        if let Some(capacity) = capacity {
            let mut appbuf = RecvBuffer {
                id: stream_id,
                data :vec![0; capacity],
                ..Default::default()
            };
            // set_len is safe assuming
            // 1) the data is initialized
            // 2) the new len is <= capacity
            unsafe { appbuf.data.set_len(capacity) };
            appbuf
        } else {
            let mut appbuf = RecvBuffer {
                id: stream_id,
                data: vec![0; DEFAULT_BUFFER_LIMIT],
                ..Default::default()
            };
            unsafe { appbuf.data.set_len(DEFAULT_BUFFER_LIMIT) };
            appbuf
        }
    }
    pub fn get_mut(&mut self) -> &mut [u8] {
        &mut self.data[self.offset..]
    }

    pub fn get_mut_consumed(&mut self) -> &mut [u8] {
        &mut self.data[self.consumed..]
    }

    pub  fn get_offset(&self) -> usize {
        self.offset
    }

    pub  fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub  fn is_full(&self) -> bool {
     self.data.len() >= self.data.capacity()
    }

    /// How many bytes we're storing
    pub fn len(&self) -> usize {
       self.data.len()
    }

    /// For a proposed write of `len` bytes, how many
    /// bytes should we actually write to adhere to the
    /// capacity of the buffer?
    pub  fn apply_limit(&self, len: usize) -> usize {
        let space = self.data.capacity().saturating_sub(self.len());
        cmp::min(len, space)

    }

    pub fn consume(&mut self, used: usize) {
        self.offset += used;
    }

    pub fn truncate_processed(&mut self, processed: usize) { self.offset -= processed; }


    pub fn data_length(&self) -> usize {
        self.offset
    }
}

#[cfg(test)]
mod test {
    use crate::vecbuf::ChunkVecBuffer;
    use super::ChunkVecBuffer;

    #[test]
    fn short_append_copy_with_limit() {
        let mut cvb = ChunkVecBuffer::new(Some(12));
        assert_eq!(cvb.append_limited_copy(b"hello"), 5);
        assert_eq!(cvb.append_limited_copy(b"world"), 5);
        assert_eq!(cvb.append_limited_copy(b"hello"), 2);
        assert_eq!(cvb.append_limited_copy(b"world"), 0);

        let mut buf = [0u8; 12];
        assert_eq!(cvb.read(&mut buf).unwrap(), 12);
        assert_eq!(buf.to_vec(), b"helloworldhe".to_vec());
    }

    #[cfg(read_buf)]
    #[test]
    fn read_buf() {
        use std::{io::BorrowedBuf, mem::MaybeUninit};

        {
            let mut cvb = ChunkVecBuffer::new(None);
            cvb.append(b"test ".to_vec());
            cvb.append(b"fixture ".to_vec());
            cvb.append(b"data".to_vec());

            let mut buf = [MaybeUninit::<u8>::uninit(); 8];
            let mut buf: BorrowedBuf<'_> = buf.as_mut_slice().into();
            cvb.read_buf(buf.unfilled()).unwrap();
            assert_eq!(buf.filled(), b"test fix");
            buf.clear();
            cvb.read_buf(buf.unfilled()).unwrap();
            assert_eq!(buf.filled(), b"ture dat");
            buf.clear();
            cvb.read_buf(buf.unfilled()).unwrap();
            assert_eq!(buf.filled(), b"a");
        }

        {
            let mut cvb = ChunkVecBuffer::new(None);
            cvb.append(b"short message".to_vec());

            let mut buf = [MaybeUninit::<u8>::uninit(); 1024];
            let mut buf: BorrowedBuf<'_> = buf.as_mut_slice().into();
            cvb.read_buf(buf.unfilled()).unwrap();
            assert_eq!(buf.filled(), b"short message");
        }
    }
}
