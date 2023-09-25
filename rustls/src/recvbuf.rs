use std::cmp;
use std::collections::VecDeque;
use std::io;
use std::io::Read;
use crate::tcpls::stream;
use crate::tcpls::stream::{RecvBuf, Stream};

/// This is the receive buffer of a stream
pub struct RecvBuffer {
    data: Vec<u8>,
    /// where the next chunk will be appended
    offset: u64,
    chuncks: VecDeque<crate::>,
}

impl RecvBuffer {
    pub(crate) fn new(limit: Option<usize>) -> Self {
        Self {
            data: Vec::with_capacity(match limit {
                Some( l ) => l,
                None => stream::DEFAULT_BUFFER_LIMIT,
            }),
            offset: 0,
        }
    }

    pub  fn get_offset(&self) -> u64 {
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

    pub fn consume(&mut self, mut used: usize) {
        while let Some(mut buf) = self.chunks.pop_front() {
            if used < buf.len() {
                self.chunks
                    .push_front(buf.split_off(used));
                break;
            } else {
                used -= buf.len();
            }
        }
    }

    /// Read data out of this object, passing it `wr`
    pub fn write_to(&mut self, wr: &mut dyn io::Write) -> io::Result<usize> {
        if self.is_empty() {
            return Ok(0);
        }

        let mut bufs = [io::IoSlice::new(&[]); 64];
        for (iov, chunk) in bufs.iter_mut().zip(self.chunks.iter()) {
            *iov = io::IoSlice::new(chunk);
        }
        let len = cmp::min(bufs.len(), self.chunks.len());
        let used = wr.write_vectored(&bufs[..len])?;
        self.consume(used);
        Ok(used)
    }
}

#[cfg(test)]
mod test {
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
