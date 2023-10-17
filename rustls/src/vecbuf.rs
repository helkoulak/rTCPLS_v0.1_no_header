use std::cmp;
use std::collections::VecDeque;
use std::io;
use std::io::Read;

/// This is a byte buffer that is built from a vector
/// of byte vectors.  This avoids extra copies when
/// appending a new byte vector, at the expense of
/// more complexity when reading out.
pub(crate) struct ChunkVecBuffer {
    buffer: VecDeque<BytesFragment>,
    limit: Option<usize>,
    /// where the next chunk will be appended
    offset: u64,
}

impl ChunkVecBuffer {
    pub(crate) fn new(limit: Option<usize>) -> Self {
        Self {
            buffer: VecDeque::new(),
            limit,
            offset: 0,
        }
    }

    pub(crate)  fn get_offset(&self) -> u64 {
        self.offset
    }

    pub(crate)  fn advance_offset(&mut self, added: u64) {
        self.offset += added;
    }

    /// Sets the upper limit on how many bytes this
    /// object can store.
    ///
    /// Setting a lower limit than the currently stored
    /// data is not an error.
    ///
    /// A [`None`] limit is interpreted as no limit.
    pub(crate)  fn set_limit(&mut self, new_limit: Option<usize>) {
        self.limit = new_limit;
    }

    /// If we're empty
    pub(crate)  fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub(crate)  fn is_full(&self) -> bool {
        self.limit
            .map(|limit| self.len() > limit)
            .unwrap_or_default()
    }

    /// How many bytes we're storing
    pub(crate) fn len(&self) -> usize {
        let mut len = 0;
        for ch in &self.buffer {
            len += ch.len;
        }
        len
    }

    /// For a proposed append of `len` bytes, how many
    /// bytes should we actually append to adhere to the
    /// currently set `limit`?
    pub(crate)  fn apply_limit(&self, len: usize) -> usize {
        if let Some(limit) = self.limit {
            let space = limit.saturating_sub(self.len());
            cmp::min(len, space)
        } else {
            len
        }
    }

    /// Append a copy of `bytes`, perhaps a prefix if
    /// we're near the limit.
    pub(crate) fn append_limited_copy(&mut self, bytes: &[u8]) -> usize {
        let take = self.apply_limit(bytes.len());
        self.append(bytes[..take].to_vec(), None, None, 0);
        take
    }

    /// Take and append the given `bytes`.
    pub(crate) fn append(&mut self, bytes: Vec<u8>, offset: Option<u64>, length: Option<usize>, fin: u8) -> usize {
        let len = bytes.len();
        
        if !bytes.is_empty() {
            let fragment = BytesFragment::new(bytes, offset, length, fin);
            self.buffer.push_back(fragment);
        }
        len
    }

    /// Take one of the chunks from this object.  This
    /// function panics if the object `is_empty`.
    pub(crate) fn pop(&mut self) -> Option<BytesFragment> {
        self.buffer.pop_front()
    }

    /// Read data out of this object, writing it into `buf`
    /// and returning how many bytes were written there.
    pub(crate) fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut offs = 0;

        while offs < buf.len() && !self.is_empty() {
            let used = self.buffer[0].fragment
                .as_slice()
                .read(&mut buf[offs..])?;

            self.consume(used);
            offs += used;
        }

        Ok(offs)
    }

    #[cfg(read_buf)]
    /// Read data out of this object, writing it into `cursor`.
    pub(crate) fn read_buf(&mut self, mut cursor: io::BorrowedCursor<'_>) -> io::Result<()> {
        while !self.is_empty() && cursor.capacity() > 0 {
            let chunk = self.buffer[0].as_slice();
            let used = std::cmp::min(chunk.len(), cursor.capacity());
            cursor.append(&chunk[..used]);
            self.consume(used);
        }

        Ok(())
    }

    pub(crate) fn consume(&mut self, mut used: usize) {
        while let Some(mut buf) = self.buffer.pop_front() {
            if used < buf.fragment.len() {
                self.buffer
                    .push_front(
                        BytesFragment::new(
                            buf.fragment.split_off(used), Some(buf.offset + used as u64), Some(buf.len - used),
                            buf.fin)
                    );
                break;
            } else {
                used -= buf.fragment.len();
            }
        }
    }

    pub(crate) fn consume_chunk(&mut self, mut used: usize, chunk: BytesFragment) {
        let mut buf = chunk;
        if used < buf.fragment.len() {
            self.buffer.push_front(BytesFragment::new(
                buf.fragment.split_off(used), Some(buf.offset + used as u64), Some(buf.len - used),
                buf.fin
            )
            );
        }
    }

    /// Read data out of this object, passing it `wr`
    pub(crate) fn write_to(&mut self, wr: &mut dyn io::Write) -> io::Result<usize> {
        if self.is_empty() {
            return Ok(0);
        }

        let mut bufs = [io::IoSlice::new(&[]); 64];
        for (iov, chunk) in bufs.iter_mut().zip(self.buffer.iter()) {
            *iov = io::IoSlice::new(&chunk.fragment);
        }
        let len = cmp::min(bufs.len(), self.buffer.len());
        let used = wr.write_vectored(&bufs[..len])?;
        self.consume(used);
        Ok(used)
    }
}

#[derive(Default)]
pub(crate) struct BytesFragment {
    pub(crate) fragment: Vec<u8>,
    /// The offset of the buffer within a stream.
    pub(crate) offset: u64,
    /// Application's data length without length of headers
    pub(crate) len: usize,
    
    pub(crate) fin: u8,
}

impl BytesFragment {
    pub(crate) fn new(fragment: Vec<u8>, off:Option<u64>, len: Option<usize>, fin: u8) -> Self {
        Self {
            fragment,
            offset: match off {
                Some(offset) => offset,
                None => 0,
            },
            len: match len {
                Some(len) => len,
                None => 0,
            },
            fin,
        }

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
            cvb.append(b"test ".to_vec(), None, None, false);
            cvb.append(b"fixture ".to_vec(), None, None, false);
            cvb.append(b"data".to_vec(), None, None, false);

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
            cvb.append(b"short message".to_vec(), None, None, false);

            let mut buf = [MaybeUninit::<u8>::uninit(); 1024];
            let mut buf: BorrowedBuf<'_> = buf.as_mut_slice().into();
            cvb.read_buf(buf.unfilled()).unwrap();
            assert_eq!(buf.filled(), b"short message");
        }
    }
}
