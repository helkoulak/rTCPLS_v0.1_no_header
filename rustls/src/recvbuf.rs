use std::{cmp, io};
use std::collections::hash_map;
use std::collections::hash_map::{Iter, IterMut};
use std::io::Error;
use crate::tcpls::stream::{DEFAULT_BUFFER_LIMIT, SimpleIdHashMap};

/// This is the receive buffer of a stream
#[derive(Default)]
#[derive(Debug)]
pub struct RecvBuf {
    pub id: u64,
    data: Vec<u8>,
    /// where the next chunk will be appended
    pub offset: u64,

    // Length of last decrypted data chunk
    len: usize,

    /// indicates to which offset data within offset has already been marked consumed by the
    /// application.
    consumed: usize,

    pub next_recv_pkt_num: u32,

    pub read_seq: u64,
}

impl RecvBuf {
    /// create a new instance of RecvBuffer
    pub fn new(stream_id: u64, capacity: Option<usize>) -> RecvBuf {
        if let Some(capacity) = capacity {
            let mut appbuf = RecvBuf {
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
            let mut appbuf = RecvBuf {
                id: stream_id,
                data: vec![0; DEFAULT_BUFFER_LIMIT],
                ..Default::default()
            };
            unsafe { appbuf.data.set_len(DEFAULT_BUFFER_LIMIT) };
            appbuf
        }
    }
    pub fn get_mut(&mut self) -> &mut [u8] {
        &mut self.data[self.offset as usize..]
    }

    pub fn as_ref(&self) -> & [u8] {
        &self.data
    }

    pub fn as_ref_consumed(&self) -> & [u8] {
        &self.data[self.consumed..self.offset as usize]
    }

    pub fn get_mut_consumed(&mut self) -> &mut [u8] {
        &mut self.data[self.consumed..]
    }

    pub  fn get_offset(&self) -> u64 {
        self.offset
    }

    pub  fn is_empty(&self) -> bool {
        self.offset == 0
    }

    pub  fn is_full(&self) -> bool {
     self.data.len() >= self.data.capacity()
    }

    /// How many bytes we're storing
    pub fn len(&self) -> usize {
        self.offset as usize
    }

    pub fn capacity(&self) -> usize {
        self.data.len() - self.offset as usize
    }

    /// For a proposed write of `len` bytes, how many
    /// bytes should we actually write to adhere to the
    /// capacity of the buffer?
    pub  fn apply_limit(&self, len: usize) -> usize {
        let space = self.capacity();
        cmp::min(len, space)

    }

    pub fn consume(&mut self, used: usize) {
        self.consumed += used;
    }

    pub fn is_consumed(&self) -> bool {
        self.consumed as u64 == self.offset
    }

    pub fn truncate_processed(&mut self, processed: usize) { self.offset -= processed as u64; }


    pub fn data_length(&self) -> u64 {
        self.offset
    }

    pub fn reset_stream(&mut self) {
        for byte in self.data.iter_mut() {
            *byte = 0;
        }
        self.offset = 0;
        self.read_seq = 0;
        self.next_recv_pkt_num = 0;
        self.consumed = 0;
        self.len = 0;
    }

    /// Read data out of this object, writing it into `buf`
    /// and returning how many bytes were written there.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {

        let to_read_length = cmp::min(buf.len(), self.as_ref_consumed().len());

        buf[..to_read_length].copy_from_slice(&self.as_ref_consumed()[..to_read_length]);
        self.consume(to_read_length);
        Ok(to_read_length)
    }
}

#[derive(Default)]
#[derive(Debug)]
pub struct RecvBufMap {
    buffers: SimpleIdHashMap<RecvBuf>,
}

impl RecvBufMap {

    pub fn new() -> RecvBufMap {
        RecvBufMap {
            ..Default::default()
        }
    }


    pub fn get_or_create_recv_buffer(&mut self, stream_id: u64, capacity: Option<usize>) -> &mut RecvBuf {
        match self.buffers.entry(stream_id) {
            hash_map::Entry::Vacant(v) => {
                v.insert(RecvBuf::new(stream_id, capacity))
            },
            hash_map::Entry::Occupied(v) => v.into_mut(),
        }
    }


    pub fn get(&self, id: u16) -> Option<&RecvBuf> {
        self.buffers.get(&(id as u64))
    }

    /// Returns the mutable stream with the given ID if it exists.
    pub fn get_mut(&mut self, id: u16) -> Option<&mut RecvBuf> {
        self.buffers.get_mut(&(id as u64))
    }

    pub fn all_empty(&self) -> bool {
        let mut all_empty = true;
        let bufs = self.buffers.iter();
        for buf in bufs {
            all_empty &= buf.1.is_empty();
        }
        all_empty
    }

    pub fn get_iter(&self) -> Iter<'_, u64, RecvBuf>{
        self.buffers.iter()
    }

    pub fn get_iter_mut(&mut self) -> IterMut<'_, u64, RecvBuf> {
        self.buffers.iter_mut()
    }

    /*pub(crate) fn read_mut(&mut self, stream_id: u64, stream: &mut Stream) -> Result<&mut [u8], Error> {
        let buf = match self.buffers.entry(stream_id) {
            hash_map::Entry::Vacant(_v) => {
                return Err(Error::RecvBufNotFound);
            }
            hash_map::Entry::Occupied(v) => v.into_mut().read_mut(&mut stream.recv)?,
        };
        Ok(buf)
    }*/

    /*pub(crate) fn has_consumed(&mut self, stream_id: u64, stream: Option<&Stream>, consumed: usize) -> Result<usize, Error>{
        match self.buffers.entry(stream_id) {
            hash_map::Entry::Occupied(v) => {
                // Registers how much the app has read on this stream buffer. If we don't
                // have a stream, it means it has been collected. We need to collect our stream
                // buffer as well assuming the application has read everything that was readable.
                let (to_collect, remaining_data) = v.into_mut().has_consumed(stream, consumed)?;
                if to_collect {
                    self.collect(stream_id);
                }
                Ok(remaining_data)
            },
            _ => Ok(0),
        }
    }*/

    /*pub(crate) fn is_consumed(&self, stream_id: u64) -> bool {
        match self.buffers.get(&stream_id) {
            Some(v) => {
                v.is_consumed()
            }
            _ => true,
        }
    }*/

    /* pub fn collect(&mut self, stream_id: u64) {
         if let Some(mut buf) = self.buffers.remove(&stream_id) {
             if self.recycled_buffers.len() < self.recycled_buffers.capacity() {
                 buf.clear();
                 self.recycled_buffers.push_back(buf);
             }
         }
     }*/

}

pub struct ReaderAppBufs {
    pub peer_cleanly_closed: bool,
    pub has_seen_eof: bool,
}

impl ReaderAppBufs {
    pub fn read_app_bufs(&mut self, buf: &mut [u8], app_bufs: &mut RecvBufMap, id: u16) -> io::Result<usize> {
        let len = app_bufs.get_or_create_recv_buffer(id as u64, None).read(buf)?;

        if len == 0 && !buf.is_empty() {
            // No bytes available:
            match (self.peer_cleanly_closed, self.has_seen_eof) {
                // cleanly closed; don't care about TCP EOF: express this as Ok(0)
                (true, _) => {}
                // unclean closure
                (false, true) => return Err(io::ErrorKind::UnexpectedEof.into()),
                // connection still going, but need more data: signal `WouldBlock` so that
                // the caller knows this
                (false, false) => return Err(io::ErrorKind::WouldBlock.into()),
            }
        }

        Ok(len)
    }
}

#[cfg(test)]
mod test {
    use crate::recvbuf::RecvBuf;
    use crate::tcpls::stream::DEFAULT_BUFFER_LIMIT;
    use crate::vecbuf::ChunkVecBuffer;

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
    #[test]
    fn test_reset_stream() {
        let mut vector = vec![0x0A; DEFAULT_BUFFER_LIMIT];
        let mut stream = RecvBuf::new(0, Some(DEFAULT_BUFFER_LIMIT));
        stream.data.copy_from_slice(vector.as_slice());
        stream.len = 1234;
        stream.next_recv_pkt_num = 95475;
        stream.read_seq = 65454;
        stream.consumed = 54455;
        stream.offset = 412;

        stream.reset_stream();

        assert!(stream.data.iter().all(|&x| x == 0));
        assert_eq!(stream.read_seq, 0);
        assert_eq!(stream.offset, 0);
        assert_eq!(stream.next_recv_pkt_num, 0);
        assert_eq!(stream.consumed, 0);
        assert_eq!(stream.len, 0);
    }

    #[test]
    fn test_read_in_external_buffer() {
        // test reading in an external buffer that is double the size of the receive buffer
        let mut buffer = vec![0u8; DEFAULT_BUFFER_LIMIT * 2];
        let mut stream = RecvBuf::new(0, Some(DEFAULT_BUFFER_LIMIT));
        stream.data.fill(0x0A);
        stream.offset += DEFAULT_BUFFER_LIMIT as u64;
        let mut data_read = stream.read(&mut buffer).unwrap();

        assert_eq!(data_read, stream.data.len());
        assert_eq!(buffer[..data_read], stream.data);
        assert_eq!(stream.read(&mut buffer).unwrap(), 0);
        // test reading in a buffer smaller than the receive buffer
        buffer = vec![0u8; 100];

        stream.consumed = 0;

        let mut data_read = stream.read(&mut buffer).unwrap();

        assert_eq!(data_read, buffer.len());
        assert_eq!(buffer, stream.data[..data_read]);

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
