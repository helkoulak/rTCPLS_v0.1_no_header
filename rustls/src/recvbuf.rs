use std::cmp;
use std::collections::hash_map;
use crate::tcpls::stream::{DEFAULT_BUFFER_LIMIT, SimpleIdHashMap};

/// This is the receive buffer of a stream
#[derive(Default)]
pub struct RecvBuf {
    pub id: u64,
    data: Vec<u8>,
    /// where the next chunk will be appended
    pub offset: u64,

    // Length of last copied data chunk
    len: usize,

    /// indicates to which offset data within outbuf has already been marked consumed by the
    /// application. V3 specific.
    consumed: usize,

    pub next_recv_pkt_num: u32,
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

    pub fn as_ref(&mut self) -> & [u8] {
        & self.data[self.offset as usize..]
    }

    pub fn get_mut_consumed(&mut self) -> &mut [u8] {
        &mut self.data[self.consumed..]
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

    pub fn consume(&mut self, used: usize) {
        self.offset += used as u64;
    }

    pub fn truncate_processed(&mut self, processed: usize) { self.offset -= processed as u64; }


    pub fn data_length(&self) -> u64 {
        self.offset
    }
}

#[derive(Default)]
pub struct RecvBufMap {
    buffers: SimpleIdHashMap<RecvBuf>,
}

impl RecvBufMap {

    pub fn new() -> RecvBufMap {
        RecvBufMap {
            ..Default::default()
        }
    }


    pub(crate) fn get_or_create_recv_buffer(&mut self, stream_id: u64, capacity: Option<usize>) -> &mut RecvBuf {
        match self.buffers.entry(stream_id) {
            hash_map::Entry::Vacant(v) => {
                v.insert(RecvBuf::new(stream_id, capacity))
            },
            hash_map::Entry::Occupied(v) => v.into_mut(),
        }
    }


    /*pub fn get_mut(&mut self, stream_id: u64) -> Option<&mut [u8]> {
        Some(self.buffers.get_mut(&stream_id)?

    }*/

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

#[cfg(test)]
mod test {
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
