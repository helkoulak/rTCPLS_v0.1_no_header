use std::io;
use std::io::{Read, Write};
use mio::net::TcpStream;
use crate::msgs::fragmenter::MAX_FRAGMENT_LEN;
use crate::tcpls::stream::SimpleIdHashMap;
use crate::vecbuf::ChunkVecBuffer;

pub struct OutstandingTcpConn {
    pub socket: TcpStream,

    /// Temporary receive buffer to receive the fake ch/sh messages on.
    /// It will be deallocated after joining the outstanding tcp connection to the tcpls session
    pub rcv_buf: Vec<u8>,
    /// Store join request if request sent before TLS handshake ends
    pub send_buf: ChunkVecBuffer,

    pub used: usize,
}

impl OutstandingTcpConn {

    pub fn new(socket: TcpStream) -> Self {
        Self{
            socket,
            rcv_buf: vec![0u8; MAX_FRAGMENT_LEN],
            send_buf: ChunkVecBuffer::new(Some(MAX_FRAGMENT_LEN)),
            used: 0,
        }
    }

    pub fn receive_join_request(&mut self) -> Result<usize, io::Error>{
        let read = match self.socket.read(&mut self.rcv_buf) {
            Ok(read) => read,
            Err(e) => return Err(e),
        };
        self.used += read;
        Ok(read)
    }

    pub fn buffer_request(&mut self, buf: Vec<u8>) {
        self.send_buf.append(buf);
    }


}
#[derive(Default)]
pub struct OutstandingConnMap {
    map: SimpleIdHashMap<OutstandingTcpConn>
}

impl OutstandingConnMap {
    pub fn as_mut_ref(&mut self) -> &mut SimpleIdHashMap<OutstandingTcpConn> {
        &mut self.map
    }

    pub fn wants_write(&self) -> bool {
        let mut wants_write = false;
        for send in &self.map {
            wants_write = wants_write || !self.map.get(send.0).unwrap().send_buf.is_empty();
        }
        wants_write
    }

    pub fn wants_read(&self) -> bool {
        let mut all_empty = false;
        for send in &self.map {
            all_empty = all_empty || self.map.get(send.0).unwrap().send_buf.is_empty();
        }
        all_empty
    }

    pub fn flush_requests(&mut self) {
        let keys: Vec<_> = self.map.keys().cloned().collect();
        for key in keys   {
            while let Some(buf) = self.map.get_mut(&key).unwrap().send_buf.pop() {
                self.map.get_mut(&key).unwrap().socket.write(buf.as_slice()).expect("send join request on socket failed");
            }
        }
    }



}
