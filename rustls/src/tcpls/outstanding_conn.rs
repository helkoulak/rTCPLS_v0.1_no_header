use std::io;
use std::io::Read;
use mio::net::TcpStream;
use crate::msgs::fragmenter::MAX_FRAGMENT_LEN;
use crate::tcpls::stream::SimpleIdHashMap;

pub struct OutstandingTcpConn {
    pub socket: TcpStream,

    /// Temporary receive buffer to receive the fake ch/sh messages on.
    /// It will be deallocated after joining the outstanding tcp connection to the tcpls session
    pub rcv_buf: Vec<u8>,

    pub used: usize,

    pub request_sent: bool,
}

impl OutstandingTcpConn {

    pub fn new(socket: TcpStream) -> Self {
        Self{
            socket,
            rcv_buf: vec![0u8; MAX_FRAGMENT_LEN],
            used: 0,
            request_sent: false,
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
            wants_write = wants_write || (self.map.get(send.0).unwrap().request_sent == false);
        }
        wants_write
    }

    pub fn wants_read(&self) -> bool {
        let mut all_empty = false;
        for send in &self.map {
            all_empty = all_empty || self.map.get(send.0).unwrap().rcv_buf.is_empty();
        }
        all_empty
    }

}
