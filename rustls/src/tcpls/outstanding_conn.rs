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
    /// Store join request if request sent before TLS handshake ends
    pub send_buf: Vec<u8>,

    pub used: usize,
}

impl OutstandingTcpConn {

    pub fn new(socket: TcpStream) -> Self {
        Self{
            socket,
            rcv_buf: vec![0u8; MAX_FRAGMENT_LEN],
            send_buf: Vec::new(),
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

    pub fn buffer_request(&mut self, buf: &[u8]) {
        self.send_buf.extend_from_slice(buf)
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

}
