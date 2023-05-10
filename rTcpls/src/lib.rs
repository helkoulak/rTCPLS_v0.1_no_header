
pub mod common {
    use std::net::{IpAddr, SocketAddr};
    use std::sync::Arc;
    use mio::net::TcpStream;
    use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection, ServerName};
    use rustls::internal::msgs::handshake::SessionId;
    use crate::common::TlsContext::TlsClient;

    pub enum TcplsFrame<'a> {
        Padding(PaddingFrame),
        Ping(PingFrame),
        Stream(StreamFrame<'a>),
        ACK(AckFrame),
        NewToken(NewTokenFrame<'a>),
        ConnectionReset(ConnectionResetFrame),
        NewAddress(NewAddressFrame),
        RemoveAddress(RemoveAddressFrame),
        StreamChange(StreamChangeFrame),
    }


    pub struct PaddingFrame {
        frame_type: u8,
    }

    pub struct PingFrame{
        frame_type: u8,
    }

    pub struct StreamFrame<'a>{
        stream_data: &'a mut [u8],
        length: u16,
        offset: u64,
        stream_id: u32,
        type_with_lsb_fin: u8,
    }

    pub struct AckFrame{
        highest_record_sn_received: u64,
        connection_id: u32,
        frame_type: u8,
    }

    pub struct NewTokenFrame<'a>{
        token: &'a mut [u8; 32],
        sequence: u8,
        frame_type: u8,
    }

    pub struct ConnectionResetFrame {
        connection_id: u32,
        frame_type: u8,
    }

    pub struct NewAddressFrame{
        port: u16,
        address: IpAddr,
        address_version: u8,
        address_id: u8,
        frame_type: u8,
    }

    pub struct RemoveAddressFrame{
        address_id: u8,
        frame_type: u8,
    }

    pub struct StreamChangeFrame{
        next_record_stream_id: u32,
        next_offset: u64,
        frame_type: u8,
    }


    pub struct TcplsSession {
        tcp_connections: Vec<TcpConnection>,
        next_connection_id: i32,
        tls_ctx: TlsContext,
        local_addresses: Vec<SocketAddr>,
        next_local_address_id: i8,
        remote_addresses: Vec<SocketAddr>,
        next_remote_address_id: i8,
        next_stream_id: i32,
        is_server: bool,
        is_closed: bool,
    }

    pub struct TcpConnection{
        connection_id: i32,
        connection_fd: u32,
        local_address_id: u8,
        remote_address_id: u8,
        is_closed: bool,
        peer_address: SocketAddr,
        peer_address_len: u32,
        attached_streams: Vec<TcpStream>,
    }

    pub struct TlsContext{
        tls_client: ClientConnection,
        tls_client_config: ClientConfig,
        tls_server: ServerConnection,
        tls_server_config: ServerConfig,
        server_name: ServerName,
    }



}




pub mod client {



}


pub mod server {



}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
