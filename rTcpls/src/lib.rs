
pub mod common {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use mio::net::TcpStream;
    use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection, ServerName};
    use rustls::internal::msgs::handshake::SessionId;
    use crate::common::TlsContext::TlsClient;


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
        streams: Vec<TcpStream>,

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
