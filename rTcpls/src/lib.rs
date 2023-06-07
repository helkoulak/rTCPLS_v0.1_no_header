

    use std::fs;
    use std::io::BufReader;
    use std::net::{IpAddr, SocketAddr};
    use std::sync::Arc;

    use mio::net::TcpStream;
    use rustls::internal::record_layer::RecordLayer;
    use rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore, ServerConfig, ServerName, Error};
    use rustls::tcpls::{ClientConnection};
    use std::cell::Ref;
    use std::ptr::addr_of_mut;


    pub mod common {
        use rustls::tcpls::ServerConnection;
        use super::*;


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

        pub struct PingFrame {
            frame_type: u8,
        }

        pub struct StreamFrame<'a> {
            stream_data: &'a mut [u8],
            length: u16,
            offset: u64,
            stream_id: u32,
            type_with_lsb_fin: u8,
        }

        pub struct AckFrame {
            highest_record_sn_received: u64,
            connection_id: u32,
            frame_type: u8,
        }

        pub struct NewTokenFrame<'a> {
            token: &'a mut [u8; 32],
            sequence: u8,
            frame_type: u8,
        }

        pub struct ConnectionResetFrame {
            connection_id: u32,
            frame_type: u8,
        }

        pub struct NewAddressFrame {
            port: u16,
            address: IpAddr,
            address_version: u8,
            address_id: u8,
            frame_type: u8,
        }

        pub struct RemoveAddressFrame {
            address_id: u8,
            frame_type: u8,
        }

        pub struct StreamChangeFrame {
            next_record_stream_id: u32,
            next_offset: u64,
            frame_type: u8,
        }


        pub struct TcplsSession {
            tls_ctx: TlsConnection,
            tcpls_connections: Vec<TcplsConnection>,
            next_connection_id: i32,
            local_addresses: Vec<SocketAddr>,
            next_local_address_id: i8,
            addresses_advertised: Vec<SocketAddr>,
            remote_addresses: Vec<SocketAddr>,
            next_remote_address_id: i8,
            next_stream_id: i32,
            is_server: bool,
            is_closed: bool,
        }

        impl TcplsSession {


        }

        pub enum TcplsConnectionState {
            CLOSED,
            FAILED,
            CONNECTING,
            CONNECTED,
            JOINED,
        }

        pub struct TcplsConnection {
            connection_id: u32,
            connection_fd: u32,
            local_address_id: u8,
            remote_address_id: u8,
            peer_address: SocketAddr,
            peer_address_len: u32,
            is_closed: bool,
            attached_streams: Vec<TcplsStream>,
            tcpls_conn_state: TcplsConnectionState,
            encryption_ctx: RecordLayer,
            decryption_ctx: RecordLayer,
            nbr_bytes_received: u32,
            // nbr records received on this con since the last ack sent
            nbr_records_received: u32,
            // nbr records received on this con since the last ack sent
            is_primary: bool,
            // Is this connection the default one?
            state: TcplsConnectionState,
        }


        pub struct TcplsStream {
            stream_id: u32,
            /** when this stream should first send an attach event before
                     * sending any packet */
            need_sending_attach_event: u32,
            /**
             * As soon as we have sent a stream attach event to the other peer, this
             * stream is usable
             */
            stream_usable: bool,

            /**
             * the stream should be cleaned up the next time tcpls_send is called
             */
            marked_for_close: bool,

            /**
             * Whether we still have to initialize the aead context for this stream.
             * That may happen if this stream is created before the handshake took place.
             */
            aead_initialized: bool,

        }


        pub enum TlsConnection {
            /// A client connection
            Client(ClientConnection),
            /// A server connection
            Server(ServerConnection),
        }
        impl TlsConnection {


        }



        pub struct TlsClientConfig{

        }


        pub fn tcpls_new_session(client_config: Arc<ClientConfig>, server_config: Arc<ServerConfig>, name: ServerName, isServer: bool){



        }



        pub fn lookup_ipv4(host: &str, port: u16) -> SocketAddr {
            use std::net::ToSocketAddrs;

            let addrs = (host, port).to_socket_addrs().unwrap();
            for addr in addrs {
                if let SocketAddr::V4(_) = addr {
                    return addr;
                }
            }

            unreachable!("Cannot lookup address");
        }


        pub fn build_cert_store(cert_file_path: Option<&String>, cert_store: Option<RootCertStore>) -> RootCertStore {
            let mut root_store = RootCertStore::empty();

            if cert_file_path.is_some(){
                let ca_path = cert_file_path.unwrap();

                let cert_file = fs::File::open(ca_path).expect("Cannot open CA file");
                let mut reader = BufReader::new(cert_file);
                root_store.add_parsable_certificates(&rustls_pemfile::certs(&mut reader).unwrap());

            } else if cert_store.is_some(){
                root_store = cert_store.unwrap();
            } else {
                    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
                        OwnedTrustAnchor::from_subject_spki_name_constraints(
                            ta.subject,
                            ta.spki,
                            ta.name_constraints,
                        )
                    }));
            }

            root_store
        }


        /// Find a ciphersuite with the given name
        pub fn find_suite(name: &str) -> Option<rustls::SupportedCipherSuite> {
            for suite in rustls::ALL_CIPHER_SUITES {
                let sname = format!("{:?}", suite.suite()).to_lowercase();

                if sname == name.to_string().to_lowercase() {
                    return Some(*suite);
                }
            }

            None
        }

        /// Make a vector of ciphersuites named in `suites`
        pub fn lookup_suites(suites: &[String]) -> Vec<rustls::SupportedCipherSuite> {
            let mut out = Vec::new();

            for csname in suites {
                let scs = find_suite(csname);
                match scs {
                    Some(s) => out.push(s),
                    None => panic!("cannot look up ciphersuite '{}'", csname),
                }
            }

            out
        }

        /// Make a vector of protocol versions named in `versions`
        pub fn lookup_versions(versions: &[String]) -> Vec<&'static rustls::SupportedProtocolVersion> {
            let mut out = Vec::new();

            for vname in versions {
                let version = match vname.as_ref() {
                    //"1.2" => &rustls::version::TLS12,
                    "1.3" => &rustls::version::TLS13,
                    _ => panic!(
                        "cannot look up version '{}', TCPLS supports only TLS '1.3'",
                        vname
                    ),
                };
                out.push(version);
            }

            out
        }

        pub fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
            let certfile = fs::File::open(filename).expect("cannot open certificate file");
            let mut reader = BufReader::new(certfile);
            rustls_pemfile::certs(&mut reader)
                .unwrap()
                .iter()
                .map(|v| rustls::Certificate(v.clone()))
                .collect()
        }

        pub fn load_private_key(filename: &str) -> rustls::PrivateKey {
            let keyfile = fs::File::open(filename).expect("cannot open private key file");
            let mut reader = BufReader::new(keyfile);

            loop {
                match rustls_pemfile::read_one(&mut reader).expect("cannot parse private key .pem file") {
                    Some(rustls_pemfile::Item::RSAKey(key)) => return rustls::PrivateKey(key),
                    Some(rustls_pemfile::Item::PKCS8Key(key)) => return rustls::PrivateKey(key),
                    Some(rustls_pemfile::Item::ECKey(key)) => return rustls::PrivateKey(key),
                    None => break,
                    _ => {}
                }
            }

            panic!(
                "no keys found in {:?} (encrypted keys not supported)",
                filename
            );
        }


    }


    pub mod client {

        use super::*;
        use super::common::*;

        pub fn new_tls_session(config: Arc<ClientConfig>, name: ServerName) -> ClientConnection{

            rustls::tcpls::ClientConnection::new(config, name).expect("Establishing a TLS session has failed")
        }


        /// Build a `rustls::ClientConfig`
        pub fn make_tls_client_config(cert_path: Option<&String>, cert_store: Option<RootCertStore>, enable_tcpls: bool, cipher_suites: Vec<String>,
                                      protocol_ver: Vec<String>, auth_key: Option<String>, auth_certs: Option<String>,
                                      no_tickets: bool, no_sni: bool, proto: Vec<String>, insecure: bool, max_frag_size: Option<usize>) -> Arc<rustls::ClientConfig> {

            let mut root_store = build_cert_store(cert_path, cert_store);

            let suites = if !cipher_suites.is_empty() {
                lookup_suites(&cipher_suites)
            } else {
                rustls::DEFAULT_CIPHER_SUITES.to_vec()
            };

            let versions = if !protocol_ver.is_empty() {
                lookup_versions(&protocol_ver)
            } else {
                rustls::DEFAULT_VERSIONS.to_vec()
            };

            let config = rustls::ClientConfig::builder()
                .with_cipher_suites(&suites)
                .with_safe_default_kx_groups()
                .with_protocol_versions(&versions)
                .expect("inconsistent cipher-suite/versions selected")
                .with_root_certificates(root_store);

            let mut config = match (&auth_key, &auth_certs) {
                (Some(key_file), Some(certs_file)) => {
                    let certs = load_certs(certs_file);
                    let key = load_private_key(key_file);
                    config
                        .with_single_cert(certs, key)
                        .expect("invalid client auth certs/key")
                }
                (None, None) => config.with_no_client_auth(),
                (_, _) => {
                    panic!("must provide --auth-certs and --auth-key together");
                }
            };

            config.key_log = Arc::new(rustls::KeyLogFile::new());

            if no_tickets {
                config.resumption = config
                    .resumption
                    .tls12_resumption(rustls::client::Tls12Resumption::SessionIdOnly);
            }

            if no_sni {
                config.enable_sni = false;
            }

            config.alpn_protocols =
                proto.iter().map(|proto| proto.as_bytes().to_vec()).collect();

            if max_frag_size.is_some() {
                config.max_fragment_size = max_frag_size;
            }


            config.enable_tcpls = enable_tcpls;

            Arc::new(config)
        }
    }


    pub mod server {
        use rustls::ServerConnection;
        use super::*;
        use super::common::*;

        pub fn new_tls_session(config: Arc<ServerConfig>) -> rustls::tcpls::ServerConnection {

            rustls::tcpls::ServerConnection::new(config).expect("Establishing a TLS session has failed")
        }

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
