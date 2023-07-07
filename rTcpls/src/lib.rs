

    use std::fs;
    use std::io::BufReader;
    use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
    use std::sync::Arc;
    use std::str::FromStr;
    use std::cell::Ref;
    use std::ptr::addr_of_mut;



    use mio::net::TcpStream;
    use rustls::internal::record_layer::RecordLayer;
    use rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore, ServerConfig, ServerName, Error};
    use rustls::tcpls::{ClientConnection};

    use crate::common::TcplsSession;


    pub mod common {
        use std::net::{Ipv4Addr, Ipv6Addr};
        use rustls::tcpls::{Connection, ServerConnection};
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
            // pub tls_ctx: Option<>
            pub tcpls_connections: Option<Vec<u32, &'static mut TcpConnection>>,
            pub next_connection_id: u32,
            pub local_addresses_ip4: Option<Vec<Ipv4Addr>>,
            pub local_addresses_ip6: Option<Vec<Ipv6Addr>>,
            pub next_local_address_id: u8,
            pub addresses_advertised: Option<Vec<SocketAddr>>,
            pub remote_addresses_ip4: Option<Vec<Ipv4Addr>>,
            pub remote_addresses_ip6: Option<Vec<Ipv6Addr>>,
            pub next_remote_address_id: u8,
            pub next_stream_id: u32,
            pub is_server: bool,
            pub is_closed: bool,
            pub tls_hs_completed: bool,
        }

        impl TcplsSession {
            pub fn new() -> Self{
                Self{
                    // tls_ctx: None,
                    tcpls_connections: None,
                    next_connection_id: 0,
                    local_addresses_ip4: None,
                    local_addresses_ip6: None,
                    next_local_address_id: 0,
                    addresses_advertised: None,
                    remote_addresses_ip4: None,
                    remote_addresses_ip6: None,
                    next_remote_address_id: 0,
                    next_stream_id: 0,
                    is_server: false,
                    is_closed: false,
                    tls_hs_completed: false,
                }
            }



        }


        pub struct TcpConnection {
            pub connection_id: u32,
            pub socket: Option<TcpStream>,
            pub local_address_id: u8,
            pub remote_address_id: u8,
            pub local_address: Option<SocketAddr>,
            pub peer_address: Option<SocketAddr>,
            pub is_closed: bool,
            pub attached_streams: Option<Vec<Stream>>,
            // pub encryption_ctx: Option<Tls13MessageEncrypter>,
            // pub decryption_ctx: Option<Tls13MessageDecrypter>,
            pub nbr_bytes_received: u32,
            // nbr records received on this con since the last ack sent
            pub nbr_records_received: u32,
            // nbr records received on this con since the last ack sent
            pub is_primary: bool,
            // Is this connection the default one?
            pub state: TcplsConnectionState,

        }

        impl TcpConnection {
            pub fn new() -> Self{
                Self{
                    connection_id: 0,
                    socket: None,
                    local_address_id: 0,
                    remote_address_id: 0,
                    local_address: None,
                    peer_address: None,
                    is_closed: false,
                    attached_streams: None,
                    // encryption_ctx: None,
                    // decryption_ctx: None,
                    nbr_bytes_received: 0,
                    nbr_records_received: 0,
                    is_primary: false,
                    state: TcplsConnectionState::CLOSED,
                }

            }
        }

        pub enum TcplsConnectionState {
            CLOSED,
            INITIALIZED,
            STARTED,         // Handshake started.
            FAILED,
            CONNECTING,
            CONNECTED,       // Handshake completed.
            JOINED,
        }


        pub struct Stream {

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





        pub struct TlsClientConfig{

        }


        pub fn tcpls_new_session(client_config: Arc<ClientConfig>, server_config: Arc<ServerConfig>, name: ServerName, is_server: bool) -> TcplsSession {
            let mut tcpls_session = TcplsSession::new();
            tcpls_session.is_server = is_server;
            tcpls_session
        }





        pub fn lookup_address(host: &str, port: u16) -> SocketAddr {

            let mut  addrs = (host, port).to_socket_addrs().unwrap(); // resolves hostname and return an itr
            addrs.next().expect("Cannot lookup address")
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

        pub fn init_tcp_connection(tcpls_session: &mut TcplsSession) {
            let tcp_conn = TcpConnection::new();


        }

        pub fn tcp_connect(dest_hostname: &str, local_address: SocketAddr,
                           port: u16, tcpls_session: &mut TcplsSession, tcp_conn: &mut TcpConnection) {
            let dest_address = lookup_address(dest_hostname, port);

            let socket = TcpStream::connect(dest_address).unwrap();
            tcp_conn.socket.insert(socket);
            if tcpls_session.tcpls_connections.is_none() {

            }


            tcp_conn.connection_id = tcpls_session.next_connection_id;
            tcpls_session.next_connection_id += 1;

            tcp_conn.local_address.insert(local_address);
            tcp_conn.local_address_id = tcpls_session.next_local_address_id;
            tcpls_session.next_local_address_id+= 1;

            tcp_conn.peer_address.insert(dest_address);
            tcp_conn.remote_address_id = tcpls_session.next_remote_address_id;
            tcpls_session.next_remote_address_id+= 1;



            tcpls_session




        }



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
