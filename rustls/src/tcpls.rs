#![allow(missing_docs)]

/// This module contains optional APIs for implementing TCPLS.
use crate::cipher::{Iv, IvLen};
use crate::client::ClientConnectionData;
use crate::common_state::{CommonState, Protocol, Side};
use crate::conn::{ConnectionCore, SideData};
use crate::enums::{AlertDescription, ProtocolVersion};

use crate::msgs::handshake::{ClientExtension, ServerExtension};
use crate::server::ServerConnectionData;
use crate::suites::BulkAlgorithm;
use crate::tls13::key_schedule::hkdf_expand;
use crate::tls13::{Tls13CipherSuite, TLS13_AES_128_GCM_SHA256_INTERNAL};

use ring::{aead, hkdf};

use mio::net::TcpStream;
use mio::Token;

use std::collections::VecDeque;
use std::fmt::{self, Debug};
use std::io;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::fs;
use std::io::BufReader;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::cell::Ref;
use std::ptr::addr_of_mut;

use local_ip_address::local_ip;



use crate::internal::record_layer::RecordLayer;
use crate::{ClientConfig, OwnedTrustAnchor, RootCertStore,
            ServerConfig, ServerName, Error, ConnectionCommon, SupportedCipherSuite,
            ALL_CIPHER_SUITES, SupportedProtocolVersion, version, Certificate, PrivateKey,
            DEFAULT_CIPHER_SUITES, DEFAULT_VERSIONS, tcpls, KeyLogFile};


pub const TCPLS_STREAM_FRAME_MAX_PAYLOAD_LENGTH: usize = crate::msgs::fragmenter::MAX_FRAGMENT_LEN;

    pub enum TcplsFrameTypes {
        Padding = 0x00,
        Ping = 0x01,
        Stream = 0x02,
        StreamWithFin = 0x03,
        ACK = 0x04,
        NewToken = 0x05,
        ConnectionReset = 0x06,
        NewAddress = 0x07,
        RemoveAddress = 0x08,
        StreamChange = 0x09,
    }


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
        frame_type: TcplsFrameTypes,
    }

    pub struct PingFrame {
        frame_type: TcplsFrameTypes,
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
        frame_type: TcplsFrameTypes,
    }

    pub struct NewTokenFrame<'a> {
        token: &'a mut [u8; 32],
        sequence: u8,
        frame_type: TcplsFrameTypes,
    }

    pub struct ConnectionResetFrame {
        connection_id: u32,
        frame_type: TcplsFrameTypes,
    }

    pub struct NewAddressFrame {
        port: u16,
        address: IpAddr,
        address_version: u8,
        address_id: u8,
        frame_type: TcplsFrameTypes,
    }

    pub struct RemoveAddressFrame {
        address_id: u8,
        frame_type: TcplsFrameTypes,
    }

    pub struct StreamChangeFrame {
        next_record_stream_id: u32,
        next_offset: u64,
        frame_type: TcplsFrameTypes,
    }


    pub struct TcplsSession<'a> {
        // pub tls_ctx: Option<>
        pub tcp_connections: Vec<&'a mut TcpConnection<'a>>,
        pub open_connections_ids: Vec<u32>,
        pub closed_connections_ids: Vec<u32>,
        pub next_connection_id: u32,
        pub local_addresses_ip4: Vec<SocketAddr>,
        pub local_addresses_ip6: Vec<SocketAddr>,
        pub next_local_address_id: u8,
        pub addresses_advertised: Vec<SocketAddr>,
        pub remote_addresses_ip4: Vec<SocketAddr>,
        pub remote_addresses_ip6: Vec<SocketAddr>,
        pub next_remote_address_id: u8,
        pub next_stream_id: u32,
        pub is_server: bool,
        pub is_closed: bool,
        pub tls_hs_completed: bool,
    }

    impl <'a> TcplsSession<'a> {
        pub fn new() -> Self{
            Self{
                // tls_ctx: None,
                tcp_connections: Vec::new(),
                open_connections_ids: Vec::new(),
                closed_connections_ids: Vec::new(),
                next_connection_id: 0,
                local_addresses_ip4: Vec::new(),
                local_addresses_ip6: Vec::new(),
                next_local_address_id: 0,
                addresses_advertised: Vec::new(),
                remote_addresses_ip4: Vec::new(),
                remote_addresses_ip6: Vec::new(),
                next_remote_address_id: 0,
                next_stream_id: 0,
                is_server: false,
                is_closed: false,
                tls_hs_completed: false,
            }
        }



    }


    pub struct TcpConnection <'a>{
        pub connection_id: u32,
        pub socket: Option<TcpStream>,
        pub token: Token,
        pub server_name: String,
        pub local_address_id: u8,
        pub local_address: Option<SocketAddr>,
        pub remote_address_id: u8,
        pub remote_address: Option<SocketAddr>,
        pub attached_streams: Vec<Stream>,
        // pub encryption_ctx: Option<Tls13MessageEncrypter>,
        // pub decryption_ctx: Option<crate::tls13::Tls13MessageDecrypter>,
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
                token: Token(0),
                server_name: String::new(),
                local_address_id: 0,
                local_address: None,
                remote_address_id: 0,
                remote_address: None,
                attached_streams: Vec::new(),
                // encryption_ctx: None,
                // decryption_ctx: None,
                nbr_bytes_received: 0,
                nbr_records_received: 0,
                is_primary: false,
                state: TcplsConnectionState::CLOSED,
            }

        }

        // < pub fn create_tcp_connection() -> TcpConnection {
        //      let tcp_conn = TcpConnection::new();
        //      tcp_conn
        //  }
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

        } else if cert_store.is_none(){
            panic!("either a file path for a cert store or an RootCertStore should be provided")
        } else {
            root_store = cert_store.unwrap();
        }

        root_store
    }


    /// Find a ciphersuite with the given name
    pub fn find_suite(name: &str) -> Option<SupportedCipherSuite> {
        for suite in ALL_CIPHER_SUITES {
            let sname = format!("{:?}", suite.suite()).to_lowercase();

            if sname == name.to_string().to_lowercase() {
                return Some(*suite);
            }
        }

        None
    }

    /// Make a vector of ciphersuites named in `suites`
    pub fn lookup_suites(suites: &[String]) -> Vec<SupportedCipherSuite> {
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
    pub fn lookup_versions(versions: &[String]) -> Vec<&'static SupportedProtocolVersion> {
        let mut out = Vec::new();

        for vname in versions {
            let version = match vname.as_ref() {
                //"1.2" => &rustls::version::TLS12,
                "1.3" => &version::TLS13,
                _ => panic!(
                    "cannot look up version '{}', TCPLS supports only TLS '1.3'",
                    vname
                ),
            };
            out.push(version);
        }

        out
    }

    pub fn load_certs(filename: &str) -> Vec<Certificate> {
        let certfile = fs::File::open(filename).expect("cannot open certificate file");
        let mut reader = BufReader::new(certfile);
        rustls_pemfile::certs(&mut reader)
            .unwrap()
            .iter()
            .map(|v| Certificate(v.clone()))
            .collect()
    }

    pub fn load_private_key(filename: &str) -> PrivateKey {
        let keyfile = fs::File::open(filename).expect("cannot open private key file");
        let mut reader = BufReader::new(keyfile);

        loop {
            match rustls_pemfile::read_one(&mut reader).expect("cannot parse private key .pem file") {
                Some(rustls_pemfile::Item::RSAKey(key)) => return PrivateKey(key),
                Some(rustls_pemfile::Item::PKCS8Key(key)) => return PrivateKey(key),
                Some(rustls_pemfile::Item::ECKey(key)) => return PrivateKey(key),
                None => break,
                _ => {}
            }
        }

        panic!(
            "no keys found in {:?} (encrypted keys not supported)",
            filename
        );
    }





    pub fn tcp_connect<'a>(dest_address: SocketAddr, port: u16, tcpls_session: &'a mut TcplsSession<'a>, tcp_conn: &'a mut TcpConnection) {
               //TODO: find a way to calculate local address
        // let my_local_ip = local_ip().unwrap();

        let socket = TcpStream::connect(dest_address).expect("TCP connection establishment failed").unwrap();

        let _ = tcp_conn.socket.insert(socket);
        tcp_conn.connection_id = tcpls_session.next_connection_id;
        tcp_conn.local_address_id = tcpls_session.next_local_address_id;
        tcp_conn.remote_address_id = tcpls_session.next_remote_address_id;

        if tcp_conn.connection_id == 0 {
            tcp_conn.is_primary = true;
        }

        // tcp_conn.local_address
        let _ = tcp_conn.remote_address.insert(dest_address);


        tcpls_session.open_connections_ids.push(tcp_conn.connection_id);
        tcpls_session.tcp_connections.push(tcp_conn);
        tcpls_session.next_connection_id += 1;
        tcpls_session.next_local_address_id += 1;
        tcpls_session.next_remote_address_id += 1;

        match dest_address.is_ipv4(){
            true =>  {tcpls_session.remote_addresses_ip4.push(dest_address);
                // tcpls_session.local_addresses_ip4.push();
            },
            false => {
                tcpls_session.remote_addresses_ip6.push(dest_address);
                // tcpls_session.local_addresses_ip6.push();
            },
        }

    }



    pub fn client_new_tls_session(config: Arc<ClientConfig>, name: ServerName) -> ClientConnection{

        ClientConnection::new(config, name).expect("Establishing a TLS session has failed")
    }


    /// Build a `rustls::ClientConfig`
    pub fn make_tls_client_config(cert_path: Option<&String>, cert_store: Option<RootCertStore>, enable_tcpls: bool, cipher_suites: Vec<String>,
                                  protocol_ver: Vec<String>, auth_key: Option<String>, auth_certs: Option<String>,
                                  no_tickets: bool, no_sni: bool, proto: Vec<String>, insecure: bool, max_frag_size: Option<usize>) -> Arc<ClientConfig> {

        let mut root_store = build_cert_store(cert_path, cert_store);

        let suites = if !cipher_suites.is_empty() {
            lookup_suites(&cipher_suites)
        } else {
            DEFAULT_CIPHER_SUITES.to_vec()
        };

        let versions = if !protocol_ver.is_empty() {
            lookup_versions(&protocol_ver)
        } else {
            DEFAULT_VERSIONS.to_vec()
        };

        let config = ClientConfig::builder()
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

        config.key_log = Arc::new(KeyLogFile::new());

        if no_tickets {
            config.resumption = config
                .resumption
                .tls12_resumption(crate::client::Tls12Resumption::SessionIdOnly);
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




 pub fn server_new_tls_session(config: Arc<ServerConfig>) -> ServerConnection {

        ServerConnection::new(config).expect("Establishing a TLS session has failed")
    }





/// A TCPLS client or server connection.
#[derive(Debug)]
pub enum Connection {
    /// A client connection
    Client(ClientConnection),
    /// A server connection
    Server(ServerConnection),
}


/// A TCPLS client connection.
pub struct ClientConnection {
    inner: ConnectionCommon<ClientConnectionData>,
}

impl ClientConnection {
    /// Make a new TCPLS ClientConnection.
    pub fn new(
        config: Arc<ClientConfig>,
        name: ServerName,
    ) -> Result<Self, Error> {
        if !config.supports_version(ProtocolVersion::TLSv1_3) {
            return Err(Error::General(
                "TLS 1.3 support is required for TCPLS".into(),
            ));
        }

        let ext = ClientExtension::TCPLS;

        Ok(Self {
            inner: ConnectionCore::for_client(config, name, vec![ext], Protocol::Tcpls)?.into(),
        })
    }

}

impl Deref for ClientConnection {
    type Target = ConnectionCommon<ClientConnectionData>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for ClientConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Debug for ClientConnection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("tcpls::ClientConnection")
            .finish()
    }
}
impl From<ClientConnection> for Connection {
    fn from(c: ClientConnection) -> Self {
        Self::Client(c)
    }
}

/// A TCPLS server connection.
pub struct ServerConnection {
    inner: ConnectionCommon<ServerConnectionData>,
}

impl ServerConnection {
    /// Make a new TCPLS ServerConnection.
    pub fn new(
        config: Arc<ServerConfig>,
    ) -> Result<Self, Error> {
        if !config.supports_version(ProtocolVersion::TLSv1_3) {
            return Err(Error::General(
                "TLS 1.3 support is required for TCPLS".into(),
            ));
        }


        let ext = ServerExtension::TCPLS;

        let mut core = ConnectionCore::for_server(config, vec![ext])?;
        core.common_state.protocol = Protocol::Tcpls;
        Ok(Self { inner: core.into() })
    }
}
impl Deref for ServerConnection {
    type Target = ConnectionCommon<ServerConnectionData>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for ServerConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Debug for ServerConnection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("tcpls::ServerConnection")
            .finish()
    }
}
impl From<ServerConnection> for Connection {
    fn from(c: ServerConnection) -> Self {
        Self::Server(c)
    }
}
