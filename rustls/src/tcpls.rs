#![allow(missing_docs)]

/// This module contains optional APIs for implementing TCPLS.
use crate::cipher::Iv;
use crate::client::ClientConnectionData;
use crate::common_state::{CommonState, Protocol, Side};
use crate::conn::ConnectionCore;
use crate::enums::ProtocolVersion;

use crate::msgs::handshake::{ClientExtension, ServerExtension};
use crate::server::ServerConnectionData;

use ring::aead;
use mio::net::TcpStream;

use std::fmt::{self, Debug};
use std::u32;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::fs;
use std::io::{BufReader, Read};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use std::cell::RefCell;

use crate::{ClientConfig, RootCertStore, ServerConfig, ServerName, Error, ConnectionCommon,
            SupportedCipherSuite, ALL_CIPHER_SUITES, SupportedProtocolVersion, version, Certificate,
            PrivateKey, DEFAULT_CIPHER_SUITES, DEFAULT_VERSIONS, tcpls, KeyLogFile, cipher, ALL_VERSIONS, Ticketer, server};

use crate::verify::{AllowAnyAnonymousOrAuthenticatedClient, AllowAnyAuthenticatedClient, NoClientAuth};


pub const TCPLS_STREAM_FRAME_MAX_PAYLOAD_LENGTH: usize = crate::msgs::fragmenter::MAX_FRAGMENT_LEN - STREAM_FRAME_OVERHEAD;

pub const STREAM_FRAME_OVERHEAD: usize = 15; // Type = 1 Byte + Stream Id = 4 Bytes + Offset = 8 Bytes + Length = 2 Bytes


#[derive(Clone, PartialEq, Eq)]
pub enum TcplsFrame {
    Padding,

    Ping,

    Stream {
        stream_data: Vec<u8>,
        length: u16,
        offset: u64,
        stream_id: u32,

    },

    ACK {
        highest_record_sn_received: u64,
        connection_id: u32,

    },

    NewToken {
        token: [u8; 32],
        sequence: u8,

    },

    ConnectionReset {
        connection_id: u32,

    },

    NewAddress {
        port: u16,
        address: IpAddr,
        address_version: u8,
        address_id: u8,

    },

    RemoveAddress {
        address_id: u8,

    },

    StreamChange {
        next_record_stream_id: u32,
        next_offset: u64,

    }
}

    pub struct TcplsSession {
        pub tls_ctx: Option<TlsContext>,
        pub tcp_connections: Vec<TcpConnection>,
        pub pending_tcp_connections: Vec<TcpConnection>,
        pub open_connections_ids: Vec<u32>,
        pub closed_connections_ids: Vec<u32>,
        pub next_connection_id: u32,
        pub next_local_address_id: u8,
        pub next_remote_address_id: u8,
        pub addresses_advertised: Vec<SocketAddr>,
        pub next_stream_id: u32,
        pub is_server: bool,
        pub is_closed: bool,
        pub tls_hs_completed: bool,
    }

    impl TcplsSession {
        pub fn new() -> Self{
            Self{
                tls_ctx: None,
                tcp_connections: Vec::new(),
                pending_tcp_connections: Vec::new(),
                open_connections_ids: Vec::new(),
                closed_connections_ids: Vec::new(),
                next_connection_id: 0,
                next_local_address_id: 0,
                addresses_advertised: Vec::new(),
                next_remote_address_id: 0,
                next_stream_id: 0,
                is_server: false,
                is_closed: false,
                tls_hs_completed: false,
            }
        }



    }

    pub enum  TlsContext{
        Client(Arc<ClientConfig>),
        Server(Arc<ServerConfig>),
    }





    pub struct TcpConnection {
        pub connection_id: u32,
        pub socket: Vec<TcpStream>,
        pub local_address_id: u8,
        pub remote_address_id: u8,
        pub attached_stream: Option<Stream>,
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
                socket: Vec::with_capacity(1),
                local_address_id: 0,
                remote_address_id: 0,
                attached_stream: None,
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

    fn load_ocsp(filename: &Option<String>) -> Vec<u8> {
        let mut ret = Vec::new();
        if let Some(name) = filename {
            fs::File::open(name)
                .expect("cannot open ocsp file")
                .read_to_end(&mut ret)
                .unwrap();
        }
        ret
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





    pub fn tcp_connect(dest_address: SocketAddr, tcpls_session: &mut TcplsSession) {

        let mut tcp_conn = TcpConnection::new();

        let socket = TcpStream::connect(dest_address).expect("TCP connection establishment failed");


        tcp_conn.socket.push(socket);

        tcp_conn.connection_id = tcpls_session.next_connection_id;
        tcp_conn.local_address_id = tcpls_session.next_local_address_id;
        tcp_conn.remote_address_id = tcpls_session.next_remote_address_id;

        if tcp_conn.connection_id == 0 {
            tcp_conn.is_primary = true;
        }

        tcpls_session.open_connections_ids.push(tcp_conn.connection_id);
        tcpls_session.tcp_connections.push(tcp_conn);
        tcpls_session.next_connection_id += 1;
        tcpls_session.next_local_address_id += 1;
        tcpls_session.next_remote_address_id += 1;

    }



    pub fn client_new_tls_session(config: Arc<ClientConfig>, name: ServerName) -> ClientConnection{

        ClientConnection::new(config, name).expect("Establishing a TLS session has failed")
    }


    /// Build a `rustls::ClientConfig`
    pub fn build_tls_client_config(cert_path: Option<&String>, cert_store: Option<RootCertStore>, cipher_suites: Vec<String>,
                                   protocol_ver: Vec<String>, auth_key: Option<String>, auth_certs: Option<String>,
                                   no_tickets: bool, no_sni: bool, proto: Vec<String>, max_frag_size: Option<usize>) -> Arc<ClientConfig> {

        let root_store = build_cert_store(cert_path, cert_store);

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


        Arc::new(config)
    }

    pub fn build_tls_server_config(client_verify: Option<String>, require_auth: bool, suite: Vec<String>,
                               protover: Vec<String>,  certs: Option<String>, key: Option<String>,
                               ocsp: Option<String>, resumption: bool, tickets: bool, proto: Vec<String>) -> Arc<ServerConfig> {
        let client_auth = if client_verify.is_some() {
            let roots = load_certs(client_verify.as_ref().unwrap());
            let mut client_auth_roots = RootCertStore::empty();
            for root in roots {
                client_auth_roots.add(&root).unwrap();
            }
            if require_auth {
                AllowAnyAuthenticatedClient::new(client_auth_roots).boxed()
            } else {
                AllowAnyAnonymousOrAuthenticatedClient::new(client_auth_roots).boxed()
            }
        } else {
            NoClientAuth::boxed()
        };

        let suites = if !suite.is_empty() {
            lookup_suites(&suite)
        } else {
            ALL_CIPHER_SUITES.to_vec()
        };

        let versions = if !protover.is_empty() {
            lookup_versions(&protover)
        } else {
            ALL_VERSIONS.to_vec()
        };

        let certs = load_certs(
            certs
                .as_ref()
                .expect("--certs option missing"),
        );
        let privkey = load_private_key(
            key
                .as_ref()
                .expect("--key option missing"),
        );
        let ocsp = load_ocsp(&ocsp);

        let mut config = ServerConfig::builder()
            .with_cipher_suites(&suites)
            .with_safe_default_kx_groups()
            .with_protocol_versions(&versions)
            .expect("inconsistent cipher-suites/versions specified")
            .with_client_cert_verifier(client_auth)
            .with_single_cert_with_ocsp_and_sct(certs, privkey, ocsp, vec![])
            .expect("bad certificates/private key");

        config.key_log = Arc::new(KeyLogFile::new());

        if resumption {
            config.session_storage = server::ServerSessionMemoryCache::new(256);
        }

        if tickets {
            config.ticketer = Ticketer::new().unwrap();
        }

        config.alpn_protocols = proto
            .iter()
            .map(|proto| proto.as_bytes().to_vec())
            .collect::<Vec<_>>();


        Arc::new(config)
    }


pub(crate) fn prepare_connection_crypto_context(iv: &mut Iv, connection_id: u32) {
    let mut conn_id = [0u8; aead::NONCE_LEN];
    put_u32(connection_id, &mut conn_id[..4]);

    conn_id
        .iter_mut()
        .zip(iv.0.iter_mut())
        .for_each(|(conn_id, iv)| {
            *iv ^= *conn_id;
        });

}

pub fn put_u32(v: u32, bytes: &mut [u8]) {
    let bytes: &mut [u8; 4] = (&mut bytes[..4]).try_into().unwrap();
    *bytes = u32::to_be_bytes(v);
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

#[test]
fn test_prep_crypto_context(){
    let mut iv= Iv::copy(&[0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]) ;
    let iv_result= Iv::copy(&[0x0C, 0x0B, 0x0A, 0x05, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]) ;
    let connection_id:u32 = 0x0C;
    prepare_connection_crypto_context(&mut iv, connection_id);
   assert_eq!(iv.value(), iv_result.value())

   }