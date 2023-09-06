#![allow(missing_docs)]
#![allow(unused_qualifications)]

use std::arch::{asm, is_aarch64_feature_detected};
use std::collections::HashMap;
use std::fmt::{self, Debug};
use std::fs;
use std::io::{BufReader, Read};
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::{io, process, u32, vec};

use if_addrs::get_if_addrs;
use mio::net::{TcpListener, TcpStream};
use mio::Token;

use octets::BufferError;

/// This module contains optional APIs for implementing TCPLS.
use crate::cipher::{derive_connection_iv, Iv, MessageDecrypter, MessageEncrypter};
use crate::client::ClientConnectionData;
use crate::common_state::*;
use crate::conn::ConnectionCore;
use crate::enums::ProtocolVersion;
use crate::msgs::codec;
use crate::msgs::handshake::{ClientExtension, ServerExtension};
use crate::record_layer::RecordLayer;
use crate::server::ServerConnectionData;
use crate::tcpls::network_address::AddressMap;
use crate::vecbuf::ChunkVecBuffer;
use crate::verify::{
    AllowAnyAnonymousOrAuthenticatedClient, AllowAnyAuthenticatedClient, NoClientAuth,
};
use crate::Connection::Client;
use crate::{
    cipher, server, version, Certificate, ClientConfig, ConnectionCommon, ContentType, Error,
    InvalidMessage, KeyLogFile, PrivateKey, RootCertStore, ServerConfig, ServerName,
    SupportedCipherSuite, SupportedProtocolVersion, Ticketer, ALL_CIPHER_SUITES, ALL_VERSIONS,
    DEFAULT_CIPHER_SUITES, DEFAULT_VERSIONS,
};

pub(crate) mod bi_stream;
pub(crate) mod frame;
mod network_address;

pub struct TcplsSession {
    pub tls_config: Option<TlsConfig>,
    /*pub client_tls_conn: Option<ClientConnection>,
    pub server_tls_conn: Option<ServerConnection>,*/
    pub tls_conn: Option<Connection>,
    pub tcp_connections: HashMap<u32, TcpConnection>,
    pub pending_tcp_connections: HashMap<u32, TcpConnection>,
    pub next_connection_id: u32,
    pub address_map: AddressMap,
    pub is_server: bool,
    pub is_closed: bool,
    pub tls_hs_completed: bool,
}

impl TcplsSession {
    pub fn new() -> Self {
        Self {
            tls_config: None,
            /* client_tls_conn: None,
            server_tls_conn: None,*/
            tls_conn: None,
            tcp_connections: HashMap::new(),
            pending_tcp_connections: HashMap::new(),
            next_connection_id: 0,
            address_map: AddressMap::new(),
            is_server: false,
            is_closed: false,
            tls_hs_completed: false,
        }
    }

    pub fn tcpls_connect(
        &mut self,
        dest_address: SocketAddr,
        config: Arc<ClientConfig>,
        server_name: ServerName,
        is_server: bool,
    ) {
        assert_ne!(is_server, true);

        let tls_config = config.clone();
        let socket = TcpStream::connect(dest_address).expect("TCP connection establishment failed");

        let new_conn_id = self.create_tcpls_connection_object(socket, is_server);
        if new_conn_id == 0 {
            let client_conn = ClientConnection::new(tls_config, server_name)
                .expect("Establishment of TLS session failed");
            let _ = self.tls_conn.insert(Connection::from(client_conn));
            let _ = self.tls_config.insert(TlsConfig::Client(config.clone()));
        } else {
            self.tls_conn
                .as_mut()
                .unwrap()
                .stream_map
                .open_stream(new_conn_id);
            self.tls_conn
                .as_mut()
                .unwrap()
                .record_layer
                .start_new_seq_space(new_conn_id);
        }
    }

    pub fn create_tcpls_connection_object(&mut self, socket: TcpStream, is_server: bool) -> u32 {
        let mut tcp_conn = TcpConnection::new(socket);

        let new_conn_id = self.next_connection_id;
        tcp_conn.connection_id = new_conn_id;
        tcp_conn.local_address_id = self.address_map.next_local_address_id;
        tcp_conn.remote_address_id = self.address_map.next_peer_address_id;

        if tcp_conn.connection_id == 0 {
            tcp_conn.is_primary = true;
        }

        if !is_server {
            self.tcp_connections.insert(new_conn_id, tcp_conn);
        } else {
            self.pending_tcp_connections.insert(new_conn_id, tcp_conn);
        }

        self.next_connection_id += 1;
        self.address_map.next_local_address_id += 1;
        self.address_map.next_peer_address_id += 1;

        new_conn_id
    }
}

pub enum TlsConfig {
    Client(Arc<ClientConfig>),
    Server(Arc<ServerConfig>),
}

impl From<Arc<ClientConfig>> for TlsConfig {
    fn from(c: Arc<ClientConfig>) -> Self {
        Self::Client(c)
    }
}

impl From<Arc<ServerConfig>> for TlsConfig {
    fn from(s: Arc<ServerConfig>) -> Self {
        Self::Server(s)
    }
}

pub struct TcpConnection {
    pub connection_id: u32,
    pub socket: TcpStream,
    pub local_address_id: u8,
    pub remote_address_id: u8,
    pub nbr_bytes_received: u32,
    // nbr records received on this con since the last ack sent
    pub nbr_records_received: u32,
    // nbr records received on this con since the last ack sent
    pub is_primary: bool,
    // Is this connection the default one?
    pub state: TcplsConnectionState,
}

impl TcpConnection {
    pub fn new(socket: TcpStream) -> Self {
        Self {
            connection_id: 0,
            socket: socket,
            local_address_id: 0,
            remote_address_id: 0,
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
    STARTED, // Handshake started.
    FAILED,
    CONNECTING,
    CONNECTED, // Handshake completed.
    JOINED,
}

pub fn lookup_address(host: &str, port: u16) -> SocketAddr {
    let mut addrs = (host, port).to_socket_addrs().unwrap(); // resolves hostname and return an itr
    addrs.next().expect("Cannot lookup address")
}

pub fn build_cert_store(
    cert_file_path: Option<&String>,
    cert_store: Option<RootCertStore>,
) -> RootCertStore {
    let mut root_store = RootCertStore::empty();

    if cert_file_path.is_some() {
        let ca_path = cert_file_path.unwrap();

        let cert_file = fs::File::open(ca_path).expect("Cannot open CA file");
        let mut reader = BufReader::new(cert_file);
        root_store.add_parsable_certificates(&rustls_pemfile::certs(&mut reader).unwrap());
    } else if cert_store.is_none() {
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

pub fn client_new_tls_connection(config: Arc<ClientConfig>, name: ServerName) -> ClientConnection {
    ClientConnection::new(config, name).expect("Establishing a TLS session has failed")
}

/// Build a `rustls::ClientConfig`
pub fn build_tls_client_config(
    cert_path: Option<&String>,
    cert_store: Option<RootCertStore>,
    cipher_suites: Vec<String>,
    protocol_ver: Vec<String>,
    auth_key: Option<String>,
    auth_certs: Option<String>,
    no_tickets: bool,
    no_sni: bool,
    proto: Vec<String>,
    max_frag_size: Option<usize>,
) -> Arc<ClientConfig> {
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

    config.alpn_protocols = proto
        .iter()
        .map(|proto| proto.as_bytes().to_vec())
        .collect();

    if max_frag_size.is_some() {
        config.max_fragment_size = max_frag_size;
    }

    Arc::new(config)
}

pub fn build_tls_server_config(
    client_verify: Option<String>,
    require_auth: bool,
    suite: Vec<String>,
    protover: Vec<String>,
    certs: Option<String>,
    key: Option<String>,
    ocsp: Option<String>,
    resumption: bool,
    tickets: bool,
    proto: Vec<String>,
) -> Arc<ServerConfig> {
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

    let certs = load_certs(certs.as_ref().expect("--certs option missing"));
    let privkey = load_private_key(key.as_ref().expect("--key option missing"));
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

pub fn server_create_listener(local_address: &str, port: u16) -> TcpListener {
    let mut addr: SocketAddr = local_address.parse().unwrap();

    addr.set_port(port);

    TcpListener::bind(addr).expect("cannot listen on port")
}

pub fn server_accept_connection(
    listener: TcpListener,
    tcpls_session: &mut TcplsSession,
    config: Arc<ServerConfig>,
) {
    let (socket, remote_address) = listener
        .accept()
        .expect("encountered error while accepting connection");

    let conn_id = tcpls_session.create_tcpls_connection_object(socket, true);
    if conn_id == 0 {
        tcpls_session.is_server = true;

        let server_conn =
            ServerConnection::new(config.clone()).expect("Establishing a TLS session has failed");
        let _ = tcpls_session.tls_conn.insert(Connection::from(server_conn));
        let _ = tcpls_session
            .tls_config
            .insert(TlsConfig::from(config));
    } else {
        tcpls_session
            .tls_conn
            .as_mut()
            .unwrap()
            .stream_map
            .open_stream(conn_id);
        tcpls_session
            .tls_conn
            .as_mut()
            .unwrap()
            .record_layer
            .start_new_seq_space(conn_id);
    }
}

pub fn server_new_tls_connection(config: Arc<ServerConfig>) -> ServerConnection {
    ServerConnection::new(config).expect("Establishing a TLS session has failed")
}

/// A TLS client or server connection.
#[derive(Debug)]
pub enum Connection {
    /// A client connection
    Client(ClientConnection),
    /// A server connection
    Server(ServerConnection),
}

impl Deref for Connection {
    type Target = CommonState;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Client(conn) => &conn.core.common_state,
            Self::Server(conn) => &conn.core.common_state,
        }
    }
}

impl DerefMut for Connection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Client(conn) => &mut conn.core.common_state,
            Self::Server(conn) => &mut conn.core.common_state,
        }
    }
}

impl From<ClientConnection> for Connection {
    fn from(c: ClientConnection) -> Self {
        Self::Client(c)
    }
}

impl From<ServerConnection> for Connection {
    fn from(c: ServerConnection) -> Self {
        Self::Server(c)
    }
}

/// A TCPLS client connection.
pub struct ClientConnection {
    inner: ConnectionCommon<ClientConnectionData>,
}

impl ClientConnection {
    /// Make a new TLS ClientConnection.
    pub fn new(config: Arc<ClientConfig>, name: ServerName) -> Result<Self, Error> {
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
        f.debug_struct("tcpls::ClientConnection").finish()
    }
}



/// A TCPLS server connection.
pub struct ServerConnection {
    inner: ConnectionCommon<ServerConnectionData>,
}

impl ServerConnection {
    /// Make a new TLS ServerConnection.
    pub fn new(config: Arc<ServerConfig>) -> Result<Self, Error> {
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
        f.debug_struct("tcpls::ServerConnection").finish()
    }
}


// #[test]
/*fn test_prep_crypto_context(){

 let mut iv= Iv::copy(&[0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]) ;
 let mut iv_vec = vec![iv];

 let iv_2= Iv::copy(&[0x0C, 0x0B, 0x0A, 0x08, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]) ;
 let connection_id:u32 = 0x01;
 derive_connection_iv(&mut iv_vec, connection_id);
assert_eq!(iv_2.value(), iv_vec.get(1).unwrap().value())

}*/
