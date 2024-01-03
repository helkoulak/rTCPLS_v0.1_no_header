#![allow(missing_docs)]
#![allow(unused_qualifications)]

/// This module contains optional APIs for implementing TCPLS.
use std::{io, u32, vec};
use std::fs;
use std::io::{BufReader, Read, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use mio::net::{TcpListener, TcpStream};

use crate::{ALL_CIPHER_SUITES, ALL_VERSIONS, Certificate, ClientConfig, ClientConnection,
            Connection, DEFAULT_CIPHER_SUITES, DEFAULT_VERSIONS, Error, IoState, KeyLogFile,
            PrivateKey, RootCertStore, server, ServerConfig, ServerConnection, ServerName,
            SupportedCipherSuite, SupportedProtocolVersion, Ticketer, version};
use crate::recvbuf::RecvBufMap;
use crate::tcpls::network_address::AddressMap;
use crate::tcpls::stream::SimpleIdHashMap;
use crate::verify::{
    AllowAnyAnonymousOrAuthenticatedClient, AllowAnyAuthenticatedClient, NoClientAuth,
};

pub mod frame;
pub mod network_address;
pub mod ranges;
pub mod stream;

pub const DEFAULT_CONNECTION_ID:u32 = 0;

pub struct TcplsSession {
    pub tls_config: Option<TlsConfig>,
    pub tls_conn: Option<Connection>,
    pub tcp_connections: SimpleIdHashMap<TcpConnection>,
    pub next_conn_id: u32,
    pub address_map: AddressMap,
    pub is_server: bool,
    pub is_closed: bool,
    pub tls_hs_completed: bool,
}

impl TcplsSession {
    pub fn new(is_server: bool) -> Self {
        Self {
            tls_config: None,
            tls_conn: None,
            tcp_connections: SimpleIdHashMap::default(),
            next_conn_id: DEFAULT_CONNECTION_ID,
            address_map: AddressMap::new(),
            is_server,
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

        let new_id = self.create_tcpls_connection_object(socket, is_server);

        if new_id == DEFAULT_CONNECTION_ID {
            let client_conn = ClientConnection::new(tls_config, server_name)
                .expect("Establishment of TLS session failed");
            let _ = self.tls_conn.insert(Connection::from(client_conn));
            let _ = self.tls_config.insert(TlsConfig::Client(config.clone()));
        }

    }

    pub fn create_tcpls_connection_object(&mut self, socket: TcpStream, is_server: bool) -> u32 {
        let mut tcp_conn = TcpConnection::new(socket, self.next_conn_id);

        let new_id = self.next_conn_id;
        tcp_conn.local_address_id = self.address_map.next_local_address_id;
        tcp_conn.remote_address_id = self.address_map.next_peer_address_id;

        if tcp_conn.connection_id == DEFAULT_CONNECTION_ID {
            tcp_conn.is_primary = true;
        }

        self.tcp_connections.insert(new_id as u64, tcp_conn);

        self.next_conn_id += 1;
        self.address_map.next_local_address_id += 1;
        self.address_map.next_peer_address_id += 1;

        new_id
    }

    pub fn server_accept_connection(
        &mut self,
        listener: &mut TcpListener,
        config: Arc<ServerConfig>,
    ) -> Result<u32, io::Error> {
        let (socket, remote_address) = listener
            .accept()
            .expect("encountered error while accepting connection");

        let conn_id = self.create_tcpls_connection_object(socket, true);

        if conn_id == 0 {
            self.is_server = true;

            let server_conn = ServerConnection::new(config.clone())
                .expect("Establishing a TLS session has failed");
            let _ = self.tls_conn.insert(Connection::from(server_conn));
            let _ = self.tls_config.insert(TlsConfig::from(config));
        }
        Ok(conn_id)
    }

    pub fn stream_send(&mut self, str_id: u16, input: &[u8], fin: bool) -> Result<usize, Error> {
       let mut tls_connection = self.tls_conn.as_mut().unwrap();
        let buffered = tls_connection
            .send_some_plaintext(input, str_id,fin);
        Ok(buffered)
    }
    

    pub fn send_on_connection(&mut self, conn_id: u32) -> Result<usize, Error> {
        let tls_conn = self.tls_conn.as_mut().unwrap();

        let (has_pending, pending_at) = match tls_conn.record_layer.streams.has_pending {
            Some(id) => (true, id),
            None => (false, 0),
        };

        // Iterator over flushable streams. If applicable, Start with the stream that has a remainder of a partially sent record
        let flushable_streams = tls_conn.record_layer.streams.flushable().skip_while(|&id| id != pending_at as u64 && has_pending);

        let mut done = 0;
        let socket = &mut self
            .tcp_connections
            .get_mut(&(conn_id as u64))
            .unwrap()
            .socket;

        for id in flushable_streams {

            let stream = match tls_conn.record_layer.streams.get_mut(id as u16) {
                Some(stream) => {
                    stream
                },
                None => return Err(Error::BufNotFound),
            };

            let mut len = stream.send.len();
            let mut sent = 0;
            while len > 0 {
                let chunk = stream.send.pop().unwrap();
                let chunk_len = chunk.len();

                sent = socket
                    .write(chunk.as_slice())
                    .unwrap();
                len -= sent;
                done += sent;
                stream.send.consume_chunk(sent, chunk);
                // In case the chunk was partially sent, by the next call
                // to send on the same connection this stream should be chosen as first
                if sent != chunk_len {
                    tls_conn.record_layer.streams.has_pending = Some(id as u16);
                    return Ok(done);
                }

            }
            // The remainder of the partially sent record was sent successfully
            if has_pending && id == pending_at as u64 {
                tls_conn.record_layer.streams.has_pending = None;
            }
            if len == 0 {
                tls_conn.record_layer.streams.remove_flushable(id);
                tls_conn.record_layer.streams.insert_writable(id);
            }
        }

        Ok(done)
    }

    /// Receive data on specified TCP socket
    pub fn recv_on_connection(&mut self, conn_id: u32) -> Result<usize, io::Error> {
        let mut socket = match self.tcp_connections.get_mut(&(conn_id as u64)) {
            Some(conn) => &mut conn.socket,
            None => panic!("Socket of specified TCP connection does not exist")
        };
       self.tls_conn.as_mut().unwrap().read_tls(socket)
    }


    pub fn stream_recv(
        &mut self,
        app_buffers: &mut RecvBufMap,
    ) -> Result<IoState, Error> {

        let tls_conn = self.tls_conn.as_mut().unwrap();

            let io_state = match tls_conn.process_new_packets(app_buffers) {
                Ok(io_state) => io_state,
                Err(err) => return Err(err),
            };


        Ok(io_state)
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
    pub fn new(socket: TcpStream, id: u32) -> Self {
        Self {
            connection_id: id,
            socket,
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

    config.enable_tcpls = true;

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

pub fn server_new_tls_connection(config: Arc<ServerConfig>) -> ServerConnection {
    ServerConnection::new(config).expect("Establishing a TLS session has failed")
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
