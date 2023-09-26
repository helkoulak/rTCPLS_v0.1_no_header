#![allow(missing_docs)]
#![allow(unused_qualifications)]

use std::arch::{asm, is_aarch64_feature_detected};
use std::cmp::min;
use std::collections::HashMap;
use std::fmt::{self, Debug};
use std::fs;
use std::io::{BufReader, Read, Seek, Write};
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::{io, process, u32, vec};

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
use crate::tcpls::stream::{RecvBufMap, DEFAULT_BUFFER_LIMIT, Stream, StreamMap};
use crate::tcpls::frame::{Frame, MAX_TCPLS_FRAGMENT_LEN, StreamFrameHeader};
use crate::tcpls::network_address::AddressMap;
use crate::vecbuf::ChunkVecBuffer;
use crate::verify::{
    AllowAnyAnonymousOrAuthenticatedClient, AllowAnyAuthenticatedClient, NoClientAuth,
};
use crate::Connection::Client;
use crate::{
    cipher, server, version, Certificate, ClientConfig, ClientConnection, Connection,
    ConnectionCommon, ContentType, InvalidMessage, KeyLogFile, PrivateKey, RootCertStore,
    ServerConfig, ServerConnection, ServerName, SupportedCipherSuite, SupportedProtocolVersion,
    Ticketer, ALL_CIPHER_SUITES, ALL_VERSIONS, DEFAULT_CIPHER_SUITES, DEFAULT_VERSIONS, Error };
use crate::msgs::base::Payload;
use crate::msgs::message::PlainMessage;

pub mod stream;
pub mod frame;
pub mod network_address;
pub mod ranges;

pub struct TcplsSession {
    pub tls_config: Option<TlsConfig>,
    pub tls_conn: Option<Connection>,
    pub tcp_connections: HashMap<u32, TcpConnection>,
    pub streams: StreamMap,
    pub next_conn_id: u32,
    pub address_map: AddressMap,
    pub is_server: bool,
    pub is_closed: bool,
    pub tls_hs_completed: bool,
    pub next_stream_id: u64,
}

impl TcplsSession {
    pub fn new(is_server: bool) -> Self {
        Self {
            tls_config: None,
            tls_conn: None,
            tcp_connections: HashMap::new(),
            streams: StreamMap::new(),
            next_conn_id: 0,
            address_map: AddressMap::new(),
            is_server,
            is_closed: false,
            tls_hs_completed: false,
            next_stream_id: 0,
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

        if new_id == 0 {
            let client_conn = ClientConnection::new(tls_config, server_name)
                .expect("Establishment of TLS session failed");
            let _ = self.tls_conn.insert(Connection::from(client_conn));
            let _ = self.tls_config.insert(TlsConfig::Client(config.clone()));
        } else {
            self.tls_conn
                .as_mut()
                .unwrap()
                .stream_map
                .attach_stream(new_id);
            self.tls_conn
                .as_mut()
                .unwrap()
                .record_layer
                .start_new_seq_space(new_id);
        }
    }

    pub fn create_tcpls_connection_object(&mut self, socket: TcpStream, is_server: bool) -> u32 {
        let mut tcp_conn = TcpConnection::new(socket, self.next_conn_id);

        let new_id = self.next_conn_id;
        tcp_conn.local_address_id = self.address_map.next_local_address_id;
        tcp_conn.remote_address_id = self.address_map.next_peer_address_id;

        if tcp_conn.connection_id == 0 {
            tcp_conn.is_primary = true;
        }

        self.tcp_connections.insert(new_id, tcp_conn);

        self.next_conn_id += 1;
        self.address_map.next_local_address_id += 1;
        self.address_map.next_peer_address_id += 1;

        new_id
    }

    /// Open a new stream and assign it to specified TCP connection.
    /// Only one stream per connection is allowed to avoid HOL problem
    pub fn open_stream(&mut self, tcp_conn_id: u32) {
        self.tls_conn.as_mut().unwrap().open_stream(tcp_conn_id);
    }

    pub fn server_accept_connection(&mut self, listener: &mut TcpListener, config: Arc<ServerConfig>) -> Result<u32, io::Error> {
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
        } else {
            self.tls_conn
                .as_mut()
                .unwrap()
                .stream_map
                .attach_stream(conn_id);
            self.tls_conn
                .as_mut()
                .unwrap()
                .record_layer
                .start_new_seq_space(conn_id);
        }
        Ok(conn_id)
    }

    pub fn stream_send(
        &mut self, stream_id: u64, input: &[u8], fin: bool,
    ) -> Result<usize, Error> {
        let mut tls_conn = self.tls_conn.as_mut().unwrap();

        if tls_conn.is_handshaking() {
           return  Err(Error::HandshakeNotComplete)
        }

        // Get existing stream or create a new one.
        let stream = self.get_or_create_stream(stream_id, true)?;

        // check if key update message should be sent
        tls_conn.perhaps_write_key_update(Some(stream));


        let cap = stream.send.apply_limit(input.len());

        let (buf, fin) = if cap < input.len() {
            (&input[..cap], false)
        } else {
            (input, fin)
        };


        // Encapsulate data chunks with TCPLS stream frame header, encrypt each fragment then
        // buffer it in send buffer

        let iter = fragment_slice_owned(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            buf,
        );

        for mut m in iter {
            let mut header = StreamFrameHeader{
                length: m.payload.0.len() as u64,
                offset: stream.send.get_offset(),
                stream_id,
                fin: match fin { true => 1, false => 0, },
            };
            let header_len = header.get_header_length();
            m.payload.0.extend_from_slice(vec![0; header_len].as_slice());
            let mut octets = octets::OctetsMut::with_slice_at_offset(&mut m.payload.0, m.payload.0.len());
            header.encode_stream_header(&mut octets).expect("encoding stream header failed");


            // Close connection once we start to run out of
            // sequence space.
            if tls_conn
                .record_layer
                .wants_close_before_encrypt()
            {
                tls_conn.send_close_notify();
            }

            // Refuse to wrap counter at all costs.
            if tls_conn.record_layer.encrypt_exhausted() {
                return Err(Error::EncryptError);
            }

            let em = tls_conn.record_layer.encrypt_outgoing_owned(m);
            stream.send.append(em.encode());
        }

        Ok(cap)
    }

    pub fn get_or_create_stream(
        &mut self, id: u64,
        x: bool,
    ) -> Result<&mut stream::Stream, Error> {
        self.streams.get_or_create(id, self.is_server)
    }


    pub fn stream_recv<'a, 'b>(
        &'a mut self, stream_id: u64, app_buffers: &'b mut RecvBufMap,
    ) -> Result<(&'b [u8], usize, bool), Error> {

        let mut tls_conn = self.tls_conn.as_mut().unwrap();

        if tls_conn.is_handshaking() {
            return  Err(Error::HandshakeNotComplete)
        }


        // The stream is ready: we have a reference to some contiguous data
        let outbuf = app_buffers.get_mut(stream_id)?;

        let read = tls_conn.process_received()



        Ok((outbuf, read, fin))
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

/// Returns an iterator of PlainMessage objects from the input slice
fn fragment_slice_owned(
    typ: ContentType,
    version: ProtocolVersion,
    payload: & [u8],
) -> impl Iterator<Item = PlainMessage> {
    payload
        .chunks(MAX_TCPLS_FRAGMENT_LEN)
        .map(move |c| PlainMessage {
            typ,
            version,
            payload: Payload(c.to_vec()),
        })
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
