#[macro_use]
extern crate serde_derive;

use std::{net, process};
use std::io;
use std::io::{Read, Write};

use std::ops::{Deref, DerefMut};
use std::str;
use std::sync::Arc;
use std::time::Duration;

use docopt::Docopt;
use log::{debug, error};
use mio::net::{TcpListener, TcpStream};
use mio::Token;
use ring::digest;
use rustls::{ALL_CIPHER_SUITES, ClientConfig, DEFAULT_CIPHER_SUITES};
use rustls::recvbuf::RecvBufMap;
use rustls::tcpls::{build_tls_client_config, build_tls_server_config, lookup_address, lookup_suites, server_create_listener, TcplsSession};
use rustls::tcpls::stream::SimpleIdHashSet;

const CLIENT: mio::Token = mio::Token(0);



struct TlsClient {
    closing: bool,
    clean_closure: bool,
    tcpls_session: TcplsSession,

}

impl TlsClient {
    fn new() -> Self {
        Self {
            closing: false,
            clean_closure: false,
            tcpls_session: TcplsSession::new(false),
        }
    }

    /// Handles events sent to the TlsClient by mio::Poll
    fn handle_event_clnt(&mut self, ev: &mio::event::Event, recv_map: &mut RecvBufMap) {
        let token = &ev.token();

        if ev.is_readable() {
            self.do_read(recv_map, token.0 as u64);

            if !self.tcpls_session.tls_conn.as_ref().unwrap().is_handshaking() {
                //Send three byte arrays on three streams
                let mut id_set = SimpleIdHashSet::default();

                self.send_data(vec![0u8; 64000].as_slice(), 0).expect("");
                self.send_data(vec![1u8; 64000].as_slice(), 1).expect("");
                self.send_data(vec![2u8; 64000].as_slice(), 2).expect("");

                id_set.insert(0);
                id_set.insert(1);
                id_set.insert(2);

                let stream_iter = self.tcpls_session.tls_conn.as_mut().unwrap().streams_to_flush(&mut id_set, true);
                self.tcpls_session.send_on_connection(token.0 as u64, None, Some(stream_iter)).expect("Sending on connection failed");
            }
        }

        if ev.is_writable() {
            self.do_write(token);
        }


        if self.is_closed() {
            println!("Connection closed");
            process::exit(if self.clean_closure { 0 } else { 1 });
        }
    }


    /// We're ready to do a read.
    fn do_read(&mut self, app_buffers: &mut RecvBufMap, id: u64) {
        // Read TLS data.  This fails if the underlying TCP connection
        // is broken.

        match self.tcpls_session.recv_on_connection(id as u32) {
            Err(error) => {
                if error.kind() == io::ErrorKind::WouldBlock {
                    return;
                }
                println!("TLS read error: {:?}", error);
                self.closing = true;
                return;
            }

            // If we're ready but there's no data: EOF.
            Ok(0) => {
                println!("EOF");
                self.closing = true;
                self.clean_closure = true;
                return;
            }

            Ok(_) => {}
        };

        // Reading some TLS data might have yielded new TLS
        // messages to process.  Errors from this indicate
        // TLS protocol problems and are fatal.
        let io_state = match self.tcpls_session.stream_recv(app_buffers, id as u32) {
            Ok(io_state) => io_state,
            Err(err) => {
                println!("TLS error: {:?}", err);
                self.closing = true;
                return;
            }
        };


        // If wethat fails, the peer might have started a clean TLS-level
        // session closure.
        if io_state.peer_has_closed() {
            self.clean_closure = true;
            self.closing = true;
        }
    }

    fn do_write(&mut self, token: &Token) {
        self.tcpls_session.send_on_connection(token.0 as u64, None, None).unwrap();
    }

    /// Registers self as a 'listener' in mio::Registry
    fn register(&mut self, registry: &mio::Registry, recv_map: &RecvBufMap) {
        let interest = self.event_set(recv_map);
        registry
            .  register(&mut self.tcpls_session.tcp_connections.get_mut(&0).unwrap().socket, CLIENT, interest)
            .unwrap();
    }

    /// Reregisters self as a 'listener' in mio::Registry.
    fn reregister(&mut self, registry: &mio::Registry, recv_map: &RecvBufMap) {
        let interest = self.event_set(recv_map);
        registry
            .reregister(&mut self.tcpls_session.tcp_connections.get_mut(&0).unwrap().socket, CLIENT, interest)
            .unwrap();
    }

    /// Use wants_read/wants_write to register for different mio-level
    /// IO readiness events.
    fn event_set(&mut self, app_buf: &RecvBufMap) -> mio::Interest {
        let rd = self.tcpls_session.tls_conn.as_mut().unwrap().wants_read(app_buf);
        let wr = self.tcpls_session.tls_conn.as_mut().unwrap().wants_write();

        if rd && wr {
            mio::Interest::READABLE | mio::Interest::WRITABLE
        } else if wr {
            mio::Interest::WRITABLE
        } else {
            mio::Interest::READABLE
        }
    }

    fn is_closed(&self) -> bool {
        self.closing
    }


    fn send_data(&mut self, input: &[u8], stream: u16) -> io::Result<()> {
        let mut data = Vec::new();
        // Total length to send
        let mut len: u16 = 0;

        len += input.len() as u16;
        // Calculate the hash of input using SHA-256
        let hash = TlsClient::calculate_sha256_hash(input);
        len += hash.algorithm().output_len as u16;
        len += 4;
        // Append total length and hash value to the input to be sent to the peer
        data.extend_from_slice([((len >> 8) & 0xFF) as u8, ((len & 0xFF) as u8)].as_slice());
        data.extend_from_slice(input);
        data.extend(vec![0x0F, 0x0F, 0x0F, 0x0F]);
        data.extend(hash.as_ref());

        // Print the hash as a hexadecimal string
        // println!("\n \n File bytes on stream {:?} : \n {:?} \n \n SHA-256 Hash {:?} \n Total length: {:?} \n", stream, file_contents, hash, len);

        self.tcpls_session.stream_send(stream, data.as_ref(), false).expect("buffering failed");


        Ok(())
    }


    fn calculate_sha256_hash(data: &[u8]) -> digest::Digest {
        let algorithm = &digest::SHA256;
        digest::digest(algorithm, data)
    }
}


pub fn make_config(cafile: &String) -> Arc<ClientConfig>{
    build_tls_client_config(Some(cafile), None,  Vec::new(), Vec::new(), None, None, false, false, Vec::new(), None )
}

/// Parse some arguments, then make a TLS client connection
/// somewhere.
fn run_client(cafile: &String, port: u16, host_name: &str, verbose: bool) {

    let version = env!("CARGO_PKG_NAME").to_string() + ", version: " + env!("CARGO_PKG_VERSION");

    if verbose {
        env_logger::Builder::new().parse_filters("trace").init();
    }

    let mut recv_map = RecvBufMap::new();

    let dest_address = lookup_address(host_name, port);

    let mut client = TlsClient::new();

    let config = make_config(cafile);

    let server_name = host_name.try_into().expect("invalid DNS name");

    client.tcpls_session.tcpls_connect(dest_address, Some(config), Some(server_name), false);

    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(50);
    client.register(poll.registry(), &recv_map);

    loop {
        poll.poll(&mut events, Some(Duration::new(5, 0))).unwrap();

        for ev in events.iter() {
            client.handle_event_clnt(ev, &mut recv_map);
            client.reregister(poll.registry(), &recv_map);
        }
    }
}





// Token for our listening socket.
const LISTENER: Token = Token(100);

// Which mode the server operates in.
#[derive(Clone)]
enum ServerMode {
    /// Write back received bytes
    Echo,

    /// Do one read, then write a bodged HTTP response and
    /// cleanly close the connection.
    Http,

    /// Forward traffic to/from given port on localhost.
    Forward(u16),
}

/// This binds together a TCP listening socket, some outstanding
/// connections, and a TLS server configuration.
struct TlsServer {
    listener: TcpListener,
    tls_config: Arc<rustls::ServerConfig>,

    closing: bool,
    closed: bool,
    mode: ServerMode,
    back: Option<TcpStream>,
    sent_http_response: bool,
    tcpls_session: TcplsSession,

}

impl TlsServer {
    fn new(listener: TcpListener, mode: ServerMode, cfg: Arc<rustls::ServerConfig>) -> Self {
        Self {
            listener,
            tls_config: cfg,
            mode,
            back: None,
            sent_http_response: false,

            closing: false,
            closed: false,
            tcpls_session: TcplsSession::new(true),
        }
    }

    fn accept(&mut self, registry: &mio::Registry, recv_map: &RecvBufMap) -> Result<(), io::Error> {
        loop {
            match self.tcpls_session.server_accept_connection(&mut self.listener, self.tls_config.clone()) {
                Ok(conn_id) => {
                    debug!("Accepting new connection of id {:?}", conn_id);

                    let token = Token(conn_id as usize);

                    self.register(registry, recv_map, token)
                }
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(err) => {
                    println!(
                        "encountered error while accepting connection; err={:?}",
                        err
                    );
                    return Err(err);
                }
            }
        }
    }

    fn conn_event(&mut self, registry: &mio::Registry, event: &mio::event::Event, recv_map: &mut RecvBufMap) {

        self.handle_event_srv(registry, event, recv_map);

    }
    fn handle_event_srv(&mut self, registry: &mio::Registry, ev: &mio::event::Event, recv_map: &mut RecvBufMap) {
        // If we're readable: read some TLS.  Then
        // see if that yielded new plaintext.  Then
        // see if the backend is readable too.
        let token = &ev.token();
        if ev.is_readable() {
            self.do_read(recv_map, token.0 as u64);

            self.try_back_read();

        }


        if ev.is_writable() {
            self.do_tls_write_and_handle_error();
        }

        if self.closing {
            let _ = self
                .tcpls_session
                .tcp_connections
                .get_mut(&0)
                .unwrap()
                .socket
                .shutdown(net::Shutdown::Both);
            self.close_back();
            self.closed = true;
            self.deregister(registry);
        } else {
            self.reregister(registry, recv_map, *token);
        }
    }

    pub fn verify_received(&mut self, recv_map: &mut RecvBufMap ) {

        let mut hash_index= 0;


        for stream in recv_map.get_iter_mut() {
            if stream.1.is_empty() || stream.1.is_consumed(){
                continue
            }

            let received_len: usize = u16::from_be_bytes([stream.1.as_ref_consumed()[0], stream.1.as_ref_consumed()[1]]) as usize;
            let unprocessed_len = stream.1.as_ref_consumed()[2..].len();

            if received_len != unprocessed_len {
                continue
            }



            hash_index = match find_pattern(&stream.1.as_ref_consumed(), vec![0x0f, 0x0f, 0x0f, 0x0f].as_slice()) {
                Some(n) => n + 4,
                None => panic!("hash prefix does not exist"),
            };

            assert_eq!(&stream.1.as_ref_consumed()[hash_index..], self.calculate_sha256_hash(&stream.1.as_ref_consumed()[2..hash_index - 4]).as_ref());
            debug!("\n \n Bytes received on stream {:?} : \n \n SHA-256 Hash {:?} \n Total length: {:?} \n",
                stream.1.id,
                &stream.1.as_ref_consumed()[hash_index..].iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>(),
                unprocessed_len);
            stream.1.empty_stream();
        }
    }

    fn calculate_sha256_hash(&mut self, data: &[u8]) -> digest::Digest {
        let algorithm = &digest::SHA256;
        digest::digest(algorithm, data)
    }


    /// Close the backend connection for forwarded sessions.
    fn close_back(&mut self) {
        if self.back.is_some() {
            let back = self.back.as_mut().unwrap();
            back.shutdown(net::Shutdown::Both)
                .unwrap();
        }
        self.back = None;
    }

    fn do_read(&mut self, app_buffers: &mut RecvBufMap, id: u64) {
        // Read some TLS data.
        match self.tcpls_session.recv_on_connection(id as u32) {
            Err(err) => {
                if let io::ErrorKind::WouldBlock = err.kind() {
                    return;
                }

                error!("read error {:?}", err);
                self.closing = true;
                return;
            }
            Ok(0) => {
                debug!("eof");
                self.closing = true;
                return;
            }
            Ok(_) => {}
        };

        // Reading some TLS data might have yielded new TLS
        // messages to process.  Errors from this indicate
        // TLS protocol problems and are fatal.
        match self.tcpls_session.stream_recv(app_buffers, id as u32 ) {
            Ok(io_state) => io_state,
            Err(err) => {
                println!("TLS error: {:?}", err);
                self.closing = true;
                return;
            }
        };

    }



    fn try_back_read(&mut self) {
        if self.back.is_none() {
            return;
        }

        // Try a non-blocking read.
        let mut buf = [0u8; 1024];
        let back = self.back.as_mut().unwrap();
        let rc = try_read(back.read(&mut buf));

        if rc.is_err() {
            error!("backend read failed: {:?}", rc);
            self.closing = true;
            return;
        }

        let maybe_len = rc.unwrap();

        // If we have a successful but empty read, that's an EOF.
        // Otherwise, we shove the data into the TLS session.
        match maybe_len {
            Some(len) if len == 0 => {
                debug!("back eof");
                self.closing = true;
            }
            Some(len) => {
                self.tcpls_session.
                    tls_conn
                    .as_mut()
                    .unwrap()
                    .writer()
                    .write_all(&buf[..len])
                    .unwrap();
            }
            None => {}
        };
    }


    fn tls_write(&mut self) -> io::Result<usize> {
        self.tcpls_session.tls_conn.as_mut().unwrap()
            .write_tls(&mut self.tcpls_session.tcp_connections.get_mut(&0).unwrap().socket, 0)
    }

    fn do_tls_write_and_handle_error(&mut self) {
        let rc = self.tls_write();
        if rc.is_err() {
            error!("write failed {:?}", rc);
            self.closing = true;
        }
    }

    fn register(&mut self, registry: &mio::Registry, app_buf: &RecvBufMap, token: Token) {
        let event_set = self.event_set(app_buf);
        registry
            .register(&mut self.tcpls_session.tcp_connections.get_mut(&0).unwrap().socket, token, event_set)
            .unwrap();

        if self.back.is_some() {
            registry
                .register(
                    self.back.as_mut().unwrap(),
                    token,
                    mio::Interest::READABLE,
                )
                .unwrap();
        }
    }

    fn reregister(&mut self, registry: &mio::Registry, app_buf: &RecvBufMap, token: Token) {
        let event_set = self.event_set(app_buf);
        registry
            .reregister(&mut self.tcpls_session.tcp_connections.get_mut(&0).unwrap().socket, token, event_set)
            .unwrap();
    }

    fn deregister(&mut self, registry: &mio::Registry) {
        registry
            .deregister(&mut self.tcpls_session.tcp_connections.get_mut(&0).unwrap().socket)
            .unwrap();

        if self.back.is_some() {
            registry
                .deregister(self.back.as_mut().unwrap())
                .unwrap();
        }
    }


    fn is_closed(&self) -> bool {
        self.closed
    }
}

pub fn find_pattern(data: &[u8], pattern: &[u8]) -> Option<usize> {
    for i in 0..data.len() {
        if data[i..].starts_with(pattern) {
            return Some(i);
        }
    }
    None
}


/// This used to be conveniently exposed by mio: map EWOULDBLOCK
/// errors to something less-errory.
fn try_read(r: io::Result<usize>) -> io::Result<Option<usize>> {
    match r {
        Ok(len) => Ok(Some(len)),
        Err(e) => {
            if e.kind() == io::ErrorKind::WouldBlock {
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}





pub fn make_config_serv(certfile: String, key: String) -> Arc<rustls::ServerConfig> {
    build_tls_server_config(None, false,
                            Vec::new(), Vec::new(),
                                   Some(certfile), Some(key),
                                   None, false,
                                   false, Vec::new(), 5)
}

fn run_server(cafile: String, key: String, verbose: bool) {
    let version = env!("CARGO_PKG_NAME").to_string() + ", version: " + env!("CARGO_PKG_VERSION");

    if verbose {
        env_logger::Builder::new()
            .parse_filters("trace")
            .init();
    }

    //Map of application controlled receive buffers
    let mut recv_map = RecvBufMap::new();

    let config = make_config_serv(cafile, key);

    let mut listener = server_create_listener("0.0.0.0:8443", None);

    let mut poll = mio::Poll::new().unwrap();

    poll.registry()
        .register(&mut listener, LISTENER, mio::Interest::READABLE)
        .unwrap();

    let mode = ServerMode::Echo;

    let mut tcpls_server = TlsServer::new(listener, mode, config);

    let mut events = mio::Events::with_capacity(256);
    loop {
        poll.poll(&mut events, Some(Duration::new(5, 0))).unwrap();

        for event in events.iter() {
            match event.token() {
                LISTENER => {
                    tcpls_server
                        .accept(poll.registry(), &recv_map)
                        .expect("error accepting socket");
                }
                _ => {
                    tcpls_server.conn_event(poll.registry(), event, &mut recv_map);
                    if !tcpls_server
                        .tcpls_session
                        .tls_conn
                        .as_ref()
                        .unwrap().is_handshaking() {
                        tcpls_server
                            .verify_received(&mut recv_map);
                    }
                }
            }
        }
    }
}

