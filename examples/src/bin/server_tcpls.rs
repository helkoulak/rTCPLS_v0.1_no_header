use std::sync::Arc;

use mio::net::{TcpListener, TcpStream};

#[macro_use]
extern crate log;

use std::collections::HashMap;

use std::io;
use std::io::{Read, Write};
use std::net;

use std::time::Duration;

#[macro_use]
extern crate serde_derive;
extern crate core;

use docopt::Docopt;
use mio::Token;

use ring::digest;



use rustls::{self, Connection, tcpls};
use rustls::recvbuf::RecvBufMap;
use rustls::tcpls::{server_create_listener, TcplsSession};

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
    next_id: usize,
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

            next_id: 0,
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
                Ok((conn_id)) => {
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
        let token = event.token();

        self.handle_event(registry, event, recv_map);

    }
    fn handle_event(&mut self, registry: &mio::Registry, ev: &mio::event::Event, recv_map: &mut RecvBufMap) {
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
            debug!("\n \n Bytes received on stream {:?} : \n \n {:?} \n \n SHA-256 Hash {:?} \n Total length: {:?} \n",
                stream.1.id,
                &stream.1.as_ref_consumed()[..hash_index - 4],
                &stream.1.as_ref_consumed()[hash_index..].iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>(),
                unprocessed_len);
            stream.1.consume(received_len + 2);
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
        match self.tcpls_session.recv_on_connection(id) {
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
        let io_state = match self.tcpls_session.stream_recv(app_buffers) {
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

    /// Process some amount of received plaintext.
    fn incoming_plaintext(&mut self, buf: &[u8]) {
        match self.mode {
            ServerMode::Echo => {
                self.tcpls_session
                    .tls_conn
                    .as_mut()
                    .unwrap()
                    .writer()
                    .write_all(buf)
                    .unwrap();
            }
            ServerMode::Http => {
                self.send_http_response_once();
            }
            ServerMode::Forward(_) => {
                self.back
                    .as_mut()
                    .unwrap()
                    .write_all(buf)
                    .unwrap();
            }
        }
    }

    fn send_http_response_once(&mut self) {
        let response =
            b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nHello world from rustls tlsserver\r\n";
        if !self.sent_http_response {
            self.tcpls_session
                .tls_conn
                .as_mut()
                .unwrap()
                .writer()
                .write_all(response)
                .unwrap();
            self.sent_http_response = true;
            self.tcpls_session
                .tls_conn
                .as_mut()
                .unwrap()
                .send_close_notify();
        }
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

    /// What IO events we're currently waiting for,
    /// based on wants_read/wants_write.
    fn event_set(&self, app_buf: &RecvBufMap) -> mio::Interest {
        let rd = self.tcpls_session.tls_conn.as_ref().unwrap().wants_read(app_buf);
        let wr = self.tcpls_session.tls_conn.as_ref().unwrap().wants_write();

        if rd && wr {
            mio::Interest::READABLE | mio::Interest::WRITABLE
        } else if wr {
            mio::Interest::WRITABLE
        } else {
            mio::Interest::READABLE
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
/// Open a plaintext TCP-level connection for forwarded connections.
fn open_back(mode: &ServerMode) -> Option<TcpStream> {
    match *mode {
        ServerMode::Forward(ref port) => {
            let addr = net::SocketAddrV4::new(net::Ipv4Addr::new(127, 0, 0, 1), *port);
            let conn = TcpStream::connect(net::SocketAddr::V4(addr)).unwrap();
            Some(conn)
        }
        _ => None,
    }
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



const USAGE: &str = "
Runs a TLS server on :PORT.  The default PORT is 443.

`echo' mode means the server echoes received data on each connection.

`http' mode means the server blindly sends a HTTP response on each
connection.

`forward' means the server forwards plaintext to a connection made to
localhost:fport.

`--certs' names the full certificate chain, `--key' provides the
RSA private key.

Usage:
  tlsserver-mio --certs CERTFILE --key KEYFILE [--suite SUITE ...] \
     [--proto PROTO ...] [--protover PROTOVER ...] [options] echo
  tlsserver-mio --certs CERTFILE --key KEYFILE [--suite SUITE ...] \
     [--proto PROTO ...] [--protover PROTOVER ...] [options] http
  tlsserver-mio --certs CERTFILE --key KEYFILE [--suite SUITE ...] \
     [--proto PROTO ...] [--protover PROTOVER ...] [options] forward <fport>
  tlsserver-mio (--version | -v)
  tlsserver-mio (--help | -h)

Options:
    -p, --port PORT     Listen on PORT [default: 443].
    --certs CERTFILE    Read server certificates from CERTFILE.
                        This should contain PEM-format certificates
                        in the right order (the first certificate should
                        certify KEYFILE, the last should be a root CA).
    --key KEYFILE       Read private key from KEYFILE.  This should be a RSA
                        private key or PKCS8-encoded private key, in PEM format.
    --ocsp OCSPFILE     Read DER-encoded OCSP response from OCSPFILE and staple
                        to certificate.  Optional.
    --auth CERTFILE     Enable client authentication, and accept certificates
                        signed by those roots provided in CERTFILE.
    --require-auth      Send a fatal alert if the client does not complete client
                        authentication.
    --resumption        Support session resumption.
    --tickets           Support tickets.
    --protover VERSION  Disable default TLS version list, and use
                        VERSION instead.  May be used multiple times.
    --suite SUITE       Disable default cipher suite list, and use
                        SUITE instead.  May be used multiple times.
    --proto PROTOCOL    Negotiate PROTOCOL using ALPN.
                        May be used multiple times.
    --verbose           Emit log output.
    --version, -v       Show tool version.
    --help, -h          Show this screen.
";

#[derive(Debug, Deserialize)]
pub struct Args {
    cmd_echo: bool,
    cmd_http: bool,
    flag_port: Option<u16>,
    flag_verbose: bool,
    flag_protover: Vec<String>,
    flag_suite: Vec<String>,
    flag_proto: Vec<String>,
    flag_certs: Option<String>,
    flag_key: Option<String>,
    flag_ocsp: Option<String>,
    flag_auth: Option<String>,
    flag_require_auth: bool,
    flag_resumption: bool,
    flag_tickets: bool,
    arg_fport: Option<u16>,
}


pub fn build_tls_server_config_args(args: &Args) -> Arc<rustls::ServerConfig> {
    tcpls::build_tls_server_config(args.flag_auth.clone(), args.flag_require_auth,
                                   args.flag_suite.clone(), args.flag_protover.clone(),
                                   args.flag_certs.clone(), args.flag_key.clone(),
                                   args.flag_ocsp.clone(), args.flag_resumption,
                                   args.flag_tickets, args.flag_proto.clone(), 5)
}

fn main() {
    let version = env!("CARGO_PKG_NAME").to_string() + ", version: " + env!("CARGO_PKG_VERSION");

    let args: Args = Docopt::new(USAGE)
        .map(|d| d.help(true))
        .map(|d| d.version(Some(version)))
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    if args.flag_verbose {
        env_logger::Builder::new()
            .parse_filters("trace")
            .init();
    }

    //Map of application controlled receive buffers
    let mut recv_map = RecvBufMap::new();

    let config = build_tls_server_config_args(&args);

    let mut listener = server_create_listener("0.0.0.0:443", Some(args.flag_port.unwrap()));

    let mut poll = mio::Poll::new().unwrap();

    poll.registry()
        .register(&mut listener, LISTENER, mio::Interest::READABLE)
        .unwrap();

    let mode = if args.cmd_echo {
        ServerMode::Echo
    } else if args.cmd_http {
        ServerMode::Http
    } else {
        ServerMode::Forward(args.arg_fport.expect("fport required"))
    };

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

