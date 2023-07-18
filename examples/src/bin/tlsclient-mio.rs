use std::process;
use std::sync::Arc;

use mio::net::TcpStream;

use std::fs;
use std::io;
use std::io::{BufReader, Read, Write};
use std::net::SocketAddr;
use std::str;
// use local_ip_address::local_ip;

use crate::tcpls::*;

#[macro_use]
extern crate serde_derive;

use docopt::Docopt;
use env_logger::builder;

use rustls::{OwnedTrustAnchor, RootCertStore, tcpls};
use rustls::tcpls::TlsContext::Client;

const CLIENT: mio::Token = mio::Token(0);



struct TlsClient {
    closing: bool,
    clean_closure: bool,
    tls_conn: rustls::tcpls::ClientConnection,
}

impl  TlsClient {
    fn new(

        server_name: rustls::ServerName,
        cfg: Arc<rustls::ClientConfig>,
    ) -> Self {
        Self {

            closing: false,
            clean_closure: false,
            tls_conn: rustls::tcpls::client_new_tls_session(cfg, server_name),
        }
    }

    /// Handles events sent to the TlsClient by mio::Poll
    fn ready(&mut self, ev: &mio::event::Event, socket: &mut TcpStream) {
        assert_eq!(ev.token(), CLIENT);

        if ev.is_readable() && self.tls_conn.is_handshaking(){
            self.do_read(socket);
        }

        if ev.is_writable() && self.tls_conn.is_handshaking(){
            self.do_write(socket);
        }

        if ev.is_writable() && ! self.tls_conn.is_handshaking() {
            let buf = [0; TCPLS_STREAM_FRAME_MAX_PAYLOAD_LENGTH];
            self.tls_conn.writer().write(& buf);
            self.do_write(socket);
        }


        if ev.is_readable() && ! self.tls_conn.is_handshaking() {
            self.do_read(socket);
        }

        if self.is_closed() {
            println!("Connection closed");
            process::exit(if self.clean_closure { 0 } else { 1 });
        }
    }

    fn read_source_to_end(&mut self, rd: &mut dyn io::Read) -> io::Result<usize> {
        let mut buf = Vec::new();
        let len = rd.read_to_end(&mut buf)?;
        self.tls_conn.writer().write_all(&buf).unwrap();
        Ok(len)
    }

    /// We're ready to do a read.
    fn do_read(&mut self, socket: &mut TcpStream) {
        // Read TLS data.  This fails if the underlying TCP connection
        // is broken.
        match self.tls_conn.read_tls(socket) {
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
        let io_state = match self.tls_conn.process_new_packets() {
            Ok(io_state) => io_state,
            Err(err) => {
                println!("TLS error: {:?}", err);
                self.closing = true;
                return;
            }
        };

        // Having read some TLS data, and processed any new messages,
        // we might have new plaintext as a result.
        //
        // Read it and then write it to stdout.
        if io_state.plaintext_bytes_to_read() > 0 {
            let mut plaintext = Vec::new();
            plaintext.resize(io_state.plaintext_bytes_to_read(), 0u8);
            self.tls_conn.reader().read_exact(&mut plaintext).unwrap();
            io::stdout().write_all(&plaintext).unwrap();
        }

        // If wethat fails, the peer might have started a clean TLS-level
        // session closure.
        if io_state.peer_has_closed() {
            self.clean_closure = true;
            self.closing = true;
        }
    }

    fn do_write(&mut self, socket: &mut TcpStream) {
        self.tls_conn
            .write_tls(socket)
            .unwrap();
    }

    /// Registers self as a 'listener' in mio::Registry
    fn register(&mut self, registry: &mio::Registry, socket: &mut TcpStream) {
        let interest = self.event_set();
        registry
            .register(socket, CLIENT, interest)
            .unwrap();
    }

    /// Reregisters self as a 'listener' in mio::Registry.
    fn reregister(&mut self, registry: &mio::Registry, socket: &mut TcpStream) {
        let interest = self.event_set();
        registry
            .reregister(socket, CLIENT, interest)
            .unwrap();
    }

    /// Use wants_read/wants_write to register for different mio-level
    /// IO readiness events.
    fn event_set(&self) -> mio::Interest {
        let rd = self.tls_conn.wants_read();
        let wr = self.tls_conn.wants_write();

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
}
impl io::Write for TlsClient {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.tls_conn.writer().write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tls_conn.writer().flush()
    }
}

impl io::Read for TlsClient {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.tls_conn.reader().read(bytes)
    }
}

const USAGE: &str = "
Connects to the TLS server at hostname:PORT.  The default PORT
is 443.  By default, this reads a request from stdin (to EOF)
before making the connection.  --http replaces this with a
basic HTTP GET request for /.

If --cafile is not supplied, a built-in set of CA certificates
are used from the webpki-roots crate.

Usage:
  tlsclient-mio [options] [--suite SUITE ...] [--proto PROTO ...] [--protover PROTOVER ...] <hostname>
  tlsclient-mio (--version | -v)
  tlsclient-mio (--help | -h)

Options:
    -p, --port PORT     Connect to PORT [default: 443].
    --http              Send a basic HTTP GET request for /.
    --cafile CAFILE     Read root certificates from CAFILE.
    --auth-key KEY      Read client authentication key from KEY.
    --auth-certs CERTS  Read client authentication certificates from CERTS.
                        CERTS must match up with KEY.
    --protover VERSION  Disable default TLS version list, and use
                        VERSION instead.  May be used multiple times.
    --suite SUITE       Disable default cipher suite list, and use
                        SUITE instead.  May be used multiple times.
    --proto PROTOCOL    Send ALPN extension containing PROTOCOL.
                        May be used multiple times to offer several protocols.
    --no-tickets        Disable session ticket support.
    --no-sni            Disable server name indication support.
    --insecure          Disable certificate verification.
    --verbose           Emit log output.
    --max-frag-size M   Limit outgoing messages to M bytes.
    --version, -v       Show tool version.
    --help, -h          Show this screen.
";

#[derive(Debug, Deserialize)]
struct Args {
    flag_port: Option<u16>,
    flag_http: bool,
    flag_verbose: bool,
    flag_protover: Vec<String>,
    flag_suite: Vec<String>,
    flag_proto: Vec<String>,
    flag_max_frag_size: Option<usize>,
    flag_cafile: Option<String>,
    flag_no_tickets: bool,
    flag_no_sni: bool,
    flag_insecure: bool,
    flag_auth_key: Option<String>,
    flag_auth_certs: Option<String>,
    arg_hostname: String,
}











#[cfg(feature = "dangerous_configuration")]
mod danger {
    pub struct NoCertificateVerification {}

    impl rustls::client::ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::Certificate,
            _intermediates: &[rustls::Certificate],
            _server_name: &rustls::ServerName,
            _scts: &mut dyn Iterator<Item = &[u8]>,
            _ocsp: &[u8],
            _now: std::time::SystemTime,
        ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::ServerCertVerified::assertion())
        }
    }
}

#[cfg(feature = "dangerous_configuration")]
fn apply_dangerous_options(args: &Args, cfg: &mut rustls::ClientConfig) {
    if args.flag_insecure {
        cfg.dangerous()
            .set_certificate_verifier(Arc::new(danger::NoCertificateVerification {}));
    }
}

#[cfg(not(feature = "dangerous_configuration"))]
fn apply_dangerous_options(args: &Args, _: &mut rustls::ClientConfig) {
    if args.flag_insecure {
        panic!("This build does not support --insecure.");
    }
}
/// Build a `ClientConfig` from our arguments
fn build_tls_client_config_args(args: &Args) -> Arc<rustls::ClientConfig> {


    build_tls_client_config(args.flag_cafile.as_ref(), None, args.flag_suite.clone(), args.flag_protover.clone(), args.flag_auth_key.clone(),
                            args.flag_auth_certs.clone(), args.flag_no_tickets, args.flag_no_sni, args.flag_proto.clone(), args.flag_max_frag_size)

}


/// Parse some arguments, then make a TLS client connection
/// somewhere.
fn main() {


    let version = env!("CARGO_PKG_NAME").to_string() + ", version: " + env!("CARGO_PKG_VERSION");

    let args: Args = Docopt::new(USAGE)
        .map(|d| d.help(true))
        .map(|d| d.version(Some(version)))
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    if args.flag_verbose {
        env_logger::Builder::new().parse_filters("trace").init();
    }
    let dest_address = tcpls::lookup_address(args.arg_hostname.as_str(), args.flag_port.unwrap());

    let mut tcpls_session = tcpls::TcplsSession::new();

    let config = build_tls_client_config_args(&args);

    let server_name = args.arg_hostname.as_str().try_into().expect("invalid DNS name");

    tcp_connect(dest_address, &mut tcpls_session);

    let connection_id = tcpls_session.next_connection_id - 1;

    let tcp_conn = tcpls_session.tcp_connections.get(connection_id as usize).unwrap();

    let socket = tcp_conn.socket.unwrap().by_ref();


    let mut tlsclient = TlsClient::new(server_name, config.clone());

    tcpls_session.tls_ctx.insert(Client(config));


    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(50);
    tlsclient.register(poll.registry(), socket);

    loop {
        poll.poll(&mut events, None).unwrap();

        for ev in events.iter() {
            tlsclient.ready(ev, socket);
            tlsclient.reregister(poll.registry(), socket);
        }
    }
}
