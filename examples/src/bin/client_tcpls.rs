#[macro_use]
extern crate serde_derive;

use std::process;
use std::fs::File;
use std::io;
use std::io::{Read, Write};

use std::ops::{Deref, DerefMut};
use std::str;
use std::sync::Arc;
use std::time::Duration;

use docopt::Docopt;
use env_logger::builder;
use env_logger::fmt::Color::White;
use ring::digest;

use rustls::{client, OwnedTrustAnchor, RootCertStore, };
use rustls::recvbuf::RecvBufMap;
use rustls::tcpls::{build_tls_client_config, DEFAULT_CONNECTION_ID, lookup_address, TcplsSession};
use rustls::tcpls::TlsConfig::Client;

const CLIENT: mio::Token = mio::Token(0);



struct TlsClient {
    closing: bool,
    clean_closure: bool,
    tcpls_session: TcplsSession,

}

impl TlsClient {
    fn new( ) -> Self {
        Self {
            closing: false,
            clean_closure: false,
            tcpls_session: TcplsSession::new(false),
        }
    }

    /// Handles events sent to the TlsClient by mio::Poll
    fn handle_event(&mut self, ev: &mio::event::Event, recv_map: &mut RecvBufMap) {

        assert_eq!(ev.token(), CLIENT);

        if ev.is_readable() && self.tcpls_session.tls_conn.as_ref().unwrap().is_handshaking(){
           self.do_read(recv_map);
        }

        if ev.is_writable() && self.tcpls_session.tls_conn.as_ref().unwrap().is_handshaking(){
            self.do_write();
        }

        if ev.is_writable() && ! self.tcpls_session.tls_conn.as_ref().unwrap().is_handshaking() {

           self.send_file("Cargo.toml", 0).expect("");
            self.send_file("Cargo.lock", 1).expect("");
            self.send_file("TLS_HS_Client", 2).expect("");
            self.tcpls_session.send_on_connection(0, None).expect("sending on socket has failed");
            
        }


        if ev.is_readable() && ! self.tcpls_session.tls_conn.as_ref().unwrap().is_handshaking() {
            self.do_read(recv_map);
        }

        if self.is_closed() {
            println!("Connection closed");
            process::exit(if self.clean_closure { 0 } else { 1 });
        }
    }

    fn read_source_to_end(&mut self, rd: &mut dyn io::Read) -> io::Result<usize> {
        let mut buf = Vec::new();
        let len = rd.read_to_end(&mut buf)?;
        self.tcpls_session.tls_conn.as_mut().unwrap().writer().write_all(&buf).unwrap();
        Ok(len)
    }

    /// We're ready to do a read.
    fn do_read(&mut self, app_buffers: &mut RecvBufMap) {
        // Read TLS data.  This fails if the underlying TCP connection
        // is broken.

        match self.tcpls_session.recv_on_connection(0) {
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
        let io_state = match self.tcpls_session.stream_recv(app_buffers) {
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
        /*if io_state.plaintext_bytes_to_read() > 0 {
            let mut plaintext = Vec::new();
            plaintext.resize(io_state.plaintext_bytes_to_read(), 0u8);
            self.tcpls_session.tls_conn.as_mut().unwrap().reader().read_exact(&mut plaintext).unwrap();
            io::stdout().write_all(&plaintext).unwrap();
        }*/

        // If wethat fails, the peer might have started a clean TLS-level
        // session closure.
        if io_state.peer_has_closed() {
            self.clean_closure = true;
            self.closing = true;
        }
    }

    fn do_write(&mut self) {

        self.tcpls_session.send_on_connection(0, None).unwrap();
    }

    /// Registers self as a 'listener' in mio::Registry
    fn register(&mut self, registry: &mio::Registry, recv_map: &RecvBufMap) {
        let interest = self.event_set(recv_map);
        registry
            .register(&mut self.tcpls_session.tcp_connections.get_mut(&0).unwrap().socket, CLIENT, interest)
            .unwrap();
    }

    /// Reregisters self as a 'listener' in mio::Registry.
    fn reregister(&mut self, registry: &mio::Registry, recv_map: & RecvBufMap) {

        let interest = self.event_set(recv_map);
        registry
            .reregister(&mut self.tcpls_session.tcp_connections.get_mut(&0).unwrap().socket, CLIENT, interest)
            .unwrap();
    }

    /// Use wants_read/wants_write to register for different mio-level
    /// IO readiness events.
    fn event_set(&mut self, app_buf: & RecvBufMap) -> mio::Interest {

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



    fn send_file(&mut self, file_name: &str, stream: u16) -> io::Result<()> {
        // Specify the file path you want to hash
        let file_path = file_name; // Replace with the actual file path

        // Read the file into a byte vector
        let mut file_contents = TlsClient::read_file_to_bytes(file_path)?;

        // Calculate the hash of the file contents using SHA-256
        let hash = TlsClient::calculate_sha256_hash(&file_contents);

        // Append hash value to the serialized file to be sent to the peer
        file_contents.extend(vec![0x0F, 0x0F, 0x0F, 0x0F]);
        file_contents.extend(hash.as_ref());

        // Print the hash as a hexadecimal string
        println!("\n \n File bytes on stream {:?} : \n {:?} \n \n SHA-256 Hash {:?} \n Total length: {:?} \n", stream, file_contents, hash, file_contents.len());

        self.tcpls_session.stream_send(stream, file_contents.as_ref(), false).expect("buffering failed");


        Ok(())

    }

    fn read_file_to_bytes(file_path: &str) -> io::Result<Vec<u8>> {
        let mut file = File::open(file_path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        Ok(buffer)
    }

    fn calculate_sha256_hash(data: &[u8]) -> digest::Digest {
        let algorithm = &digest::SHA256;
        digest::digest(algorithm, data)
    }

   /* fn read_file_and_calculate_hash(file_path: &str) -> Result<(Vec<u8>, Digest), Error> {
        // Open the file
        let mut file = File::open(file_path)?;

        // Read the file contents into a byte vector
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        // Calculate the SHA-256 hash
        let hash = ring::digest::digest(&ring::digest::SHA256, &buffer);

        Ok((buffer,hash))
    }*/
}
impl io::Write for TlsClient {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {

        self.tcpls_session.tls_conn.as_mut().unwrap().writer().write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tcpls_session.tls_conn.as_mut().unwrap().writer().flush()
    }
}

impl io::Read for TlsClient {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {

        self.tcpls_session.tls_conn.as_mut().unwrap().reader().read(bytes)
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

    let mut recv_map = RecvBufMap::new();

    let dest_address = lookup_address(args.arg_hostname.as_str(), args.flag_port.unwrap());

    let mut client = TlsClient::new();

    let config = build_tls_client_config_args(&args);

    let server_name = args.arg_hostname.as_str().try_into().expect("invalid DNS name");

    client.tcpls_session.tcpls_connect(dest_address, config, server_name, false);


    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(50);
    client.register(poll.registry(), &recv_map);

    loop {
        poll.poll(&mut events, Some(Duration::new(5, 0))).unwrap();

        for ev in events.iter() {
            client.handle_event(ev, &mut recv_map);
            client.reregister(poll.registry(), &recv_map);
        }
    }
}
