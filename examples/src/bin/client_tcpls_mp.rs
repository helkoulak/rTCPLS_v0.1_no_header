#[macro_use]
extern crate serde_derive;

use std::process;
use std::io;
use std::io::{Read, Write};

use std::ops::{Deref, DerefMut};
use std::str;
use std::sync::Arc;
use docopt::Docopt;
use mio::Token;
use ring::digest;
use rustls::recvbuf::RecvBufMap;
use rustls::tcpls::{build_tls_client_config, lookup_address, TcplsSession};
use rustls::tcpls::stream::{SimpleIdHashSet, StreamIter};

const CONNECTION1: mio::Token = mio::Token(0);
const CONNECTION2: mio::Token = mio::Token(1);

const CONNECTION3: mio::Token = mio::Token(2);


struct TlsClient {
    closing: bool,
    clean_closure: bool,
    tcpls_session: TcplsSession,
    all_joined: bool,
    sending_ids: SimpleIdHashSet,
}

impl TlsClient {
    fn new( ) -> Self {
        Self {
            closing: false,
            clean_closure: false,
            tcpls_session: TcplsSession::new(false),
            all_joined: false,
            sending_ids: SimpleIdHashSet::default(),
        }
    }

    /// Handles events sent to the TlsClient by mio::Poll
    fn handle_event(&mut self, ev: &mio::event::Event, recv_map: &mut RecvBufMap) {

        let token = &ev.token();

        if ev.is_readable()  {
            self.do_read(recv_map, token.0 as u64);
            if !self.tcpls_session.tls_conn.as_ref().unwrap().is_handshaking() && !self.sending_ids.contains(&(token.0 as u64)){
                let mut id_set = SimpleIdHashSet::default();

                print!("Client sends on connection {:?} \n", token.0);
                if token.0 == 0 {
                    self.send_data(vec![0u8; 64000].as_slice(), 0).expect("");
                    self.send_data(vec![1u8; 64000].as_slice(), 1).expect("");
                    self.send_data(vec![2u8; 64000].as_slice(), 2).expect("");
                    self.send_data(vec![3u8; 64000].as_slice(), 3).expect("");
                    id_set.insert(0);
                    id_set.insert(1);
                    id_set.insert(2);
                    id_set.insert(3);
                }
                if token.0 == 1 {
                    self.send_data(vec![4u8; 64000].as_slice(), 4).expect("");
                    self.send_data(vec![5u8; 64000].as_slice(), 5).expect("");
                    self.send_data(vec![6u8; 64000].as_slice(), 6).expect("");
                    id_set.insert(4);
                    id_set.insert(5);
                    id_set.insert(6);
                }
                if token.0 == 2 {
                    self.send_data(vec![7u8; 64000].as_slice(), 7).expect("");
                    self.send_data(vec![8u8; 64000].as_slice(), 8).expect("");
                    self.send_data(vec![9u8; 64000].as_slice(), 9).expect("");
                    id_set.insert(7);
                    id_set.insert(8);
                    id_set.insert(9);
                }
                self.tcpls_session.send_on_connection(Some(token.0 as u64), None, Some(id_set)).expect("Sending on connection failed");
                self.sending_ids.insert(token.0 as u64);
            }


        }

        if ev.is_writable() {
            self.do_write(token.0 as u64);
        }

        if self.is_closed() {
            println!("Connection closed");
            process::exit(if self.clean_closure { 0 } else { 1 });
        }
    }

    /// We're ready to do a read.
    fn do_read(&mut self, app_buffers: &mut RecvBufMap, id: u64) {
        if self.tcpls_session.tls_conn.as_mut().unwrap().outstanding_tcp_conns.as_mut_ref().contains_key(&id) {
            if !self.tcpls_session.tls_conn.as_mut().unwrap().is_handshaking() {
                self.process_join_reponse(id);
            }
            return;
        }
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
        let io_state = match self.tcpls_session.process_received(app_buffers, id as u32) {
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

    fn do_write(&mut self, id: u64) {

        if self.tcpls_session.tls_conn.as_mut().unwrap().outstanding_tcp_conns.as_mut_ref().contains_key(&id) &&
            !self.tcpls_session.tls_conn.as_mut().unwrap().is_handshaking() {
            self.join_outstanding(id);
            return;
        }
        if self.tcpls_session.tcp_connections.contains_key(&id) {

            self.tcpls_session.send_on_connection(Some(id), None, None).expect("Send on connection failed");
        }


    }

    /// Registers self as a 'listener' in mio::Registry
    fn register(&mut self, registry: &mio::Registry, recv_map: &RecvBufMap, token: Token) {
        let interest = self.event_set(recv_map, token.0 as u64);
        let  socket = self.tcpls_session.get_socket(token.0 as u64);
        registry
            .register(socket, token, interest)
            .unwrap();
    }

    /// Reregisters self as a 'listener' in mio::Registry.
    fn reregister(&mut self, registry: &mio::Registry, recv_map: & RecvBufMap, token: Token) {

        let interest = self.event_set(recv_map, token.0 as u64);
        let  socket = self.tcpls_session.get_socket(token.0 as u64);
        registry
            .reregister(socket, token, interest)
            .unwrap();
    }

    /// Use wants_read/wants_write to register for different mio-level
    /// IO readiness events.
    fn event_set(&mut self, app_buf: & RecvBufMap, id: u64) -> mio::Interest {

        let rd = match self.tcpls_session.tls_conn.as_mut().unwrap().outstanding_tcp_conns.as_mut_ref().contains_key(&id) {
            true => self.tcpls_session.tls_conn.as_mut().unwrap().outstanding_tcp_conns.wants_read(id),
            false => self.tcpls_session.tls_conn.as_mut().unwrap().wants_read(app_buf),
            };
        let wr = match self.tcpls_session.tls_conn.as_mut().unwrap().outstanding_tcp_conns.as_mut_ref().contains_key(&id) {
            true => self.tcpls_session.tls_conn.as_mut().unwrap().outstanding_tcp_conns.wants_write(id),
            false => self.tcpls_session.tls_conn.as_mut().unwrap().wants_write(),
        };

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
        let mut len:u16 = 0;

        len += input.len() as u16;
        // Calculate the hash of input using SHA-256
        let hash = TlsClient::calculate_sha256_hash(input);
        len += hash.algorithm().output_len as u16;
        len += 4;
        // Append total length and hash value to the input to be sent to the peer
        data.extend_from_slice( [((len >> 8) & 0xFF) as u8, ((len & 0xFF) as u8)].as_slice());
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

    pub(crate) fn join_outstanding(&mut self, id: u64) {
        self.tcpls_session.join_tcp_connection(id).expect("sending join request failed");
    }

    pub(crate) fn process_join_reponse(&mut self, id: u64) {
        match self.tcpls_session.tls_conn.as_mut()
            .unwrap()
            .outstanding_tcp_conns
            .as_mut_ref()
            .get_mut(&id)
            .unwrap()
            .receive_join_request() {
            Ok(_bytes) => (),
            Err(ref error) => if error.kind() == io::ErrorKind::WouldBlock {
                return;
            },
            Err(error) => panic!("{:?}", error),
        }

        match self.tcpls_session.process_join_request(id) {
            Ok(()) => {
                self.all_joined = self.tcpls_session.tls_conn.as_mut()
                    .unwrap()
                    .outstanding_tcp_conns
                    .as_mut_ref().is_empty();
                return
            },
            Err(err) => panic!("{:?}", err),
        };
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

    let dest_add1 = lookup_address("0.0.0.0", 8443);
    let dest_add2 = lookup_address("0.0.0.0", 8444);
    let dest_add3 = lookup_address("0.0.0.0", 8445);

    let mut client = TlsClient::new();

    let config = build_tls_client_config_args(&args);

    let server_name = args.arg_hostname.as_str().try_into().expect("invalid DNS name");

    client.tcpls_session.tcpls_connect(dest_add1, Some(config), Some(server_name), false);
    // Create second tcp conection
    client.tcpls_session.tcpls_connect(dest_add2, None, None, false);
    // Create third tcp conection
    client.tcpls_session.tcpls_connect(dest_add3, None, None, false);


    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(50);
    client.register(poll.registry(), &recv_map, CONNECTION1);
    client.register(poll.registry(), &recv_map, CONNECTION2);
    client.register(poll.registry(), &recv_map, CONNECTION3);
    loop {
        poll.poll(&mut events, None).unwrap();

        for ev in events.iter() {
                client.handle_event(ev, &mut recv_map);
                client.reregister(poll.registry(), &recv_map, ev.token());
            }

    }
}
