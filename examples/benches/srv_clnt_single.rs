use std::{fs, io};
use std::io::Write;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use rustls::{ClientConfig, ClientConnection, Connection, ConnectionCommon, DEFAULT_CIPHER_SUITES, RootCertStore, ServerConfig, ServerConnection, SideData, tcpls};
use rustls::recvbuf::RecvBufMap;



#[derive(Clone, Copy, PartialEq)]
pub enum KeyType {
    Rsa,
    Ecdsa,
    Ed25519,
}

impl KeyType {
    fn path_for(&self, part: &str) -> String {
        match self {
            Self::Rsa => format!("../test-ca/rsa/{}", part),
            Self::Ecdsa => format!("../test-ca/ecdsa/{}", part),
            Self::Ed25519 => format!("../test-ca/eddsa/{}", part),
        }
    }

    fn get_chain(&self) -> Vec<rustls::Certificate> {
        rustls_pemfile::certs(&mut io::BufReader::new(
            fs::File::open(self.path_for("end.fullchain")).unwrap(),
        ))
            .unwrap()
            .iter()
            .map(|v| rustls::Certificate(v.clone()))
            .collect()
    }

    fn get_key(&self) -> rustls::PrivateKey {
        rustls::PrivateKey(
            rustls_pemfile::pkcs8_private_keys(&mut io::BufReader::new(
                fs::File::open(self.path_for("end.key")).unwrap(),
            ))
                .unwrap()[0]
                .clone(),
        )
    }

    fn get_client_chain(&self) -> Vec<rustls::Certificate> {
        rustls_pemfile::certs(&mut io::BufReader::new(
            fs::File::open(self.path_for("client.fullchain")).unwrap(),
        ))
            .unwrap()
            .iter()
            .map(|v| rustls::Certificate(v.clone()))
            .collect()
    }

    fn get_client_key(&self) -> rustls::PrivateKey {
        rustls::PrivateKey(
            rustls_pemfile::pkcs8_private_keys(&mut io::BufReader::new(
                fs::File::open(self.path_for("client.key")).unwrap(),
            ))
                .unwrap()[0]
                .clone(),
        )
    }
}
pub fn dns_name(name: &'static str) -> rustls::ServerName {
    name.try_into().unwrap()
}

pub fn make_pair(kt: KeyType) -> (ClientConnection, ServerConnection, RecvBufMap, RecvBufMap) {
    make_pair_for_configs(make_client_config(kt), make_server_config(kt))
}
pub fn make_pair_for_configs(
    client_config: ClientConfig,
    server_config: ServerConfig,
) -> (ClientConnection, ServerConnection, RecvBufMap, RecvBufMap) {
    make_pair_for_arc_configs(&Arc::new(client_config), &Arc::new(server_config))
}

pub fn make_pair_for_arc_configs(
    client_config: &Arc<ClientConfig>,
    server_config: &Arc<ServerConfig>,
) -> (ClientConnection, ServerConnection, RecvBufMap, RecvBufMap) {
    (
        ClientConnection::new(Arc::clone(client_config), dns_name("localhost")).unwrap(),
        ServerConnection::new(Arc::clone(server_config)).unwrap(),
        RecvBufMap::new(),
        RecvBufMap::new(),
    )
}
fn make_server_config(
   key_type: KeyType,
) -> ServerConfig {
    let client_auth = NoClientAuth::boxed();

    let mut cfg = ServerConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(client_auth)
        .with_single_cert(key_type.get_chain(), key_type.get_key())
        .expect("bad certs/private key?");

    cfg.session_storage = Arc::new(NoServerSessionStorage {});

    cfg.max_fragment_size = None;
    cfg
}

fn make_client_config(
   key_type: KeyType,
) -> ClientConfig {
    let mut root_store = RootCertStore::empty();
    let mut rootbuf =
        io::BufReader::new(fs::File::open(key_type.path_for("ca.cert")).unwrap());
    root_store.add_parsable_certificates(&rustls_pemfile::certs(&mut rootbuf).unwrap());

    let cfg = ClientConfig::builder()
        .with_cipher_suites(DEFAULT_CIPHER_SUITES)
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(root_store);

    let mut cfg = cfg.with_no_client_auth();

    cfg.resumption = Resumption::disabled();


    cfg
}

pub fn do_handshake(
    client: &mut (impl DerefMut + Deref<Target = ConnectionCommon<impl SideData>>),
    server: &mut (impl DerefMut + Deref<Target = ConnectionCommon<impl SideData>>),
    serv: &mut RecvBufMap,
    clnt: &mut RecvBufMap,
) -> (usize, usize) {
    let (mut to_client, mut to_server) = (0, 0);
    while server.is_handshaking() || client.is_handshaking() {
        to_server += transfer(client, server, 0);
        server.process_new_packets(serv).unwrap();
        to_client += transfer(server, client, 0);
        client.process_new_packets(clnt).unwrap();
    }
    (to_server, to_client)
}

pub fn transfer(
    left: &mut (impl DerefMut + Deref<Target = ConnectionCommon<impl SideData>>),
    right: &mut (impl DerefMut + Deref<Target = ConnectionCommon<impl SideData>>),
    id: u16,
) -> usize {
    let mut buf = vec![0u8; 2 * 1024 * 1024];
    let mut total = 0;

    while left.wants_write() {
        let sz = {
            let into_buf: &mut dyn io::Write = &mut &mut buf[..];
            left.write_tls(into_buf, id).unwrap()
        };
        total += sz;
        if sz == 0 {
            return total;
        }

        let mut offs = 0;
        loop {
            let from_buf: &mut dyn io::Read = &mut &buf[offs..sz];
            offs += right.read_tls(from_buf).unwrap();
            if sz == offs {
                break;
            }
        }
    }

    total
}


struct OtherSession<C, S>
    where
        C: DerefMut + Deref<Target = ConnectionCommon<S>>,
        S: SideData,
{
    sess: C,
    pub reads: usize,
    pub writevs: Vec<Vec<usize>>,
    fail_ok: bool,
    pub short_writes: bool,
    pub last_error: Option<rustls::Error>,
    pub recv_map: RecvBufMap,
}

impl<C, S> OtherSession<C, S>
    where
        C: DerefMut + Deref<Target = ConnectionCommon<S>>,
        S: SideData,
{
    fn new(sess: C) -> OtherSession<C, S> {
        OtherSession {
            sess,
            reads: 0,
            writevs: vec![],
            fail_ok: false,
            short_writes: false,
            last_error: None,
            recv_map: RecvBufMap::new(),
        }
    }

    fn new_fails(sess: C) -> OtherSession<C, S> {
        let mut os = OtherSession::new(sess);
        os.fail_ok = true;
        os
    }
}

impl<C, S> io::Read for OtherSession<C, S>
    where
        C: DerefMut + Deref<Target = ConnectionCommon<S>>,
        S: SideData,
{
    fn read(&mut self, mut b: &mut [u8]) -> io::Result<usize> {
        self.reads += 1;
        self.sess.write_tls(b.by_ref(), 0)
    }
}

impl<C, S> io::Write for OtherSession<C, S>
    where
        C: DerefMut + Deref<Target = ConnectionCommon<S>>,
        S: SideData,
{
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let mut buf = input.clone();
        self.sess.read_tls(&mut buf)

    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn write_vectored<'b>(&mut self, b: &[io::IoSlice<'b>]) -> io::Result<usize> {
        let mut total = 0;
        let mut lengths = vec![];
        for bytes in b {
            let write_len = if self.short_writes {
                if bytes.len() > 5 {
                    bytes.len() / 2
                } else {
                    bytes.len()
                }
            } else {
                bytes.len()
            };

            let l = self
                .sess
                .read_tls(&mut io::Cursor::new(&bytes[..write_len]))?;
            lengths.push(l);
            total += l;
            if bytes.len() != l {
                break;
            }
        }

        self.writevs.push(lengths);
        Ok(total)
    }
}

use criterion::{criterion_group, criterion_main, Criterion, Throughput, BenchmarkId, BatchSize};
use pprof::criterion::{Output, PProfProfiler};
use rustls::client::Resumption;
use rustls::server::{NoClientAuth, NoServerSessionStorage};
use rustls::tcpls::stream::SimpleIdHashSet;
use rustls::tcpls::TcplsSession;

fn criterion_benchmark(c: &mut Criterion) {
    let sendbuf = vec![1u8; 10 * 1024 * 1024];
    let mut group = c.benchmark_group("Data_recv");
    group.throughput(Throughput::Bytes(10 * 1024 * 1024));
    group.bench_with_input(BenchmarkId::new("Data_recv_single_stream_single_connection", "10 MB"), &sendbuf,
                           |b, sendbuf| {

                               b.iter_batched_ref(|| {
                                   // Finish handshake
                                   let (mut client, mut server, mut recv_svr, mut recv_clnt) =
                                       make_pair(KeyType::Rsa);
                                   do_handshake(&mut client, &mut server, &mut recv_svr, &mut recv_clnt);
                                   let mut tcpls_client = TcplsSession::new(false);
                                   let _ = tcpls_client.tls_conn.insert(Connection::from(client));
                                   tcpls_client.tls_conn.as_mut().unwrap().set_buffer_limit(None, 1);
                                   //Encrypt data and buffer it in send buffer
                                   tcpls_client.stream_send(1, sendbuf.as_slice(), false).expect("Buffering in send buffer failed");

                                   let mut stream_to_flush = SimpleIdHashSet::default();
                                   stream_to_flush.insert(1);
                                   // Create app receive buffer
                                   recv_svr.get_or_create_recv_buffer(1, Some(11 * 1024 * 1024));
                                   let mut pipe = OtherSession::new(server);
                                   let mut sent = 0;
                                   while sent < sendbuf.len() {
                                       sent += tcpls_client.send_on_connection(None, Some(&mut pipe), Some(stream_to_flush.clone())).unwrap();
                                   }
                                   (pipe, recv_svr)
                               },

                                                  |(ref mut pipe, recv_svr)| pipe.sess.process_new_packets(recv_svr).unwrap(),
                                                  BatchSize::SmallInput)
                           });
    group.finish();
}


criterion_group!{
    name = benches;
    config = Criterion::default()
        .with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)))
        .measurement_time(std::time::Duration::from_secs(15))
        .sample_size(9000);
    targets = criterion_benchmark
}
criterion_main!(benches);