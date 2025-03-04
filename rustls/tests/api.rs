
#![cfg_attr(read_buf, feature(read_buf))]
#![cfg_attr(read_buf, feature(core_io_borrowed_buf))]

//! Assorted public API tests.

use std::cell::RefCell;

#[macro_use]
mod macros;



use std::fmt;
use std::fmt::Debug;
use std::io::{self, IoSlice, Read, Write};
use std::mem;
use std::ops::{Deref, DerefMut};
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use pki_types::{CertificateDer, IpAddr, ServerName, UnixTime};
use rustls::client::{verify_server_cert_signed_by_trust_anchor, ResolvesClientCert, Resumption};
use rustls::crypto::{ring as provider, CryptoProvider};
use rustls::internal::msgs::base::Payload;
use rustls::internal::msgs::codec::Codec;
use rustls::internal::msgs::enums::AlertLevel;
use rustls::internal::msgs::handshake::{ClientExtension, HandshakePayload, TcplsToken};
use rustls::internal::msgs::message::{
    Message, MessagePayload,
};
use rustls::server::{ClientHello, ParsedCertificate, ResolvesServerCert};
use rustls::{Connection, SupportedCipherSuite};
use rustls::{
    sign, AlertDescription, CertificateError, ConnectionCommon, ContentType, Error,
    KeyLog, PeerIncompatible, PeerMisbehaved, SideData,
};
use rustls::{CipherSuite, ProtocolVersion, SignatureScheme};
use rustls::{ClientConfig, ClientConnection};
use rustls::DistinguishedName;
use rustls::{ServerConfig, ServerConnection};
use rustls::{Stream, StreamOwned};

use rustls::version::TLS13;

mod common;
use common::*;

use provider::cipher_suite;
use provider::sign::RsaSigningKey;
use rustls::crypto::cipher::{OutboundChunks, OutboundPlainMessage};

use rustls::recvbuf::RecvBufMap;
use rustls::tcpls::frame::{Frame, MAX_TCPLS_FRAGMENT_LEN};


fn alpn_test_error(
    server_protos: Vec<Vec<u8>>,
    client_protos: Vec<Vec<u8>>,
    agreed: Option<&[u8]>,
    expected_error: Option<ErrorFromPeer>,
) {
    let mut server_config = make_server_config(KeyType::Rsa);
    server_config.alpn_protocols = server_protos;

    let server_config = Arc::new(server_config);

    for version in rustls::ALL_VERSIONS {
             if version.version == ProtocolVersion::TLSv1_2 {
                continue
            }

        let mut client_config = make_client_config_with_versions(KeyType::Rsa, &[version]);
        client_config.alpn_protocols = client_protos.clone();

        let (mut client, mut server,  mut recv_svr, mut recv_clnt) =
            make_pair_for_arc_configs(&Arc::new(client_config), &server_config);

        assert_eq!(client.alpn_protocol(), None);
        assert_eq!(server.alpn_protocol(), None);
        let error = do_handshake_until_error(&mut client, &mut server, &mut recv_svr, &mut recv_clnt);
        assert_eq!(client.alpn_protocol(), agreed);
        assert_eq!(server.alpn_protocol(), agreed);
        assert_eq!(error.err(), expected_error);
    }
}

fn alpn_test(server_protos: Vec<Vec<u8>>, client_protos: Vec<Vec<u8>>, agreed: Option<&[u8]>) {
    alpn_test_error(server_protos, client_protos, agreed, None)
}

#[test]
fn alpn() {
    // no support
    alpn_test(vec![], vec![], None);

    // server support
    alpn_test(vec![b"server-proto".to_vec()], vec![], None);

    // client support
    alpn_test(vec![], vec![b"client-proto".to_vec()], None);

    // no overlap
    alpn_test_error(
        vec![b"server-proto".to_vec()],
        vec![b"client-proto".to_vec()],
        None,
        Some(ErrorFromPeer::Server(Error::NoApplicationProtocol)),
    );

    // server chooses preference
    alpn_test(
        vec![b"server-proto".to_vec(), b"client-proto".to_vec()],
        vec![b"client-proto".to_vec(), b"server-proto".to_vec()],
        Some(b"server-proto"),
    );

    // case sensitive
    alpn_test_error(
        vec![b"PROTO".to_vec()],
        vec![b"proto".to_vec()],
        None,
        Some(ErrorFromPeer::Server(Error::NoApplicationProtocol)),
    );
}

fn version_test(
    client_versions: &[&'static rustls::SupportedProtocolVersion],
    server_versions: &[&'static rustls::SupportedProtocolVersion],
    result: Option<ProtocolVersion>,
) {
    let client_versions = if client_versions.is_empty() {
        rustls::ALL_VERSIONS
    } else {
        client_versions
    };
    let server_versions = if server_versions.is_empty() {
        rustls::ALL_VERSIONS
    } else {
        server_versions
    };

    let client_config = make_client_config_with_versions(KeyType::Rsa, client_versions);
    let server_config = make_server_config_with_versions(KeyType::Rsa, server_versions);

    println!(
        "version {:?} {:?} -> {:?}",
        client_versions, server_versions, result
    );


    let (mut client, mut server, mut recv_srv, mut recv_clnt) = make_pair_for_configs(client_config, server_config);

    assert_eq!(client.protocol_version(), None);
    assert_eq!(server.protocol_version(), None);
    if result.is_none() {

        let err = do_handshake_until_error(&mut client, &mut server,  &mut recv_srv, &mut recv_clnt);
        assert!(err.is_err());
    } else {
        do_handshake(&mut client, &mut server, &mut recv_srv, &mut recv_clnt);
        assert_eq!(client.protocol_version(), result);
        assert_eq!(server.protocol_version(), result);
    }
}

#[test]
fn versions() {
    // default -> 1.3
    version_test(&[], &[], Some(ProtocolVersion::TLSv1_3));
}

/*fn check_read(reader: &mut dyn io::Read, bytes: &[u8]) {
    let mut buf = vec![0u8; bytes.len() + 1];
    assert_eq!(bytes.len(), reader.read(&mut buf).unwrap());
    assert_eq!(bytes, &buf[..bytes.len()]);
}*/
/*fn check_read_app_buff(reader: &mut  ReaderAppBufs, bytes: &[u8], app_recv: &mut RecvBufMap, id: u16){
    let mut buf = vec![0u8; bytes.len() + 1];
    assert_eq!(bytes.len(), reader.read_app_bufs(&mut buf, app_recv, id).unwrap());
    assert_eq!(bytes, &buf[..bytes.len()]);
}*/


/*fn check_read_err(reader: &mut dyn io::Read, err_kind: io::ErrorKind) {
    let mut buf = vec![0u8; 1];
    let err = reader.read(&mut buf).unwrap_err();
    assert!(matches!(err, err  if err.kind()  == err_kind))
}*/

#[cfg(read_buf)]
fn check_read_buf(reader: &mut dyn io::Read, bytes: &[u8]) {
    use core::io::BorrowedBuf;
    use std::mem::MaybeUninit;

    let mut buf = [MaybeUninit::<u8>::uninit(); 128];
    let mut buf: BorrowedBuf<'_> = buf.as_mut_slice().into();
    reader.read_buf(buf.unfilled()).unwrap();
    assert_eq!(buf.filled(), bytes);
}

#[cfg(read_buf)]
fn check_read_buf_err(reader: &mut dyn io::Read, err_kind: io::ErrorKind) {
    use core::io::BorrowedBuf;
    use std::mem::MaybeUninit;

    let mut buf = [MaybeUninit::<u8>::uninit(); 1];
    let mut buf: BorrowedBuf<'_> = buf.as_mut_slice().into();
    let err = reader
        .read_buf(buf.unfilled())
        .unwrap_err();
    assert!(matches!(err, err  if err.kind()  == err_kind))
}

#[test]
fn config_builder_for_client_rejects_empty_kx_groups() {
    assert_eq!(

        ClientConfig::builder_with_provider(
            CryptoProvider {
                kx_groups: Vec::default(),
                ..provider::default_provider()
            }
            .into()
        )
        .with_safe_default_protocol_versions()
        .err(),
        Some(Error::General("no kx groups configured".into()))
    );
}

#[test]
fn config_builder_for_client_rejects_empty_cipher_suites() {
    assert_eq!(

        ClientConfig::builder_with_provider(
            CryptoProvider {
                cipher_suites: Vec::default(),
                ..provider::default_provider()
            }
            .into()
        )
        .with_safe_default_protocol_versions()
        .err(),
        Some(Error::General("no usable cipher suites configured".into()))
    );
}



#[test]
fn config_builder_for_server_rejects_empty_kx_groups() {
    assert_eq!(

        ServerConfig::builder_with_provider(
            CryptoProvider {
                kx_groups: Vec::default(),
                ..provider::default_provider()
            }
            .into()
        )
        .with_safe_default_protocol_versions()
        .err(),
        Some(Error::General("no kx groups configured".into()))
    );
}

#[test]
fn config_builder_for_server_rejects_empty_cipher_suites() {
    assert_eq!(

        ServerConfig::builder_with_provider(
            CryptoProvider {
                cipher_suites: Vec::default(),
                ..provider::default_provider()
            }
            .into()
        )
        .with_safe_default_protocol_versions()
        .err(),
        Some(Error::General("no usable cipher suites configured".into()))
    );
}



#[test]
fn config_builder_for_client_with_time() {
    ClientConfig::builder_with_details(
        provider::default_provider().into(),
        Arc::new(rustls::time_provider::DefaultTimeProvider),
    )
    .with_safe_default_protocol_versions()
    .unwrap();
}

#[test]
fn config_builder_for_server_with_time() {
    ServerConfig::builder_with_details(
        provider::default_provider().into(),
        Arc::new(rustls::time_provider::DefaultTimeProvider),
    )
    .with_safe_default_protocol_versions()
    .unwrap();
}







#[test]
fn client_can_get_server_cert() {

    for kt in ALL_KEY_TYPES {
        for version in rustls::ALL_VERSIONS {
                 if version.version == ProtocolVersion::TLSv1_2 {
                continue
            }
            let client_config = make_client_config_with_versions(*kt, &[version]);
            let (mut client, mut server,  mut recv_srv, mut recv_clnt) =
                make_pair_for_configs(client_config, make_server_config(*kt));
            do_handshake(&mut client, &mut server,  &mut recv_srv, &mut recv_clnt);

            let certs = client.peer_certificates();
            assert_eq!(certs, Some(kt.get_chain().as_slice()));
        }
    }
}

#[test]
fn client_can_get_server_cert_after_resumption() {

    for kt in ALL_KEY_TYPES {
        let server_config = make_server_config(*kt);
        for version in rustls::ALL_VERSIONS {
                 if version.version == ProtocolVersion::TLSv1_2 {
                continue
            }
            let client_config = make_client_config_with_versions(*kt, &[version]);
            let (mut client, mut server, mut recv_srv, mut recv_clnt) =
                make_pair_for_configs(client_config.clone(), server_config.clone());
            do_handshake(&mut client, &mut server,  &mut recv_srv, &mut recv_clnt);

            let original_certs = client.peer_certificates();

            let (mut client, mut server, mut recv_srv, mut recv_clnt) =
                make_pair_for_configs(client_config.clone(), server_config.clone());
            do_handshake(&mut client, &mut server,  &mut recv_srv, &mut recv_clnt);

            let resumed_certs = client.peer_certificates();

            assert_eq!(original_certs, resumed_certs);
        }
    }
}

#[test]
fn server_can_get_client_cert() {

    for kt in ALL_KEY_TYPES {
        let server_config = Arc::new(make_server_config_with_mandatory_client_auth(*kt));

        for version in rustls::ALL_VERSIONS {
                 if version.version == ProtocolVersion::TLSv1_2 {
                continue
            }
            let client_config = make_client_config_with_versions_with_auth(*kt, &[version]);
            let (mut client, mut server, mut recv_srv, mut recv_clnt) =
                make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
            do_handshake(&mut client, &mut server,  &mut recv_srv, &mut recv_clnt);

            let certs = server.peer_certificates();
            assert_eq!(certs, Some(kt.get_client_chain().as_slice()));
        }
    }
}

#[test]
fn server_can_get_client_cert_after_resumption() {

    for kt in ALL_KEY_TYPES {
        let server_config = Arc::new(make_server_config_with_mandatory_client_auth(*kt));

        for version in rustls::ALL_VERSIONS {
                 if version.version == ProtocolVersion::TLSv1_2 {
                continue
            }
            let client_config = make_client_config_with_versions_with_auth(*kt, &[version]);
            let client_config = Arc::new(client_config);
            let (mut client, mut server, mut recv_srv, mut recv_clnt) =
                make_pair_for_arc_configs(&client_config, &server_config);
            do_handshake(&mut client, &mut server,  &mut recv_srv, &mut recv_clnt);
            let original_certs = server.peer_certificates();

            let (mut client, mut server, mut recv_srv, mut recv_clnt) =
                make_pair_for_arc_configs(&client_config, &server_config);
            do_handshake(&mut client, &mut server,  &mut recv_srv, &mut recv_clnt);
            let resumed_certs = server.peer_certificates();
            assert_eq!(original_certs, resumed_certs);
        }
    }
}



/// Test that the server handles combination of `offer_client_auth()` returning true
/// and `client_auth_mandatory` returning `Some(false)`. This exercises both the
/// client's and server's ability to "recover" from the server asking for a client

/// certificate and not being given one.
#[test]
fn server_allow_any_anonymous_or_authenticated_client() {
    let kt = KeyType::Rsa;
    for client_cert_chain in [None, Some(kt.get_client_chain())] {
        let client_auth_roots = get_client_root_store(kt);
        let client_auth = webpki_client_verifier_builder(client_auth_roots.clone())
            .allow_unauthenticated()
            .build()
            .unwrap();

        let server_config = server_config_builder()
            .with_client_cert_verifier(client_auth)
            .with_single_cert(kt.get_chain(), kt.get_key())
            .unwrap();
        let server_config = Arc::new(server_config);

        for version in rustls::ALL_VERSIONS {
                 if version.version == ProtocolVersion::TLSv1_2 {
                continue
            }

            let client_config = if client_cert_chain.is_some() {
                make_client_config_with_versions_with_auth(kt, &[version])
            } else {
                make_client_config_with_versions(kt, &[version])
            };

            let (mut client, mut server, mut recv_srv, mut recv_clnt) =
                make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
            do_handshake(&mut client, &mut server, &mut recv_srv, &mut recv_clnt);

            let certs = server.peer_certificates();
            assert_eq!(certs, client_cert_chain.as_deref());
        }
    }
}


/*fn check_read_and_close(reader: &mut ReaderAppBufs, app_bufs: &mut RecvBufMap, expect: &[u8], id: u16) {
    check_read_app_buff(reader, expect, app_bufs, id);
    assert!(matches!(app_bufs.get_mut(id as u32).unwrap().read(&mut [0u8; 5]), Ok(0)));
}*/









#[test]
fn test_tls13_valid_early_plaintext_alert() {
    let (mut client, mut server, mut recv_svr, _recv_clnt) = make_pair(KeyType::Rsa);

    // Perform the start of a TLS 1.3 handshake, sending a client hello to the server.
    // The client will not have written a CCS or any encrypted messages to the server yet.
    transfer(&mut client, &mut server, None);
    server.process_new_packets(&mut recv_svr).unwrap();

    // Inject a plaintext alert from the client. The server should accept this since:
    //  * It hasn't decrypted any messages from the peer yet.
    //  * The message content type is Alert.
    //  * The payload size is indicative of a plaintext alert message.
    //  * The negotiated protocol version is TLS 1.3.
    server
        .read_tls(&mut io::Cursor::new(
            &build_alert(AlertLevel::Fatal, AlertDescription::UnknownCA, &[])
        ))
        .unwrap();

    // The server should process the plaintext alert without error.
    assert_eq!(
        server.process_new_packets(&mut recv_svr),
        Err(Error::AlertReceived(AlertDescription::UnknownCA)),
    );
}

#[test]
fn test_tls13_too_short_early_plaintext_alert() {
    let (mut client, mut server, mut recv_svr, _recv_clnt) = make_pair(KeyType::Rsa);

    // Perform the start of a TLS 1.3 handshake, sending a client hello to the server.
    // The client will not have written a CCS or any encrypted messages to the server yet.
    transfer(&mut client, &mut server, None);
    server.process_new_packets(&mut recv_svr).unwrap();

    // Inject a plaintext alert from the client. The server should attempt to decrypt this message
    // because the payload length is too large to be considered an early plaintext alert.
    server
        .read_tls(&mut io::Cursor::new(&build_alert(AlertLevel::Fatal, AlertDescription::UnknownCA, &[0xff])))
        .unwrap();

    // The server should produce a decrypt error trying to decrypt the plaintext alert.
    assert_eq!(server.process_new_packets(&mut recv_svr), Err(Error::DecryptError),);
}

#[test]
fn test_tls13_late_plaintext_alert() {
    let (mut client, mut server, mut recv_svr, mut recv_clnt) = make_pair(KeyType::Rsa);

    // Complete a bi-directional TLS1.3 handshake. After this point no plaintext messages
    // should occur.
    do_handshake(&mut client, &mut server, &mut recv_svr, &mut recv_clnt);

    // Inject a plaintext alert from the client. The server should attempt to decrypt this message.
    server
        .read_tls(&mut io::Cursor::new(&build_alert(AlertLevel::Fatal, AlertDescription::UnknownCA, &[])))
        .unwrap();

    // The server should produce a decrypt error, trying to decrypt a plaintext alert.
    assert_eq!(server.process_new_packets(&mut recv_svr), Err(Error::DecryptError));
}

fn build_alert(level: AlertLevel, desc: AlertDescription, suffix: &[u8]) -> Vec<u8> {
    let mut v = vec![ContentType::Alert.into()];
    ProtocolVersion::TLSv1_2.encode(&mut v);
    ((2 + suffix.len()) as u16).encode(&mut v);
    level.encode(&mut v);
    desc.encode(&mut v);
    v.extend_from_slice(suffix);
    v
}

#[derive(Default, Debug)]
struct ServerCheckCertResolve {
    expected_sni: Option<String>,
    expected_sigalgs: Option<Vec<SignatureScheme>>,
    expected_alpn: Option<Vec<Vec<u8>>>,
    expected_cipher_suites: Option<Vec<CipherSuite>>,
}

impl ResolvesServerCert for ServerCheckCertResolve {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<sign::CertifiedKey>> {
        if client_hello
            .signature_schemes()
            .is_empty()
        {
            panic!("no signature schemes shared by client");
        }

        if client_hello.cipher_suites().is_empty() {
            panic!("no cipher suites shared by client");
        }

        if let Some(expected_sni) = &self.expected_sni {
            let sni: &str = client_hello
                .server_name()
                .expect("sni unexpectedly absent");
            assert_eq!(expected_sni, sni);
        }

        if let Some(expected_sigalgs) = &self.expected_sigalgs {
            assert_eq!(
                expected_sigalgs,
                client_hello.signature_schemes(),
                "unexpected signature schemes"
            );
        }

        if let Some(expected_alpn) = &self.expected_alpn {
            let alpn = client_hello
                .alpn()
                .expect("alpn unexpectedly absent")
                .collect::<Vec<_>>();
            assert_eq!(alpn.len(), expected_alpn.len());

            for (got, wanted) in alpn.iter().zip(expected_alpn.iter()) {
                assert_eq!(got, &wanted.as_slice());
            }
        }

        if let Some(expected_cipher_suites) = &self.expected_cipher_suites {
            assert_eq!(
                expected_cipher_suites,
                client_hello.cipher_suites(),
                "unexpected cipher suites"
            );
        }

        None
    }
}

#[test]
fn server_cert_resolve_with_sni() {

    for kt in ALL_KEY_TYPES {
            let mut recv_svr = RecvBufMap::new();
        let mut recv_clnt = RecvBufMap::new();
        let client_config = make_client_config(*kt);
        let mut server_config = make_server_config(*kt);

        server_config.cert_resolver = Arc::new(ServerCheckCertResolve {
            expected_sni: Some("the-value-from-sni".into()),
            ..Default::default()
        });

        let mut client =

            ClientConnection::new(Arc::new(client_config), server_name("the-value-from-sni"))
                .unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

        let err = do_handshake_until_error(&mut client, &mut server, &mut recv_svr, &mut recv_clnt);
        assert!(err.is_err());
    }
}

#[test]
fn server_cert_resolve_with_alpn() {

    for kt in ALL_KEY_TYPES {
             let mut recv_svr = RecvBufMap::new();
        let mut recv_clnt = RecvBufMap::new();
        let mut client_config = make_client_config(*kt);
        client_config.alpn_protocols = vec!["foo".into(), "bar".into()];

        let mut server_config = make_server_config(*kt);
        server_config.cert_resolver = Arc::new(ServerCheckCertResolve {
            expected_alpn: Some(vec![b"foo".to_vec(), b"bar".to_vec()]),
            ..Default::default()
        });

        let mut client =
            ClientConnection::new(Arc::new(client_config), server_name("sni-value")).unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

        let err = do_handshake_until_error(&mut client, &mut server, &mut recv_svr, &mut recv_clnt);
        assert!(err.is_err());
    }
}

#[test]
fn client_trims_terminating_dot() {

    for kt in ALL_KEY_TYPES {
             let mut recv_svr = RecvBufMap::new();
        let mut recv_clnt = RecvBufMap::new();
        let client_config = make_client_config(*kt);
        let mut server_config = make_server_config(*kt);

        server_config.cert_resolver = Arc::new(ServerCheckCertResolve {
            expected_sni: Some("some-host.com".into()),
            ..Default::default()
        });

        let mut client =

            ClientConnection::new(Arc::new(client_config), server_name("some-host.com.")).unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

        let err = do_handshake_until_error(&mut client, &mut server, &mut recv_svr, &mut recv_clnt);
        assert!(err.is_err());
    }
}







#[derive(Debug)]
struct ServerCheckNoSni {}

impl ResolvesServerCert for ServerCheckNoSni {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<sign::CertifiedKey>> {
        assert!(client_hello.server_name().is_none());

        None
    }
}

#[test]
fn client_with_sni_disabled_does_not_send_sni() {

    for kt in ALL_KEY_TYPES {
        let mut server_config = make_server_config(*kt);
        server_config.cert_resolver = Arc::new(ServerCheckNoSni {});
        let server_config = Arc::new(server_config);

        for version in rustls::ALL_VERSIONS {
                 if version.version == ProtocolVersion::TLSv1_2 {
                continue
            }
                let mut recv_svr = RecvBufMap::new();
            let mut recv_clnt = RecvBufMap::new();
            let mut client_config = make_client_config_with_versions(*kt, &[version]);
            client_config.enable_sni = false;

            let mut client =

                ClientConnection::new(Arc::new(client_config), server_name("value-not-sent"))
                    .unwrap();
            let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();

            let err = do_handshake_until_error(&mut client, &mut server, &mut recv_svr, &mut recv_clnt);
            assert!(err.is_err());
        }
    }
}

#[test]
fn client_checks_server_certificate_with_given_name() {

    for kt in ALL_KEY_TYPES {
        let server_config = Arc::new(make_server_config(*kt));

        for version in rustls::ALL_VERSIONS {
                 if version.version == ProtocolVersion::TLSv1_2 {
                continue
            }
                let mut recv_svr = RecvBufMap::new();
            let mut recv_clnt = RecvBufMap::new();
            let client_config = make_client_config_with_versions(*kt, &[version]);
            let mut client = ClientConnection::new(
                Arc::new(client_config),
                server_name("not-the-right-hostname.com"),
            )
            .unwrap();
            let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();

            let err = do_handshake_until_error(&mut client, &mut server, &mut recv_svr, &mut recv_clnt);
            assert_eq!(
                err,
                Err(ErrorFromPeer::Client(Error::InvalidCertificate(
                    CertificateError::NotValidForName
                )))
            );
        }
    }
}


#[test]
fn client_checks_server_certificate_with_given_ip_address() {
    fn check_server_name(
        client_config: Arc<ClientConfig>,
        server_config: Arc<ServerConfig>,
        name: &'static str,
    ) -> Result<(), ErrorFromPeer> {
        let mut client = ClientConnection::new(client_config, server_name(name)).unwrap();
        let mut server = ServerConnection::new(server_config).unwrap();
            let mut recv_svr = RecvBufMap::new();
            let mut recv_clnt = RecvBufMap::new();
        do_handshake_until_error(&mut client, &mut server, &mut recv_svr, &mut recv_clnt)
    }

    for kt in ALL_KEY_TYPES {
        let server_config = Arc::new(make_server_config(*kt));

        for version in rustls::ALL_VERSIONS {
                if version.version == ProtocolVersion::TLSv1_2 {
                    continue
                }
            let client_config = Arc::new(make_client_config_with_versions(*kt, &[version]));

            // positive ipv4 case
            assert_eq!(
                check_server_name(client_config.clone(), server_config.clone(), "198.51.100.1"),
                Ok(()),
            );

            // negative ipv4 case
            assert_eq!(
                check_server_name(client_config.clone(), server_config.clone(), "198.51.100.2"),
                Err(ErrorFromPeer::Client(Error::InvalidCertificate(
                    CertificateError::NotValidForName
                )))
            );

            // positive ipv6 case
            assert_eq!(
                check_server_name(client_config.clone(), server_config.clone(), "2001:db8::1"),
                Ok(()),
            );

            // negative ipv6 case
            assert_eq!(
                check_server_name(client_config.clone(), server_config.clone(), "2001:db8::2"),
                Err(ErrorFromPeer::Client(Error::InvalidCertificate(
                    CertificateError::NotValidForName
                )))
            );
        }
    }
}

#[test]
fn client_check_server_certificate_ee_revoked() {
    for kt in ALL_KEY_TYPES {
        let server_config = Arc::new(make_server_config(*kt));

        // Setup a server verifier that will check the EE certificate's revocation status.
        let crls = vec![kt.end_entity_crl()];
        let builder = webpki_server_verifier_builder(get_client_root_store(*kt))
            .with_crls(crls)
            .only_check_end_entity_revocation();

        for version in rustls::ALL_VERSIONS {
                 if version.version == ProtocolVersion::TLSv1_2 {
                continue
            }
                let mut recv_svr = RecvBufMap::new();
            let mut recv_clnt = RecvBufMap::new();
            let client_config = make_client_config_with_verifier(&[version], builder.clone());
            let mut client =
                ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();
            let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();

            // We expect the handshake to fail since the server's EE certificate is revoked.
            let err = do_handshake_until_error(&mut client, &mut server, &mut recv_svr, &mut recv_clnt);
            assert_eq!(
                err,
                Err(ErrorFromPeer::Client(Error::InvalidCertificate(
                    CertificateError::Revoked
                )))
            );
        }
    }
}

#[test]
fn client_check_server_certificate_ee_unknown_revocation() {
    for kt in ALL_KEY_TYPES {
        let server_config = Arc::new(make_server_config(*kt));

        // Setup a server verifier builder that will check the EE certificate's revocation status, but not
        // allow unknown revocation status (the default). We'll provide CRLs that are not relevant
        // to the EE cert to ensure its status is unknown.
        let unrelated_crls = vec![kt.intermediate_crl()];
        let forbid_unknown_verifier = webpki_server_verifier_builder(get_client_root_store(*kt))
            .with_crls(unrelated_crls.clone())
            .only_check_end_entity_revocation();

        // Also set up a verifier builder that will allow unknown revocation status.
        let allow_unknown_verifier = webpki_server_verifier_builder(get_client_root_store(*kt))
            .with_crls(unrelated_crls)
            .only_check_end_entity_revocation()
            .allow_unknown_revocation_status();

        for version in rustls::ALL_VERSIONS {
                 if version.version == ProtocolVersion::TLSv1_2 {
                continue
            }
            let mut recv_svr = RecvBufMap::new();
            let mut recv_clnt = RecvBufMap::new();
            let client_config =
                make_client_config_with_verifier(&[version], forbid_unknown_verifier.clone());
            let mut client =
                ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();
            let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();

            // We expect if we use the forbid_unknown_verifier that the handshake will fail since the
            // server's EE certificate's revocation status is unknown given the CRLs we've provided.
            let err = do_handshake_until_error(&mut client, &mut server, &mut recv_svr, &mut recv_clnt);
            assert!(matches!(
                err,
                Err(ErrorFromPeer::Client(Error::InvalidCertificate(
                    CertificateError::UnknownRevocationStatus
                )))
            ));
            let mut recv_svr = RecvBufMap::new();
            let mut recv_clnt = RecvBufMap::new();
            // We expect if we use the allow_unknown_verifier that the handshake will not fail.
            let client_config =
                make_client_config_with_verifier(&[version], allow_unknown_verifier.clone());
            let mut client =
                ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();
            let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();
            let res = do_handshake_until_error(&mut client, &mut server, &mut recv_svr, &mut recv_clnt);
            assert!(res.is_ok());
        }
    }
}

#[test]
fn client_check_server_certificate_intermediate_revoked() {
    for kt in ALL_KEY_TYPES {
        let server_config = Arc::new(make_server_config(*kt));

        // Setup a server verifier builder that will check the full chain revocation status against a CRL
        // that marks the intermediate certificate as revoked. We allow unknown revocation status
        // so the EE cert's unknown status doesn't cause an error.
        let crls = vec![kt.intermediate_crl()];
        let full_chain_verifier_builder =
            webpki_server_verifier_builder(get_client_root_store(*kt))
                .with_crls(crls.clone())
                .allow_unknown_revocation_status();

        // Also set up a verifier builder that will use the same CRL, but only check the EE certificate
        // revocation status.
        let ee_verifier_builder = webpki_server_verifier_builder(get_client_root_store(*kt))
            .with_crls(crls.clone())
            .only_check_end_entity_revocation()
            .allow_unknown_revocation_status();

        for version in rustls::ALL_VERSIONS {
                 if version.version == ProtocolVersion::TLSv1_2 {
                continue
            }
            let mut recv_svr = RecvBufMap::new();
            let mut recv_clnt = RecvBufMap::new();
            let client_config =
                make_client_config_with_verifier(&[version], full_chain_verifier_builder.clone());
            let mut client =
                ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();
            let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();

            // We expect the handshake to fail when using the full chain verifier since the intermediate's
            // EE certificate is revoked.
            let err = do_handshake_until_error(&mut client, &mut server, &mut recv_svr, &mut recv_clnt);
            assert_eq!(
                err,
                Err(ErrorFromPeer::Client(Error::InvalidCertificate(
                    CertificateError::Revoked
                )))
            );
            let mut recv_svr = RecvBufMap::new();
            let mut recv_clnt = RecvBufMap::new();

            let client_config =
                make_client_config_with_verifier(&[version], ee_verifier_builder.clone());
            let mut client =
                ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();
            let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();
            // We expect the handshake to succeed when we use the verifier that only checks the EE certificate
            // revocation status. The revoked intermediate status should not be checked.
            let res = do_handshake_until_error(&mut client, &mut server, &mut recv_svr, &mut recv_clnt);
            assert!(res.is_ok())
        }
    }
}

/// Simple smoke-test of the webpki verify_server_cert_signed_by_trust_anchor helper API.
/// This public API is intended to be used by consumers implementing their own verifier and
/// so isn't used by the other existing verifier tests.
#[test]
fn client_check_server_certificate_helper_api() {
    for kt in ALL_KEY_TYPES {
        let chain = kt.get_chain();
        let correct_roots = get_client_root_store(*kt);
        let incorrect_roots = get_client_root_store(match kt {
            KeyType::Rsa => KeyType::EcdsaP256,
            _ => KeyType::Rsa,
        });
        // Using the correct trust anchors, we should verify without error.
        assert!(verify_server_cert_signed_by_trust_anchor(
            &ParsedCertificate::try_from(chain.first().unwrap()).unwrap(),
            &correct_roots,
            &[chain.get(1).unwrap().clone()],
            UnixTime::now(),
            webpki::ALL_VERIFICATION_ALGS,
        )
        .is_ok());
        // Using the wrong trust anchors, we should get the expected error.
        assert_eq!(
            verify_server_cert_signed_by_trust_anchor(
                &ParsedCertificate::try_from(chain.first().unwrap()).unwrap(),
                &incorrect_roots,
                &[chain.get(1).unwrap().clone()],
                UnixTime::now(),
                webpki::ALL_VERIFICATION_ALGS,
            )
            .unwrap_err(),
            Error::InvalidCertificate(CertificateError::UnknownIssuer)
        );
    }
}

#[test]
fn test_server_rejects_non_empty_tcpls_tokens_extension() {
    fn non_empty_tcpls_tokens(msg: &mut Message) -> Altered {
        if let MessagePayload::Handshake { parsed, encoded } = &mut msg.payload {
            if let HandshakePayload::ClientHello(ch) = &mut parsed.payload {
                for mut ext in ch.extensions.iter_mut() {
                    if let ClientExtension::TcplsTokens(tokens) = &mut ext {
                        for _i in 1..=5 {
                            tokens.push(TcplsToken::new([5u8;32]));
                        }
                    }

                }
            }

            *encoded = Payload::new(parsed.get_encoding());
        }
        Altered::InPlace
    }
    let server_config = Arc::new(make_server_config(KeyType::Rsa));
    let mut client_config = make_client_config_with_versions(KeyType::Rsa, &[&rustls::version::TLS13]);
    client_config.enable_tcpls = true;
    let (mut client, mut server, mut recv_svr, mut recv_clnt) =
        make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
    let (mut conn_client, mut conn_server) = (Connection::Client(client), Connection::Server(server));
    transfer_altered(&mut conn_client, non_empty_tcpls_tokens, &mut conn_server);
    client = match conn_client {
        Connection::Client(conn) => conn,
        Connection::Server(_conn) => panic!("Wrong connection type")
    };
    server = match conn_server {
        Connection::Server(conn) => conn,
        Connection::Client(_conn) => panic!("Wrong connection type"),
    };
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        do_handshake(&mut client, &mut server, &mut recv_svr, &mut recv_clnt);
    }));
    assert!(result.is_err());
}

#[test]
fn receive_tcpls_tokens_from_server() {
    let mut server_config = make_server_config(KeyType::Rsa);
    server_config.max_tcpls_tokens_cap = 5;
    let mut client_config = make_client_config_with_versions(KeyType::Rsa, &[&rustls::version::TLS13]);
    client_config.enable_tcpls = true;
    let (mut client, mut server, mut recv_svr, mut recv_clnt) =
        make_pair_for_arc_configs(&Arc::new(client_config), &Arc::new(server_config));
    do_handshake(&mut client, &mut server, &mut recv_svr, &mut recv_clnt);
    let client_tokens = match client.tcpls_tokens() {
        Some(tokens) => tokens,
        None => panic!("cannot continue test. No tokens found")
    };
    let server_tokens = match server.tcpls_tokens() {
        Some(tokens) => tokens,
        None => panic!("cannot continue test. No tokens found")
    };
    for i in 0..server_tokens.len() {
        assert_eq!(client_tokens.get(i), server_tokens.get(i));
    }

}

#[test]
fn clients_rejects_empty_tcpls_tokens_extension_from_server() {
    let mut server_config = make_server_config(KeyType::Rsa);
    let mut client_config = make_client_config_with_versions(KeyType::Rsa, &[&TLS13]);
    client_config.enable_tcpls = true;
    server_config.max_tcpls_tokens_cap = 0;
    let (mut client, mut server, mut recv_svr, mut recv_clnt) =
        make_pair_for_arc_configs(&Arc::new(client_config), &Arc::new(server_config));

    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        do_handshake(&mut client, &mut server, &mut recv_svr, &mut recv_clnt);
    }));

    assert!(result.is_err())
}

#[test]
fn receive_same_number_of_tcpls_tokens_from_server() {
    // Generate 5 tokens on server side and receive 5 on client side
    let mut server_config = make_server_config(KeyType::Rsa);
    server_config.max_tcpls_tokens_cap = 5;
    let mut client_config = make_client_config_with_versions(KeyType::Rsa, &[&rustls::version::TLS13]);
    client_config.enable_tcpls = true;
    let (mut client, mut server, mut recv_svr, mut recv_clnt) =
        make_pair_for_arc_configs(&Arc::new(client_config), &Arc::new(server_config));
    do_handshake(&mut client, &mut server, &mut recv_svr, &mut recv_clnt);
    let client_tokens = match client.tcpls_tokens() {
        Some(tokens) => tokens,
        None => panic!("cannot continue test. No tokens found")
    };
    let server_tokens = match server.tcpls_tokens() {
        Some(tokens) => tokens,
        None => panic!("cannot continue test. No tokens found")
    };
    for i in 0..=5 {
        assert_eq!(client_tokens.get(i), server_tokens.get(i));
    }
    // Generate 20 tokens on server side and receive 20 on client side
    let mut server_config = make_server_config(KeyType::Rsa);
    server_config.max_tcpls_tokens_cap = 20;
    let mut client_config = make_client_config_with_versions(KeyType::Rsa, &[&rustls::version::TLS13]);
    client_config.enable_tcpls = true;
    let (mut client, mut server, mut recv_svr, mut recv_clnt) =
        make_pair_for_arc_configs(&Arc::new(client_config), &Arc::new(server_config));
    do_handshake(&mut client, &mut server, &mut recv_svr, &mut recv_clnt);
    let client_tokens = match client.tcpls_tokens() {
        Some(tokens) => tokens,
        None => panic!("cannot continue test. No tokens found")
    };
    let server_tokens = match server.tcpls_tokens() {
        Some(tokens) => tokens,
        None => panic!("cannot continue test. No tokens found")
    };
    for i in 0..=20 {
        assert_eq!(client_tokens.get(i), server_tokens.get(i));
    }

}



pub fn send_stream_change_frame(stream_id: u32, offset: u64) -> Vec<u8> {
    let mut buffer = vec![0u8; 13];
    let mut b = octets::OctetsMut::with_slice(&mut buffer);
    Frame::StreamChange {
        next_record_stream_id: stream_id,
        next_offset: offset,
    }.encode(&mut b).unwrap();
    buffer
}
#[test]
fn receive_out_of_order_tls_records_multiple_streams() {
    let data_len= 300 * MAX_TCPLS_FRAGMENT_LEN;
    let capacity = 400 * MAX_TCPLS_FRAGMENT_LEN;
    let sendbuf1 = vec![1u8; data_len];
    let sendbuf2 = vec![2u8; data_len];

   // Finish handshake
   let (mut client, mut server, mut recv_svr, mut recv_clnt) =
       make_pair(KeyType::Rsa);
   do_handshake(&mut client, &mut server, &mut recv_svr, &mut recv_clnt);
   server.set_deframer_cap(0, capacity);
   server.set_deframer_cap(1, capacity);
   server.set_deframer_cap(2, capacity);

   let mut pipe = OtherSession::new(&mut server);
   let mut conn_id: u32 = 0;
   client.write_to = 1;
   let mut last_stream: Vec<Option<u32>> = Vec::default();
   let mut buf: Vec<u8>;

   for chunk in sendbuf1.chunks(MAX_TCPLS_FRAGMENT_LEN).map(|chunk| chunk.to_vec()) {
       client.set_connection_in_use(conn_id);
       pipe.sess.set_connection_in_use(conn_id);
       if last_stream.get(conn_id as usize).is_none() || last_stream.get(conn_id as usize).unwrap().unwrap() != 1 {
           buf = send_stream_change_frame(1, 0);
           let msg = OutboundPlainMessage {
               typ: ContentType::TcplsControl,
               version: ProtocolVersion::TLSv1_2,
               payload: OutboundChunks::from(
                   buf.as_slice()
               ),
           };
           client.send_msg_enc_benchmark(msg);
           pipe.write_all(client.get_encrypted_chunk_as_slice());
           last_stream.insert(conn_id as usize, Some(1));
       }
       client.writer().write(chunk.as_slice()).expect("Could not encrypt data");
       pipe.write_all(client.get_encrypted_chunk_as_slice());
       conn_id += 1;
       if conn_id == 3 {
           conn_id = 0;
       }

   }
   client.write_to = 2;
   conn_id = 0;
   for chunk in sendbuf2.chunks(MAX_TCPLS_FRAGMENT_LEN).map(|chunk| chunk.to_vec()) {
       client.set_connection_in_use(conn_id);
       pipe.sess.set_connection_in_use(conn_id);
       if last_stream.get(conn_id as usize).is_none() || last_stream.get(conn_id as usize).unwrap().unwrap() != 1 {
           buf = send_stream_change_frame(1, 0);
           let msg = OutboundPlainMessage {
               typ: ContentType::TcplsControl,
               version: ProtocolVersion::TLSv1_2,
               payload: OutboundChunks::from(
                   buf.as_slice()
               ),
           };
           client.send_msg_enc_benchmark(msg);
           pipe.write_all(client.get_encrypted_chunk_as_slice());
           last_stream.insert(conn_id as usize, Some(1));
       }
       client.writer().write(chunk.as_slice()).expect("Could not encrypt data");
       pipe.write_all(client.get_encrypted_chunk_as_slice());
       conn_id += 1;
       if conn_id == 3{
           conn_id = 0;
       }
   }
   // Create app receive buffer
   recv_svr.get_or_create(1, Some(capacity));
   recv_svr.get_or_create(2, Some(capacity));

    let conn_ids: Vec<u32> = vec![0,1,2];
    let stream_ids: Vec<u32> = vec![1,2];
    for str_id in stream_ids {
        loop {
            for id in &conn_ids {
                pipe.sess.set_connection_in_use(*id);
                pipe.sess.process_new_packets(&mut recv_svr).unwrap();
            }
            if recv_svr.get(str_id as u16).unwrap().data_length() >= sendbuf1.len() as u64 { break }
        }

    }
}


#[derive(Debug)]
struct ClientCheckCertResolve {
    query_count: AtomicUsize,
    expect_queries: usize,
    expect_root_hint_subjects: Vec<Vec<u8>>,
    expect_sigschemes: Vec<SignatureScheme>,
}

impl ClientCheckCertResolve {
    fn new(
        expect_queries: usize,
        expect_root_hint_subjects: Vec<Vec<u8>>,
        expect_sigschemes: Vec<SignatureScheme>,
    ) -> Self {
        Self {
            query_count: AtomicUsize::new(0),
            expect_queries,
            expect_root_hint_subjects,
            expect_sigschemes,
        }
    }
}

impl Drop for ClientCheckCertResolve {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            let count = self.query_count.load(Ordering::SeqCst);
            assert_eq!(count, self.expect_queries);
        }
    }
}

impl ResolvesClientCert for ClientCheckCertResolve {
    fn resolve(
        &self,
        root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<sign::CertifiedKey>> {
        self.query_count
            .fetch_add(1, Ordering::SeqCst);
            if sigschemes.is_empty() {
            panic!("no signature schemes shared by server");
        }

        assert_eq!(sigschemes, self.expect_sigschemes);
        assert_eq!(root_hint_subjects, self.expect_root_hint_subjects);
            None
    }

    fn has_certs(&self) -> bool {
        true
    }
}


fn test_client_cert_resolve(
    key_type: KeyType,
    server_config: Arc<ServerConfig>,
    expected_root_hint_subjects: Vec<Vec<u8>>,
) {
    for version in rustls::ALL_VERSIONS {
             if version.version == ProtocolVersion::TLSv1_2 {
                continue
            }
        println!("{:?} {:?}:", version.version, key_type);

        let mut client_config = make_client_config_with_versions(key_type, &[version]);
        client_config.client_auth_cert_resolver = Arc::new(ClientCheckCertResolve::new(
            1,
            expected_root_hint_subjects.clone(),
            default_signature_schemes(version.version),
        ));

        let (mut client, mut server, mut recv_srv, mut recv_clnt) =
            make_pair_for_arc_configs(&Arc::new(client_config), &server_config);

        assert_eq!(
            do_handshake_until_error(&mut client, &mut server, &mut recv_srv, &mut recv_clnt),
            Err(ErrorFromPeer::Server(Error::NoCertificatesPresented))
        );
    }
}

fn default_signature_schemes(version: ProtocolVersion) -> Vec<SignatureScheme> {
    let mut v = vec![];



    v.extend_from_slice(&[
        SignatureScheme::ECDSA_NISTP384_SHA384,
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::ED25519,
        SignatureScheme::RSA_PSS_SHA512,
        SignatureScheme::RSA_PSS_SHA384,
        SignatureScheme::RSA_PSS_SHA256,
    ]);

    if version == ProtocolVersion::TLSv1_2 {
        v.extend_from_slice(&[
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA256,
        ]);
    }

    v
}

#[test]
fn client_cert_resolve_default() {
    // Test that in the default configuration that a client cert resolver gets the expected
    // CA subject hints, and supported signature algorithms.
    for key_type in ALL_KEY_TYPES {
        let server_config = Arc::new(make_server_config_with_mandatory_client_auth(*key_type));

        // In a default configuration we expect that the verifier's trust anchors are used
        // for the hint subjects.
        let expected_root_hint_subjects = vec![key_type
            .ca_distinguished_name()
            .to_vec()];

        test_client_cert_resolve(*key_type, server_config, expected_root_hint_subjects);
    }
}

#[test]
fn client_cert_resolve_server_no_hints() {
    // Test that a server can provide no hints and the client cert resolver gets the expected
    // arguments.
    for key_type in ALL_KEY_TYPES {
        // Build a verifier with no hint subjects.
        let verifier = webpki_client_verifier_builder(get_client_root_store(*key_type))
            .clear_root_hint_subjects();
        let server_config = make_server_config_with_client_verifier(*key_type, verifier);
        let expected_root_hint_subjects = Vec::default(); // no hints expected.
        test_client_cert_resolve(*key_type, server_config.into(), expected_root_hint_subjects);
    }
}

#[test]
fn client_cert_resolve_server_added_hint() {
    // Test that a server can add an extra subject above/beyond those found in its trust store
    // and the client cert resolver gets the expected arguments.
    let extra_name = b"0\x1a1\x180\x16\x06\x03U\x04\x03\x0c\x0fponyland IDK CA".to_vec();
    for key_type in ALL_KEY_TYPES {
        let expected_hint_subjects = vec![
            key_type
                .ca_distinguished_name()
                .to_vec(),
            extra_name.clone(),
        ];
        // Create a verifier that adds the extra_name as a hint subject in addition to the ones
        // from the root cert store.
        let verifier = webpki_client_verifier_builder(get_client_root_store(*key_type))
            .add_root_hint_subjects([DistinguishedName::from(extra_name.clone())].into_iter());
        let server_config = make_server_config_with_client_verifier(*key_type, verifier);
        test_client_cert_resolve(*key_type, server_config.into(), expected_hint_subjects);
    }
}

#[test]
fn client_auth_works() {
    for kt in ALL_KEY_TYPES {
        let server_config = Arc::new(make_server_config_with_mandatory_client_auth(*kt));

        for version in rustls::ALL_VERSIONS {
                if version.version == ProtocolVersion::TLSv1_2 {
                continue
            }
            let client_config = make_client_config_with_versions_with_auth(*kt, &[version]);
            let (mut client, mut server, mut recv_svr, mut recv_clnt) =
                make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
            do_handshake(&mut client, &mut server, &mut recv_svr, &mut recv_clnt);
        }
    }
}

#[test]
fn client_mandatory_auth_client_revocation_works() {
    for kt in ALL_KEY_TYPES {
        // Create a server configuration that includes a CRL that specifies the client certificate
        // is revoked.
        let relevant_crls = vec![kt.client_crl()];
        // Only check the EE certificate status. See client_mandatory_auth_intermediate_revocation_works
        // for testing revocation status of the whole chain.
        let ee_verifier_builder = webpki_client_verifier_builder(get_client_root_store(*kt))
            .with_crls(relevant_crls)
            .only_check_end_entity_revocation();
        let revoked_server_config = Arc::new(make_server_config_with_client_verifier(
            *kt,
            ee_verifier_builder,
        ));

        // Create a server configuration that includes a CRL that doesn't cover the client certificate,
        // and uses the default behaviour of treating unknown revocation status as an error.
        let unrelated_crls = vec![kt.intermediate_crl()];
        let ee_verifier_builder = webpki_client_verifier_builder(get_client_root_store(*kt))
            .with_crls(unrelated_crls.clone())
            .only_check_end_entity_revocation();
        let missing_client_crl_server_config = Arc::new(make_server_config_with_client_verifier(
            *kt,
            ee_verifier_builder,
        ));

        // Create a server configuration that includes a CRL that doesn't cover the client certificate,
        // but change the builder to allow unknown revocation status.
        let ee_verifier_builder = webpki_client_verifier_builder(get_client_root_store(*kt))
            .with_crls(unrelated_crls.clone())
            .only_check_end_entity_revocation()
            .allow_unknown_revocation_status();
        let allow_missing_client_crl_server_config = Arc::new(
            make_server_config_with_client_verifier(*kt, ee_verifier_builder),
        );

        for version in rustls::ALL_VERSIONS {
                 if version.version == ProtocolVersion::TLSv1_2 {
                continue
            }
            // Connecting to the server with a CRL that indicates the client certificate is revoked
            // should fail with the expected error.
            let client_config =
                Arc::new(make_client_config_with_versions_with_auth(*kt, &[version]));
            let (mut client, mut server, mut recv_srv, mut recv_clnt) =
                make_pair_for_arc_configs(&client_config, &revoked_server_config);
            let err = do_handshake_until_error(&mut client, &mut server, &mut recv_srv, &mut recv_clnt);
            assert_eq!(
                err,
                Err(ErrorFromPeer::Server(Error::InvalidCertificate(
                    CertificateError::Revoked
                )))
            );
            // Connecting to the server missing CRL information for the client certificate should
            // fail with the expected unknown revocation status error.
            let (mut client, mut server, mut recv_srv, mut recv_clnt) =
                make_pair_for_arc_configs(&client_config, &missing_client_crl_server_config);
            let res = do_handshake_until_error(&mut client, &mut server, &mut recv_srv, &mut recv_clnt);
            assert!(matches!(
                res,
                Err(ErrorFromPeer::Server(Error::InvalidCertificate(
                    CertificateError::UnknownRevocationStatus
                )))
            ));
            // Connecting to the server missing CRL information for the client should not error
            // if the server's verifier allows unknown revocation status.
            let (mut client, mut server, mut recv_srv, mut recv_clnt) =
                make_pair_for_arc_configs(&client_config, &allow_missing_client_crl_server_config);
            let res = do_handshake_until_error(&mut client, &mut server, &mut recv_srv, &mut recv_clnt);
            assert!(res.is_ok());
        }
    }
}

#[test]
fn client_mandatory_auth_intermediate_revocation_works() {
    for kt in ALL_KEY_TYPES {
        // Create a server configuration that includes a CRL that specifies the intermediate certificate
        // is revoked. We check the full chain for revocation status (default), and allow unknown
        // revocation status so the EE's unknown revocation status isn't an error.
        let crls = vec![kt.intermediate_crl()];
        let full_chain_verifier_builder =
            webpki_client_verifier_builder(get_client_root_store(*kt))
                .with_crls(crls.clone())
                .allow_unknown_revocation_status();
        let full_chain_server_config = Arc::new(make_server_config_with_client_verifier(
            *kt,
            full_chain_verifier_builder,
        ));

        // Also create a server configuration that uses the same CRL, but that only checks the EE
        // cert revocation status.
        let ee_only_verifier_builder = webpki_client_verifier_builder(get_client_root_store(*kt))
            .with_crls(crls)
            .only_check_end_entity_revocation()
            .allow_unknown_revocation_status();
        let ee_server_config = Arc::new(make_server_config_with_client_verifier(
            *kt,
            ee_only_verifier_builder,
        ));

        for version in rustls::ALL_VERSIONS {
                 if version.version == ProtocolVersion::TLSv1_2 {
                continue
            }
            // When checking the full chain, we expect an error - the intermediate is revoked.
            let client_config =
                Arc::new(make_client_config_with_versions_with_auth(*kt, &[version]));
            let (mut client, mut server, mut recv_srv, mut recv_clnt) =
                make_pair_for_arc_configs(&client_config, &full_chain_server_config);
            let err = do_handshake_until_error(&mut client, &mut server, &mut recv_srv, &mut recv_clnt);
            assert_eq!(
                err,
                Err(ErrorFromPeer::Server(Error::InvalidCertificate(
                    CertificateError::Revoked
                )))
            );
            // However, when checking just the EE cert we expect no error - the intermediate's
            // revocation status should not be checked.
            let (mut client, mut server, mut recv_srv, mut recv_clnt) =
                make_pair_for_arc_configs(&client_config, &ee_server_config);
            assert!(do_handshake_until_error(&mut client, &mut server, &mut recv_srv, &mut recv_clnt).is_ok());
        }
    }
}

#[test]
fn client_optional_auth_client_revocation_works() {
    for kt in ALL_KEY_TYPES {
        // Create a server configuration that includes a CRL that specifies the client certificate
        // is revoked.
        let crls = vec![kt.client_crl()];
        let server_config = Arc::new(make_server_config_with_optional_client_auth(*kt, crls));

        for version in rustls::ALL_VERSIONS {
                 if version.version == ProtocolVersion::TLSv1_2 {
                continue
            }
            let client_config = make_client_config_with_versions_with_auth(*kt, &[version]);
            let (mut client, mut server, mut recv_srv, mut recv_clnt) =
                make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
            // Because the client certificate is revoked, the handshake should fail.
            let err = do_handshake_until_error(&mut client, &mut server, &mut recv_srv, &mut recv_clnt);
            assert_eq!(
                err,
                Err(ErrorFromPeer::Server(Error::InvalidCertificate(
                    CertificateError::Revoked
                )))
            );
        }
    }
}

#[test]
fn client_error_is_sticky() {
    let (mut client, _, _recv_srv, mut recv_clnt) = make_pair(KeyType::Rsa);
    client
        .read_tls(&mut b"\x16\x03\x03\x00\x08\x0f\x00\x00\x04junk".as_ref())
        .unwrap();
    let mut err = client.process_new_packets(&mut recv_clnt);
    assert!(err.is_err());
    err = client.process_new_packets(&mut recv_clnt);
    assert!(err.is_err());
}

#[test]
fn server_error_is_sticky() {

    let (_, mut server, mut recv_srv, _recv_clnt) = make_pair(KeyType::Rsa);
    server
        .read_tls(&mut b"\x16\x03\x03\x00\x08\x0f\x00\x00\x04junk".as_ref())
        .unwrap();
    let mut err = server.process_new_packets(&mut recv_srv);
    assert!(err.is_err());
    err = server.process_new_packets(&mut recv_srv);
    assert!(err.is_err());
}

#[test]
fn server_flush_does_nothing() {
    let (_, mut server,  _recv_srv,  _recv_clnt) = make_pair(KeyType::Rsa);
    assert!(matches!(server.writer().flush(), Ok(())));
}

#[test]
fn client_flush_does_nothing() {

    let (mut client, _, _recv_srv,  _recv_clnt) = make_pair(KeyType::Rsa);
    assert!(matches!(client.writer().flush(), Ok(())));
}

#[allow(clippy::no_effect)]
#[test]
fn server_is_send_and_sync() {
    let (_, server, _recv_srv, _recv_clnt) = make_pair(KeyType::Rsa);
    &server as &dyn Send;
    &server as &dyn Sync;
}

#[allow(clippy::no_effect)]
#[test]
fn client_is_send_and_sync() {
    let (client, _, _recv_srv, _recv_clnt) = make_pair(KeyType::Rsa);
    &client as &dyn Send;
    &client as &dyn Sync;
}







struct OtherSession<'a, C, S>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    S: SideData,
{
    sess: &'a mut C,
    pub reads: usize,
    pub writevs: Vec<Vec<usize>>,
    fail_ok: bool,
    pub short_writes: bool,
    pub last_error: Option<rustls::Error>,
    pub buffered: bool,
    buffer: Vec<Vec<u8>>,
    pub recv_map: RecvBufMap,
}

impl<'a, C, S> OtherSession<'a, C, S>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    S: SideData,
{
    fn new(sess: &'a mut C) -> OtherSession<'a, C, S> {
        OtherSession {
            sess,
            reads: 0,
            writevs: vec![],
            fail_ok: false,
            short_writes: false,
            last_error: None,
            buffered: false,
            buffer: vec![],
            recv_map: RecvBufMap::new(),
        }
    }

    fn new_buffered(sess: &'a mut C) -> OtherSession<'a, C, S> {
        let mut os = OtherSession::new(sess);
        os.buffered = true;
        os
    }

    fn new_fails(sess: &'a mut C) -> OtherSession<'a, C, S> {
        let mut os = OtherSession::new(sess);
        os.fail_ok = true;
        os
    }


    fn flush_vectored(&mut self, b: &[io::IoSlice<'_>]) -> io::Result<usize> {
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


        let rc = self.sess.process_new_packets(&mut self.recv_map);
        if !self.fail_ok {
            rc.unwrap();
        } else if rc.is_err() {
            self.last_error = rc.err();
        }

        self.writevs.push(lengths);
        Ok(total)
    }
    fn write_all(&mut self, mut buf: &[u8]) -> usize {
        let mut sent = 0;
        while !buf.is_empty() {
            match self.write(buf) {
                Ok(0) => {
                    sent = 0;
                }
                Ok(n) => {
                    buf = &buf[n..];
                    sent += n;
                },
                Err(_e) => panic!("Something wrong"),
            }
        }
        sent
    }
}

impl<'a, C, S> io::Read for OtherSession<'a, C, S>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    S: SideData,
{
    fn read(&mut self, mut b: &mut [u8]) -> io::Result<usize> {
        self.reads += 1;
        self.sess.write_tls(b.by_ref(), 0)
    }
}

impl<'a, C, S> io::Write for OtherSession<'a, C, S>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    S: SideData,
{
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
          let mut buf = input;
        self.sess.read_tls(&mut buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.buffer.is_empty() {
            let buffer = mem::take(&mut self.buffer);
            let slices = buffer
                .iter()
                .map(|b| io::IoSlice::new(b))
                .collect::<Vec<_>>();
            self.flush_vectored(&slices)?;
        }
        Ok(())
    }

    fn write_vectored(&mut self, b: &[io::IoSlice<'_>]) -> io::Result<usize> {
     /*   if self.buffered {
            self.buffer
                .extend(b.iter().map(|s| s.to_vec()));
            return Ok(b.iter().map(|s| s.len()).sum());
        }*/
        self.flush_vectored(b)
    }
}

#[test]
fn server_read_returns_wouldblock_when_no_data() {
    let (_, mut server, _recv_srv, _recv_clnt) = make_pair(KeyType::Rsa);
    assert!(matches!(server.reader().read(&mut [0u8; 1]),
                     Err(err) if err.kind() == io::ErrorKind::WouldBlock));
}

#[test]
fn client_read_returns_wouldblock_when_no_data() {

    let (mut client, _,  _recv_srv,  _recv_clnt) = make_pair(KeyType::Rsa);
    assert!(matches!(client.reader().read(&mut [0u8; 1]),
                     Err(err) if err.kind() == io::ErrorKind::WouldBlock));
}

#[test]
fn new_server_returns_initial_io_state() {

    let (_, mut server, mut recv_srv, _recv_clnt) = make_pair(KeyType::Rsa);
    let io_state = server.process_new_packets(&mut recv_srv).unwrap();
    println!("IoState is Debug {:?}", io_state);
    assert_eq!(io_state.plaintext_bytes_to_read(), 0);
    assert!(!io_state.peer_has_closed());
    assert_eq!(io_state.tls_bytes_to_write(), 0);
}

#[test]
fn new_client_returns_initial_io_state() {

    let (mut client, _, _recv_srv, mut recv_clnt) = make_pair(KeyType::Rsa);
    let io_state = client.process_new_packets(&mut recv_clnt).unwrap();
    println!("IoState is Debug {:?}", io_state);
    assert_eq!(io_state.plaintext_bytes_to_read(), 0);
    assert!(!io_state.peer_has_closed());
    assert!(io_state.tls_bytes_to_write() > 200);
}

#[test]
fn client_complete_io_for_handshake() {

    let (mut client, mut server, _recv_srv, _recv_clnt) = make_pair(KeyType::Rsa);

    assert!(client.is_handshaking());
    let (rdlen, wrlen) = client
        .complete_io(&mut OtherSession::new(&mut server), None)
        .unwrap();
    assert!(rdlen > 0 && wrlen > 0);
    assert!(!client.is_handshaking());
    assert!(!client.wants_write());
}

#[test]
fn buffered_client_complete_io_for_handshake() {
    let (mut client, mut server, _recv_srv, mut recv_clnt) = make_pair(KeyType::Rsa);

    assert!(client.is_handshaking());
    let (rdlen, wrlen) = client
        .complete_io(&mut OtherSession::new_buffered(&mut server), Some(&mut recv_clnt))
        .unwrap();
    assert!(rdlen > 0 && wrlen > 0);
    assert!(!client.is_handshaking());
    assert!(!client.wants_write());
}

#[test]
fn client_complete_io_for_handshake_eof() {

    let (mut client, _, _recv_srv,  _recv_clnt) = make_pair(KeyType::Rsa);
    let mut input = io::Cursor::new(Vec::new());

    assert!(client.is_handshaking());
    let err = client
        .complete_io(&mut input, None)
        .unwrap_err();
    assert_eq!(io::ErrorKind::UnexpectedEof, err.kind());
}






#[test]
fn single_stream_multipath() {

    let data_len= 300 * MAX_TCPLS_FRAGMENT_LEN;
    let capacity = 400 * MAX_TCPLS_FRAGMENT_LEN;
    let sendbuf1 = vec![1u8; data_len];

    // Finish handshake
    let (mut client, mut server, mut recv_svr, mut recv_clnt) =
        make_pair(KeyType::Rsa);
    do_handshake(&mut client, &mut server, &mut recv_svr, &mut recv_clnt);
    server.set_deframer_cap(0, capacity);
    server.set_deframer_cap(1, capacity);
    server.set_deframer_cap(2, capacity);

    let mut pipe = OtherSession::new(&mut server);
    let mut conn_id: u32 = 0;
    client.write_to = 1;
    let mut last_stream: Vec<Option<u32>> = Vec::default();
    let mut buf;

    for chunk in sendbuf1.chunks(MAX_TCPLS_FRAGMENT_LEN).map(|chunk| chunk.to_vec()) {
        client.set_connection_in_use(conn_id);
        pipe.sess.set_connection_in_use(conn_id);
        if last_stream.get(conn_id as usize).is_none() || last_stream.get(conn_id as usize).unwrap().unwrap() != 1 {
            buf = send_stream_change_frame(1, 0);
            let msg = OutboundPlainMessage {
                typ: ContentType::TcplsControl,
                version: ProtocolVersion::TLSv1_2,
                payload: OutboundChunks::from(
                    buf.as_slice()
                ),
            };
            client.send_msg_enc_benchmark(msg);
            pipe.write_all(client.get_encrypted_chunk_as_slice());
            last_stream.insert(conn_id as usize, Some(1));
        }
        client.writer().write(chunk.as_slice()).expect("Could not encrypt data");
        pipe.write_all(client.get_encrypted_chunk_as_slice());
        conn_id += 1;
        if conn_id == 3 {
            conn_id = 0;
        }

    }

    // Create app receive buffer
    recv_svr.get_or_create(1, Some(capacity));


    let conn_ids: Vec<u32> = vec![0,1,2];
    let stream_ids: Vec<u32> = vec![1];
    for str_id in stream_ids {
        loop {
            for id in &conn_ids {
                pipe.sess.set_connection_in_use(*id);
                pipe.sess.process_new_packets(&mut recv_svr).unwrap();
            }
            if recv_svr.get(str_id as u16).unwrap().data_length() >= sendbuf1.len() as u64 { break }
        }

    }
}

#[test]
fn server_complete_io_for_handshake() {

    for kt in ALL_KEY_TYPES {
        let (mut client, mut server,  _recv_srv, _recv_clnt) = make_pair(*kt);

        assert!(server.is_handshaking());
        let (rdlen, wrlen) = server
            .complete_io(&mut OtherSession::new(&mut client), None)
            .unwrap();
        assert!(rdlen > 0 && wrlen > 0);
        assert!(!server.is_handshaking());
        assert!(!server.wants_write());
    }
}

#[test]
fn server_complete_io_for_handshake_eof() {
    let (_, mut server, _recv_srv,  _recv_clnt) = make_pair(KeyType::Rsa);
    let mut input = io::Cursor::new(Vec::new());

    assert!(server.is_handshaking());
    let err = server
        .complete_io(&mut input, None)
        .unwrap_err();
    assert_eq!(io::ErrorKind::UnexpectedEof, err.kind());
}







/*#[derive(Debug, Copy, Clone)]
enum StreamKind {
    Owned,
    Ref,
}*/

/*fn test_client_stream_write(stream_kind: StreamKind) {
    for kt in ALL_KEY_TYPES {
        let (mut client, mut server, mut recv_srv, mut recv_clnt) = make_pair(*kt);
        let data = b"hello";
        {
            let mut pipe = OtherSession::new(&mut server);
            let mut stream: Box<dyn Write> = match stream_kind {
                StreamKind::Ref => Box::new(Stream::new(&mut client, &mut pipe, &mut recv_clnt)),
                StreamKind::Owned => Box::new(StreamOwned::new(client, pipe, recv_clnt)),
            };
            assert_eq!(stream.write(data).unwrap(), 5);
        }
        check_read_app_buff(&mut server.reader_app_bufs(), data, &mut recv_srv, 0);
    }
}*/

/*fn test_server_stream_write(stream_kind: StreamKind) {
    for kt in ALL_KEY_TYPES {
        let (mut client, mut server, mut recv_srv, mut recv_clnt) = make_pair(*kt);
        let data = b"hello";
        {
            let mut pipe = OtherSession::new(&mut client);
            let mut stream: Box<dyn Write> = match stream_kind {
                StreamKind::Ref => Box::new(Stream::new(&mut server, &mut pipe, &mut recv_srv)),
                StreamKind::Owned => Box::new(StreamOwned::new(server, pipe, recv_srv)),
            };
            assert_eq!(stream.write(data).unwrap(), 5);
        }
            check_read_app_buff(&mut client.reader_app_bufs(), data, &mut recv_clnt, 0);

    }
}*/





/*#[derive(Debug, Copy, Clone)]
enum ReadKind {
    Buf,
    #[cfg(read_buf)]
    BorrowedBuf,
}*/

/*fn test_stream_read(read_kind: ReadKind, mut stream: impl Read, data: &[u8]) {
    match read_kind {
        ReadKind::Buf => {
            check_read(&mut stream, data);
            check_read_err(&mut stream, io::ErrorKind::UnexpectedEof)
        }
        #[cfg(read_buf)]
        ReadKind::BorrowedBuf => {
            check_read_buf(&mut stream, data);
            check_read_buf_err(&mut stream, io::ErrorKind::UnexpectedEof)
        }
    }
}*/

/*fn test_client_stream_read(stream_kind: StreamKind, read_kind: ReadKind) {
    for kt in ALL_KEY_TYPES {
        let (mut client, mut server,  _recv_srv, mut recv_clnt) = make_pair(*kt);
        let data = b"world";
        server.writer().write_all(data).unwrap();

        {
            let mut pipe = OtherSession::new(&mut server);
            transfer_eof(&mut client);

            let stream: Box<dyn Read> = match stream_kind {
                StreamKind::Ref => Box::new(Stream::new(&mut client, &mut pipe, &mut recv_clnt)),
                StreamKind::Owned => Box::new(StreamOwned::new(client, pipe, recv_clnt)),
            };

            test_stream_read(read_kind, stream, data)
        }
    }
}*/

/*fn test_server_stream_read(stream_kind: StreamKind, read_kind: ReadKind) {
    for kt in ALL_KEY_TYPES {
        let (mut client, mut server, mut recv_srv, _recv_clnt) = make_pair(*kt);
        let data = b"world";
        client.writer().write_all(data).unwrap();

        {
            let mut pipe = OtherSession::new(&mut client);
            transfer_eof(&mut server);

            let stream: Box<dyn Read> = match stream_kind {
                StreamKind::Ref => Box::new(Stream::new(&mut server, &mut pipe, &mut recv_srv)),
                StreamKind::Owned => Box::new(StreamOwned::new(server, pipe, recv_srv)),
            };

            test_stream_read(read_kind, stream, data)
        }
    }
}*/

#[test]
fn test_client_write_and_vectored_write_equivalence() {
    let (mut client, mut server, mut recv_srv, mut recv_clnt) = make_pair(KeyType::Rsa);
    do_handshake(&mut client, &mut server, &mut recv_srv, &mut recv_clnt);

    const N: usize = 1000;

    let data_chunked: Vec<IoSlice> = std::iter::repeat(IoSlice::new(b"A"))
        .take(N)
        .collect();
    let bytes_written_chunked = client
        .writer()
        .write_vectored(&data_chunked)
        .unwrap();
    let bytes_sent_chunked = transfer(&mut client, &mut server, None);
    println!("write_vectored returned {bytes_written_chunked} and sent {bytes_sent_chunked}");

    let data_contiguous = &[b'A'; N];
    let bytes_written_contiguous = client
        .writer()
        .write(data_contiguous)
        .unwrap();
    let bytes_sent_contiguous = transfer(&mut client, &mut server, None);
    println!("write returned {bytes_written_contiguous} and sent {bytes_sent_contiguous}");

    assert_eq!(bytes_written_chunked, bytes_written_contiguous);
    assert_eq!(bytes_sent_chunked, bytes_sent_contiguous);
}

struct FailsWrites {
    errkind: io::ErrorKind,
    after: usize,
}

impl io::Read for FailsWrites {
    fn read(&mut self, _b: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}

impl io::Write for FailsWrites {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        if self.after > 0 {
            self.after -= 1;
            Ok(b.len())
        } else {
            Err(io::Error::new(self.errkind, "oops"))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}



#[test]
fn stream_write_swallows_underlying_io_error_after_plaintext_processed() {

    let (mut client, mut server, mut recv_srv, mut recv_clnt) = make_pair(KeyType::Rsa);
    do_handshake(&mut client, &mut server, &mut recv_srv, &mut recv_clnt);

    let mut pipe = FailsWrites {
        errkind: io::ErrorKind::ConnectionAborted,
        after: 1,
    };
    client
        .writer()
        .write_all(b"hello")
        .unwrap();

    let mut client_stream = Stream::new(&mut client, &mut pipe, &mut recv_clnt);
    let rc = client_stream.write(b"world");
    assert_eq!(format!("{:?}", rc), "Ok(5)");
}

fn make_disjoint_suite_configs() -> (ClientConfig, ServerConfig) {
    let kt = KeyType::Rsa;

    let client_provider = CryptoProvider {
        cipher_suites: vec![cipher_suite::TLS13_CHACHA20_POLY1305_SHA256],
        ..provider::default_provider()
    };
    let server_config = finish_server_config(
        kt,
        ServerConfig::builder_with_provider(client_provider.into())
            .with_safe_default_protocol_versions()
            .unwrap(),
    );

    let server_provider = CryptoProvider {
        cipher_suites: vec![cipher_suite::TLS13_AES_256_GCM_SHA384],
        ..provider::default_provider()
    };
    let client_config = finish_client_config(
        kt,
        ClientConfig::builder_with_provider(server_provider.into())
            .with_safe_default_protocol_versions()
            .unwrap(),
    );

    (client_config, server_config)
}

#[test]
fn client_stream_handshake_error() {
    let (client_config, server_config) = make_disjoint_suite_configs();

    let (mut client, mut server, _recv_srv, mut recv_clnt) = make_pair_for_configs(client_config, server_config);

    {
        let mut pipe = OtherSession::new_fails(&mut server);
        let mut client_stream = Stream::new(&mut client, &mut pipe, &mut recv_clnt);
        let rc = client_stream.write(b"hello");
        assert!(rc.is_err());
        assert_eq!(
            format!("{:?}", rc),
            "Err(Custom { kind: InvalidData, error: AlertReceived(HandshakeFailure) })"
        );
        let rc = client_stream.write(b"hello");
        assert!(rc.is_err());
        assert_eq!(
            format!("{:?}", rc),
            "Err(Custom { kind: InvalidData, error: AlertReceived(HandshakeFailure) })"
        );
    }
}

#[test]
fn client_streamowned_handshake_error() {
    let (client_config, server_config) = make_disjoint_suite_configs();

    let (client, mut server, _recv_srv, recv_clnt) = make_pair_for_configs(client_config, server_config);

    let pipe = OtherSession::new_fails(&mut server);
    let mut client_stream = StreamOwned::new(client, pipe, recv_clnt);
    let rc = client_stream.write(b"hello");
    assert!(rc.is_err());
    assert_eq!(
        format!("{:?}", rc),
        "Err(Custom { kind: InvalidData, error: AlertReceived(HandshakeFailure) })"
    );
    let rc = client_stream.write(b"hello");
    assert!(rc.is_err());
    assert_eq!(
        format!("{:?}", rc),
        "Err(Custom { kind: InvalidData, error: AlertReceived(HandshakeFailure) })"
    );


    let (_, _) = client_stream.into_parts();
}

#[test]
fn server_stream_handshake_error() {
    let (client_config, server_config) = make_disjoint_suite_configs();

    let (mut client, mut server, mut recv_srv, _recv_clnt) = make_pair_for_configs(client_config, server_config);

    client
        .writer()
        .write_all(b"world")
        .unwrap();

    {
        let mut pipe = OtherSession::new_fails(&mut client);

        let mut server_stream = Stream::new(&mut server, &mut pipe, &mut recv_srv);
        let mut bytes = [0u8; 5];
        let rc = server_stream.read(&mut bytes);
        assert!(rc.is_err());
        assert_eq!(
            format!("{:?}", rc),
            "Err(Custom { kind: InvalidData, error: PeerIncompatible(NoCipherSuitesInCommon) })"
        );
    }
}

#[test]
fn server_streamowned_handshake_error() {
    let (client_config, server_config) = make_disjoint_suite_configs();

    let (mut client, server, recv_srv, _recv_clnt) = make_pair_for_configs(client_config, server_config);

    client
        .writer()
        .write_all(b"world")
        .unwrap();

    let pipe = OtherSession::new_fails(&mut client);
    let mut server_stream = StreamOwned::new(server, pipe, recv_srv);
    let mut bytes = [0u8; 5];
    let rc = server_stream.read(&mut bytes);
    assert!(rc.is_err());
    assert_eq!(
        format!("{:?}", rc),
        "Err(Custom { kind: InvalidData, error: PeerIncompatible(NoCipherSuitesInCommon) })"
    );
}

#[test]
fn server_config_is_clone() {
    let _ = make_server_config(KeyType::Rsa);
}

#[test]
fn client_config_is_clone() {
    let _ = make_client_config(KeyType::Rsa);
}

#[test]
fn client_connection_is_debug() {

    let (client, _,  _recv_srv,  _recv_clnt) = make_pair(KeyType::Rsa);
    println!("{:?}", client);
}

#[test]
fn server_connection_is_debug() {

    let (_, server, _recv_srv, _recv_clnt) = make_pair(KeyType::Rsa);
    println!("{:?}", server);
}

#[test]
fn server_complete_io_for_handshake_ending_with_alert() {
    let (client_config, server_config) = make_disjoint_suite_configs();
    let (mut client, mut server, _recv_srv,  _recv_clnt) = make_pair_for_configs(client_config, server_config);
    assert!(server.is_handshaking());
    let mut pipe = OtherSession::new_fails(&mut client);
    let rc = server.complete_io(&mut pipe, None);
    assert!(rc.is_err(), "server io failed due to handshake failure");
    assert!(!server.wants_write(), "but server did send its alert");
    assert_eq!(
        format!("{:?}", pipe.last_error),
        "Some(AlertReceived(HandshakeFailure))",
        "which was received by client"
    );
}

#[test]
fn server_exposes_offered_sni() {
    let kt = KeyType::Rsa;
    for version in rustls::ALL_VERSIONS {
             if version.version == ProtocolVersion::TLSv1_2 {
                continue
            }
            let mut recv_svr = RecvBufMap::new();
        let mut recv_clnt = RecvBufMap::new();
        let client_config = make_client_config_with_versions(kt, &[version]);
        let mut client = ClientConnection::new(
            Arc::new(client_config),
            server_name("second.testserver.com"),
        )
        .unwrap();
        let mut server = ServerConnection::new(Arc::new(make_server_config(kt))).unwrap();

        assert_eq!(None, server.server_name());
        do_handshake(&mut client, &mut server, &mut recv_svr, &mut recv_clnt);
        assert_eq!(Some("second.testserver.com"), server.server_name());
    }
}

#[test]
fn server_exposes_offered_sni_smashed_to_lowercase() {
    // webpki actually does this for us in its DnsName type
    let kt = KeyType::Rsa;
    for version in rustls::ALL_VERSIONS {
             if version.version == ProtocolVersion::TLSv1_2 {
                continue
            }
            let mut recv_svr = RecvBufMap::new();
        let mut recv_clnt = RecvBufMap::new();
        let client_config = make_client_config_with_versions(kt, &[version]);
        let mut client = ClientConnection::new(
            Arc::new(client_config),
            server_name("SECOND.TESTServer.com"),
        )
        .unwrap();
        let mut server = ServerConnection::new(Arc::new(make_server_config(kt))).unwrap();

        assert_eq!(None, server.server_name());
        do_handshake(&mut client, &mut server, &mut recv_svr, &mut recv_clnt);
        assert_eq!(Some("second.testserver.com"), server.server_name());
    }
}

#[test]
fn server_exposes_offered_sni_even_if_resolver_fails() {
    let kt = KeyType::Rsa;
    let resolver = rustls::server::ResolvesServerCertUsingSni::new();
         let mut app_bufs = RecvBufMap::new();
        let mut server_config = make_server_config(kt);
    server_config.cert_resolver = Arc::new(resolver);
    let server_config = Arc::new(server_config);

    for version in rustls::ALL_VERSIONS {
             if version.version == ProtocolVersion::TLSv1_2 {
                continue
            }
        let client_config = make_client_config_with_versions(kt, &[version]);
        let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();
        let mut client =

            ClientConnection::new(Arc::new(client_config), server_name("thisdoesNOTexist.com"))
                .unwrap();

        assert_eq!(None, server.server_name());
        transfer(&mut client, &mut server, None);
        assert_eq!(
            server.process_new_packets(&mut app_bufs),
            Err(Error::General(
                "no server certificate chain resolved".to_string()
            ))
        );
        assert_eq!(Some("thisdoesnotexist.com"), server.server_name());
    }
}

#[test]
fn sni_resolver_works() {
    let kt = KeyType::Rsa;
    let mut resolver = rustls::server::ResolvesServerCertUsingSni::new();
    let signing_key = RsaSigningKey::new(&kt.get_key()).unwrap();
    let signing_key: Arc<dyn sign::SigningKey> = Arc::new(signing_key);
    resolver
        .add(
            "localhost",
            sign::CertifiedKey::new(kt.get_chain(), signing_key.clone()),
        )
        .unwrap();

    let mut server_config = make_server_config(kt);
    server_config.cert_resolver = Arc::new(resolver);
    let server_config = Arc::new(server_config);

    let mut server1 = ServerConnection::new(Arc::clone(&server_config)).unwrap();
    let mut client1 =
        ClientConnection::new(Arc::new(make_client_config(kt)), server_name("localhost")).unwrap();
         let mut recv_srv = RecvBufMap::new();
    let mut recv_clnt = RecvBufMap::new();
    let err = do_handshake_until_error(&mut client1, &mut server1, &mut recv_srv, &mut recv_clnt);
    assert_eq!(err, Ok(()));

    let mut server2 = ServerConnection::new(Arc::clone(&server_config)).unwrap();
    let mut client2 = ClientConnection::new(
        Arc::new(make_client_config(kt)),
        server_name("notlocalhost"),
    )
    .unwrap();
        let mut recv_srv = RecvBufMap::new();
    let mut recv_clnt = RecvBufMap::new();
    let err = do_handshake_until_error(&mut client2, &mut server2, &mut recv_srv, &mut recv_clnt);
    assert_eq!(
        err,
        Err(ErrorFromPeer::Server(Error::General(
            "no server certificate chain resolved".into()
        )))
    );
}

#[test]
fn sni_resolver_rejects_wrong_names() {
    let kt = KeyType::Rsa;
    let mut resolver = rustls::server::ResolvesServerCertUsingSni::new();

    let signing_key = RsaSigningKey::new(&kt.get_key()).unwrap();
    let signing_key: Arc<dyn sign::SigningKey> = Arc::new(signing_key);

    assert_eq!(
        Ok(()),
        resolver.add(
            "localhost",
            sign::CertifiedKey::new(kt.get_chain(), signing_key.clone())
        )
    );
    assert_eq!(

        Err(Error::InvalidCertificate(CertificateError::NotValidForName)),
        resolver.add(
            "not-localhost",
            sign::CertifiedKey::new(kt.get_chain(), signing_key.clone())
        )
    );
    assert_eq!(
        Err(Error::General("Bad DNS name".into())),
        resolver.add(
            "not ascii 🦀",
            sign::CertifiedKey::new(kt.get_chain(), signing_key.clone())
        )
    );
}

#[test]
fn sni_resolver_lower_cases_configured_names() {
    let kt = KeyType::Rsa;
    let mut resolver = rustls::server::ResolvesServerCertUsingSni::new();

    let signing_key = RsaSigningKey::new(&kt.get_key()).unwrap();
    let signing_key: Arc<dyn sign::SigningKey> = Arc::new(signing_key);

    assert_eq!(
        Ok(()),
        resolver.add(
            "LOCALHOST",
            sign::CertifiedKey::new(kt.get_chain(), signing_key.clone())
        )
    );

    let mut server_config = make_server_config(kt);
    server_config.cert_resolver = Arc::new(resolver);
    let server_config = Arc::new(server_config);

    let mut server1 = ServerConnection::new(Arc::clone(&server_config)).unwrap();
    let mut client1 = ClientConnection::new(Arc::new(make_client_config(kt)), server_name("localhost")).unwrap();

        let mut recv_srv = RecvBufMap::new();
        let mut recv_clnt = RecvBufMap::new();
    let err = do_handshake_until_error(&mut client1, &mut server1, &mut recv_srv, &mut recv_clnt);
    assert_eq!(err, Ok(()));
}

#[test]
fn sni_resolver_lower_cases_queried_names() {
    // actually, the handshake parser does this, but the effect is the same.
    let kt = KeyType::Rsa;
    let mut resolver = rustls::server::ResolvesServerCertUsingSni::new();

    let signing_key = RsaSigningKey::new(&kt.get_key()).unwrap();
    let signing_key: Arc<dyn sign::SigningKey> = Arc::new(signing_key);

    assert_eq!(
        Ok(()),
        resolver.add(
            "localhost",
            sign::CertifiedKey::new(kt.get_chain(), signing_key.clone())
        )
    );

    let mut server_config = make_server_config(kt);
    server_config.cert_resolver = Arc::new(resolver);
    let server_config = Arc::new(server_config);

    let mut server1 = ServerConnection::new(Arc::clone(&server_config)).unwrap();
    let mut client1 =

        ClientConnection::new(Arc::new(make_client_config(kt)), server_name("LOCALHOST")).unwrap();
        let mut recv_srv = RecvBufMap::new();
        let mut recv_clnt = RecvBufMap::new();
    let err = do_handshake_until_error(&mut client1, &mut server1, &mut recv_srv, &mut recv_clnt);
    assert_eq!(err, Ok(()));
}

#[test]
fn sni_resolver_rejects_bad_certs() {
    let kt = KeyType::Rsa;
    let mut resolver = rustls::server::ResolvesServerCertUsingSni::new();

    let signing_key = RsaSigningKey::new(&kt.get_key()).unwrap();
    let signing_key: Arc<dyn sign::SigningKey> = Arc::new(signing_key);

    assert_eq!(
        Err(Error::NoCertificatesPresented),
        resolver.add(
            "localhost",
            sign::CertifiedKey::new(vec![], signing_key.clone())
        )
    );

    let bad_chain = vec![CertificateDer::from(vec![0xa0])];
    assert_eq!(
        Err(Error::InvalidCertificate(CertificateError::BadEncoding)),
        resolver.add(
            "localhost",
            sign::CertifiedKey::new(bad_chain, signing_key.clone())
        )
    );
}

fn do_exporter_test(client_config: ClientConfig, server_config: ServerConfig) {
    let mut client_secret = [0u8; 64];
    let mut server_secret = [0u8; 64];
    let (mut client, mut server, mut recv_srv, mut recv_clnt) = make_pair_for_configs(client_config, server_config);

    assert_eq!(
        Err(Error::HandshakeNotComplete),
        client.export_keying_material(&mut client_secret, b"label", Some(b"context"))
    );
    assert_eq!(
        Err(Error::HandshakeNotComplete),
        server.export_keying_material(&mut server_secret, b"label", Some(b"context"))
    );

    do_handshake(&mut client, &mut server, &mut recv_srv, &mut recv_clnt);

    assert!(client
        .export_keying_material(&mut client_secret, b"label", Some(b"context"))
        .is_ok());
    assert!(server
        .export_keying_material(&mut server_secret, b"label", Some(b"context"))
        .is_ok());
    assert_eq!(client_secret.to_vec(), server_secret.to_vec());

    let mut empty = vec![];
    assert_eq!(
        client
            .export_keying_material(&mut empty, b"label", Some(b"context"))
            .err(),
        Some(Error::General(
            "export_keying_material with zero-length output".into()
        ))
    );
    assert_eq!(
        server
            .export_keying_material(&mut empty, b"label", Some(b"context"))
            .err(),
        Some(Error::General(
            "export_keying_material with zero-length output".into()
        ))
    );

    assert!(client
        .export_keying_material(&mut client_secret, b"label", None)
        .is_ok());
    assert_ne!(client_secret.to_vec(), server_secret.to_vec());
    assert!(server
        .export_keying_material(&mut server_secret, b"label", None)
        .is_ok());
    assert_eq!(client_secret.to_vec(), server_secret.to_vec());
}




#[test]
fn test_tls13_exporter() {

    for kt in ALL_KEY_TYPES {
        let client_config = make_client_config_with_versions(*kt, &[&rustls::version::TLS13]);
        let server_config = make_server_config(*kt);

        do_exporter_test(client_config, server_config);
    }
}


#[test]
fn test_tls13_exporter_maximum_output_length() {
    let client_config =
        make_client_config_with_versions(KeyType::EcdsaP256, &[&rustls::version::TLS13]);
    let server_config = make_server_config(KeyType::EcdsaP256);

    let (mut client, mut server, mut recv_srv, mut recv_clnt) = make_pair_for_configs(client_config, server_config);
    do_handshake(&mut client, &mut server, &mut recv_srv, &mut recv_clnt);

    assert_eq!(
        client.negotiated_cipher_suite(),
        Some(find_suite(CipherSuite::TLS13_AES_256_GCM_SHA384))
    );

    let mut maximum_allowed_output_client = [0u8; 255 * 48];
    let mut maximum_allowed_output_server = [0u8; 255 * 48];
    client
        .export_keying_material(
            &mut maximum_allowed_output_client,
            b"label",
            Some(b"context"),
        )
        .unwrap();
    server
        .export_keying_material(
            &mut maximum_allowed_output_server,
            b"label",
            Some(b"context"),
        )
        .unwrap();

    assert_eq!(maximum_allowed_output_client, maximum_allowed_output_server);

    let mut too_long_output = [0u8; 255 * 48 + 1];
    assert_eq!(
        client
            .export_keying_material(&mut too_long_output, b"label", Some(b"context"),)
            .err(),
        Some(Error::General("exporting too much".into()))
    );
    assert_eq!(
        server
            .export_keying_material(&mut too_long_output, b"label", Some(b"context"),)
            .err(),
        Some(Error::General("exporting too much".into()))
    );
}

fn find_suite(suite: CipherSuite) -> SupportedCipherSuite {
    for scs in provider::ALL_CIPHER_SUITES
        .iter()
        .copied()
    {
        if scs.suite() == suite {
            return scs;
        }
    }

    panic!("find_suite given unsupported suite");
}


fn test_ciphersuites() -> Vec<(
    &'static rustls::SupportedProtocolVersion,
    KeyType,
    CipherSuite,
)> {
    let v = vec![
        (
            &rustls::version::TLS13,
            KeyType::Rsa,
            CipherSuite::TLS13_AES_256_GCM_SHA384,
        ),
        (
            &rustls::version::TLS13,
            KeyType::Rsa,
            CipherSuite::TLS13_AES_128_GCM_SHA256,
        ),
     /*   #[cfg(feature = "tls12")]
        (
            &rustls::version::TLS12,
            KeyType::EcdsaP384,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        ),
        #[cfg(feature = "tls12")]
        (
            &rustls::version::TLS12,
            KeyType::EcdsaP384,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        ),
        #[cfg(feature = "tls12")]
        (
            &rustls::version::TLS12,
            KeyType::Rsa,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ),
        #[cfg(feature = "tls12")]
        (
            &rustls::version::TLS12,
            KeyType::Rsa,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ),*/
    ];



    v
}

#[test]
fn negotiated_ciphersuite_default() {
    for kt in ALL_KEY_TYPES {
        do_suite_test(
            make_client_config(*kt),
            make_server_config(*kt),
            find_suite(CipherSuite::TLS13_AES_256_GCM_SHA384),
            ProtocolVersion::TLSv1_3,
        );
    }
}

#[test]
fn all_suites_covered() {

    assert_eq!(
        provider::DEFAULT_CIPHER_SUITES.len(), // 4 TLS 1.2 test suits were excluded
        test_ciphersuites().len()
    );
}

#[test]
fn negotiated_ciphersuite_client() {

    for (version, kt, suite) in test_ciphersuites() {
        let scs = find_suite(suite);
        let client_config = finish_client_config(
            kt,
            ClientConfig::builder_with_provider(
                CryptoProvider {
                    cipher_suites: vec![scs],
                    ..provider::default_provider()
                }
                .into(),
            )
            .with_protocol_versions(&[version])
            .unwrap(),
        );

        do_suite_test(client_config, make_server_config(kt), scs, version.version);
    }
}

#[test]
fn negotiated_ciphersuite_server() {

    for (version, kt, suite) in test_ciphersuites() {
        let scs = find_suite(suite);
        let server_config = finish_server_config(
            kt,
            ServerConfig::builder_with_provider(
                CryptoProvider {
                    cipher_suites: vec![scs],
                    ..provider::default_provider()
                }
                .into(),
            )
            .with_protocol_versions(&[version])
            .unwrap(),
        );

        do_suite_test(make_client_config(kt), server_config, scs, version.version);
    }
}

#[test]
fn negotiated_ciphersuite_server_ignoring_client_preference() {
    for (version, kt, suite) in test_ciphersuites() {
        let scs = find_suite(suite);
        let scs_other = if scs.suite() == CipherSuite::TLS13_AES_256_GCM_SHA384 {
            find_suite(CipherSuite::TLS13_AES_128_GCM_SHA256)
        } else {
            find_suite(CipherSuite::TLS13_AES_256_GCM_SHA384)
        };
        let mut server_config = finish_server_config(
            kt,
            ServerConfig::builder_with_provider(
                CryptoProvider {
                    cipher_suites: vec![scs, scs_other],
                    ..provider::default_provider()
                }
                .into(),
            )
            .with_protocol_versions(&[version])
            .unwrap(),
        );
        server_config.ignore_client_order = true;

        let client_config = finish_client_config(
            kt,
            ClientConfig::builder_with_provider(
                CryptoProvider {
                cipher_suites: vec![ scs_other, scs ],
                ..provider::default_provider()
            }.into(),
        )
        .with_safe_default_protocol_versions()
        .unwrap());

        do_suite_test(client_config, server_config, scs, version.version);
    }

}

#[derive(Debug, PartialEq)]
struct KeyLogItem {
    label: String,
    client_random: Vec<u8>,
    secret: Vec<u8>,
}


#[derive(Debug)]
struct KeyLogToVec {
    label: &'static str,
    items: Mutex<Vec<KeyLogItem>>,
}

impl KeyLogToVec {
    fn new(who: &'static str) -> Self {
        Self {
            label: who,
            items: Mutex::new(vec![]),
        }
    }

    fn take(&self) -> Vec<KeyLogItem> {
        std::mem::take(&mut self.items.lock().unwrap())
    }
}

impl KeyLog for KeyLogToVec {
    fn log(&self, label: &str, client: &[u8], secret: &[u8]) {
        let value = KeyLogItem {
            label: label.into(),
            client_random: client.into(),
            secret: secret.into(),
        };

        println!("key log {:?}: {:?}", self.label, value);

        self.items.lock().unwrap().push(value);
    }
}



#[test]
fn key_log_for_tls13() {

    let client_key_log = Arc::new(KeyLogToVec::new("client"));
    let server_key_log = Arc::new(KeyLogToVec::new("server"));

    let kt = KeyType::Rsa;
    let mut client_config = make_client_config_with_versions(kt, &[&rustls::version::TLS13]);
    client_config.key_log = client_key_log.clone();
    let client_config = Arc::new(client_config);

    let mut server_config = make_server_config(kt);
    server_config.key_log = server_key_log.clone();
    let server_config = Arc::new(server_config);

    // full handshake

    let (mut client, mut server, mut recv_srv, mut recv_clnt) = make_pair_for_arc_configs(&client_config, &server_config);
    do_handshake(&mut client, &mut server, &mut recv_srv, &mut recv_clnt);

    let client_full_log = client_key_log.take();
    let server_full_log = server_key_log.take();

    assert_eq!(5, client_full_log.len());
    assert_eq!("CLIENT_HANDSHAKE_TRAFFIC_SECRET", client_full_log[0].label);
    assert_eq!("SERVER_HANDSHAKE_TRAFFIC_SECRET", client_full_log[1].label);
    assert_eq!("CLIENT_TRAFFIC_SECRET_0", client_full_log[2].label);
    assert_eq!("SERVER_TRAFFIC_SECRET_0", client_full_log[3].label);
    assert_eq!("EXPORTER_SECRET", client_full_log[4].label);

    assert_eq!(client_full_log[0], server_full_log[0]);
    assert_eq!(client_full_log[1], server_full_log[1]);
    assert_eq!(client_full_log[2], server_full_log[2]);
    assert_eq!(client_full_log[3], server_full_log[3]);
    assert_eq!(client_full_log[4], server_full_log[4]);

    // resumed

    let (mut client, mut server, mut recv_srv, mut recv_clnt) = make_pair_for_arc_configs(&client_config, &server_config);
    do_handshake(&mut client, &mut server, &mut recv_srv, &mut recv_clnt);

    let client_resume_log = client_key_log.take();
    let server_resume_log = server_key_log.take();

    assert_eq!(5, client_resume_log.len());
    assert_eq!(
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        client_resume_log[0].label
    );
    assert_eq!(
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        client_resume_log[1].label
    );
    assert_eq!("CLIENT_TRAFFIC_SECRET_0", client_resume_log[2].label);
    assert_eq!("SERVER_TRAFFIC_SECRET_0", client_resume_log[3].label);
    assert_eq!("EXPORTER_SECRET", client_resume_log[4].label);

    assert_eq!(6, server_resume_log.len());
    assert_eq!("CLIENT_EARLY_TRAFFIC_SECRET", server_resume_log[0].label);
    assert_eq!(
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        server_resume_log[1].label
    );
    assert_eq!(
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        server_resume_log[2].label
    );
    assert_eq!("CLIENT_TRAFFIC_SECRET_0", server_resume_log[3].label);
    assert_eq!("SERVER_TRAFFIC_SECRET_0", server_resume_log[4].label);
    assert_eq!("EXPORTER_SECRET", server_resume_log[5].label);

    assert_eq!(client_resume_log[0], server_resume_log[1]);
    assert_eq!(client_resume_log[1], server_resume_log[2]);
    assert_eq!(client_resume_log[2], server_resume_log[3]);
    assert_eq!(client_resume_log[3], server_resume_log[4]);
    assert_eq!(client_resume_log[4], server_resume_log[5]);
}

struct ServerStorage {
    storage: Arc<dyn rustls::server::StoresServerSessions>,
    put_count: AtomicUsize,
    get_count: AtomicUsize,
    take_count: AtomicUsize,
}

impl ServerStorage {
    fn new() -> Self {
        Self {
            storage: rustls::server::ServerSessionMemoryCache::new(1024),
            put_count: AtomicUsize::new(0),
            get_count: AtomicUsize::new(0),
            take_count: AtomicUsize::new(0),
        }
    }

    fn puts(&self) -> usize {
        self.put_count.load(Ordering::SeqCst)
    }
    fn gets(&self) -> usize {
        self.get_count.load(Ordering::SeqCst)
    }
    fn takes(&self) -> usize {
        self.take_count.load(Ordering::SeqCst)
    }
}

impl fmt::Debug for ServerStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(put: {:?}, get: {:?}, take: {:?})",
            self.put_count, self.get_count, self.take_count
        )
    }
}

impl rustls::server::StoresServerSessions for ServerStorage {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.put_count
            .fetch_add(1, Ordering::SeqCst);
        self.storage.put(key, value)
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.get_count
            .fetch_add(1, Ordering::SeqCst);
        self.storage.get(key)
    }

    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.take_count
            .fetch_add(1, Ordering::SeqCst);
        self.storage.take(key)
    }

    fn can_cache(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // complete mock, but not 100% used in tests
enum ClientStorageOp {
    SetKxHint(ServerName<'static>, rustls::NamedGroup),
    GetKxHint(ServerName<'static>, Option<rustls::NamedGroup>),
    SetTls12Session(ServerName<'static>),
    GetTls12Session(ServerName<'static>, bool),
    RemoveTls12Session(ServerName<'static>),
    InsertTls13Ticket(ServerName<'static>),
    TakeTls13Ticket(ServerName<'static>, bool),
}

struct ClientStorage {
    storage: Arc<dyn rustls::client::ClientSessionStore>,
    ops: Mutex<Vec<ClientStorageOp>>,
}

impl ClientStorage {
    fn new() -> Self {
        Self {
            storage: Arc::new(rustls::client::ClientSessionMemoryCache::new(1024)),
            ops: Mutex::new(Vec::new()),
        }
    }

    #[cfg(feature = "tls12")]
    fn ops(&self) -> Vec<ClientStorageOp> {
        self.ops.lock().unwrap().clone()
    }

    #[cfg(feature = "tls12")]
    fn ops_and_reset(&self) -> Vec<ClientStorageOp> {
        std::mem::take(&mut self.ops.lock().unwrap())
    }
}

impl fmt::Debug for ClientStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(ops: {:?})", self.ops.lock().unwrap())
    }
}

impl rustls::client::ClientSessionStore for ClientStorage {

    fn set_kx_hint(&self, server_name: ServerName<'static>, group: rustls::NamedGroup) {
        self.ops
            .lock()
            .unwrap()
            .push(ClientStorageOp::SetKxHint(server_name.clone(), group));
        self.storage
            .set_kx_hint(server_name, group)
    }


    fn kx_hint(&self, server_name: &ServerName<'_>) -> Option<rustls::NamedGroup> {
        let rc = self.storage.kx_hint(server_name);
        self.ops
            .lock()
            .unwrap()
            .push(ClientStorageOp::GetKxHint(server_name.to_owned(), rc));
        rc
    }

    fn set_tls12_session(
        &self,

        server_name: ServerName<'static>,
        value: rustls::client::Tls12ClientSessionValue,
    ) {
        self.ops
            .lock()
            .unwrap()
            .push(ClientStorageOp::SetTls12Session(server_name.clone()));
        self.storage
            .set_tls12_session(server_name, value)
    }

    fn tls12_session(
        &self,
        server_name: &ServerName<'_>,
    ) -> Option<rustls::client::Tls12ClientSessionValue> {
        let rc = self.storage.tls12_session(server_name);
        self.ops
            .lock()
            .unwrap()
            .push(ClientStorageOp::GetTls12Session(
                server_name.to_owned(),
                rc.is_some(),
            ));
        rc
    }


    fn remove_tls12_session(&self, server_name: &ServerName<'static>) {
        self.ops
            .lock()
            .unwrap()
            .push(ClientStorageOp::RemoveTls12Session(server_name.clone()));
        self.storage
            .remove_tls12_session(server_name);
    }

    fn insert_tls13_ticket(
        &self,
        server_name: ServerName<'static>,
        value: rustls::client::Tls13ClientSessionValue,
    ) {
        self.ops
            .lock()
            .unwrap()
            .push(ClientStorageOp::InsertTls13Ticket(server_name.clone()));
        self.storage
            .insert_tls13_ticket(server_name, value);
    }

    fn take_tls13_ticket(
        &self,
        server_name: &ServerName<'static>,
    ) -> Option<rustls::client::Tls13ClientSessionValue> {
        let rc = self
            .storage
            .take_tls13_ticket(server_name);
        self.ops
            .lock()
            .unwrap()
            .push(ClientStorageOp::TakeTls13Ticket(
                server_name.clone(),
                rc.is_some(),
            ));
        rc
    }
}

#[test]
fn tls13_stateful_resumption() {
    let kt = KeyType::Rsa;
    let client_config = make_client_config_with_versions(kt, &[&rustls::version::TLS13]);
    let client_config = Arc::new(client_config);

    let mut server_config = make_server_config(kt);
    let storage = Arc::new(ServerStorage::new());
    server_config.session_storage = storage.clone();
    let server_config = Arc::new(server_config);

    // full handshake
    let (mut client, mut server, mut recv_srv, mut recv_clnt) = make_pair_for_arc_configs(&client_config, &server_config);
    let (full_c2s, full_s2c) = do_handshake(&mut client, &mut server, &mut recv_srv, &mut recv_clnt);
    assert_eq!(storage.puts(), 4);
    assert_eq!(storage.gets(), 0);
    assert_eq!(storage.takes(), 0);
    assert_eq!(
        client
            .peer_certificates()
            .map(|certs| certs.len()),
        Some(3)
    );

    // resumed
    let (mut client, mut server, mut recv_srv, mut recv_clnt) = make_pair_for_arc_configs(&client_config, &server_config);
    let (resume_c2s, resume_s2c) = do_handshake(&mut client, &mut server, &mut recv_srv, &mut recv_clnt);
    assert!(resume_c2s > full_c2s);
    assert!(resume_s2c < full_s2c);
    assert_eq!(storage.puts(), 8);
    assert_eq!(storage.gets(), 0);
    assert_eq!(storage.takes(), 1);
    assert_eq!(
        client
            .peer_certificates()
            .map(|certs| certs.len()),
        Some(3)
    );

    // resumed again
    let (mut client, mut server, mut recv_srv, mut recv_clnt) = make_pair_for_arc_configs(&client_config, &server_config);
    let (resume2_c2s, resume2_s2c) = do_handshake(&mut client, &mut server, &mut recv_srv, &mut recv_clnt);
    assert_eq!(resume_s2c, resume2_s2c);
    assert_eq!(resume_c2s, resume2_c2s);
    assert_eq!(storage.puts(), 12);
    assert_eq!(storage.gets(), 0);
    assert_eq!(storage.takes(), 2);
    assert_eq!(
        client
            .peer_certificates()
            .map(|certs| certs.len()),
        Some(3)
    );
}

#[test]
fn tls13_stateless_resumption() {
    let kt = KeyType::Rsa;
    let client_config = make_client_config_with_versions(kt, &[&rustls::version::TLS13]);
    let client_config = Arc::new(client_config);

    let mut server_config = make_server_config(kt);
    server_config.ticketer = provider::Ticketer::new().unwrap();
    let storage = Arc::new(ServerStorage::new());
    server_config.session_storage = storage.clone();
    let server_config = Arc::new(server_config);

    // full handshake
    let (mut client, mut server, mut recv_srv, mut recv_clnt) = make_pair_for_arc_configs(&client_config, &server_config);
    let (full_c2s, full_s2c) = do_handshake(&mut client, &mut server, &mut recv_srv, &mut recv_clnt);
    assert_eq!(storage.puts(), 0);
    assert_eq!(storage.gets(), 0);
    assert_eq!(storage.takes(), 0);
    assert_eq!(
        client
            .peer_certificates()
            .map(|certs| certs.len()),
        Some(3)
    );

    // resumed
    let (mut client, mut server, mut recv_srv, mut recv_clnt) = make_pair_for_arc_configs(&client_config, &server_config);
    let (resume_c2s, resume_s2c) = do_handshake(&mut client, &mut server, &mut recv_srv, &mut recv_clnt);
    assert!(resume_c2s > full_c2s);
    assert!(resume_s2c < full_s2c);
    assert_eq!(storage.puts(), 0);
    assert_eq!(storage.gets(), 0);
    assert_eq!(storage.takes(), 0);
    assert_eq!(
        client
            .peer_certificates()
            .map(|certs| certs.len()),
        Some(3)
    );

    // resumed again
    let (mut client, mut server, mut recv_srv, mut recv_clnt) = make_pair_for_arc_configs(&client_config, &server_config);
    let (resume2_c2s, resume2_s2c) = do_handshake(&mut client, &mut server, &mut recv_srv, &mut recv_clnt);
    assert_eq!(resume_s2c, resume2_s2c);
    assert_eq!(resume_c2s, resume2_c2s);
    assert_eq!(storage.puts(), 0);
    assert_eq!(storage.gets(), 0);
    assert_eq!(storage.takes(), 0);
    assert_eq!(
        client
            .peer_certificates()
            .map(|certs| certs.len()),
        Some(3)
    );
}

#[test]
fn early_data_not_available() {
    let (mut client, _,  _recv_srv,  _recv_clnt) = make_pair(KeyType::Rsa);
    assert!(client.early_data().is_none());
}

fn early_data_configs() -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let kt = KeyType::Rsa;
    let mut client_config = make_client_config(kt);
    client_config.enable_early_data = true;
    client_config.resumption = Resumption::store(Arc::new(ClientStorage::new()));

    let mut server_config = make_server_config(kt);
    server_config.max_early_data_size = 1234;
    (Arc::new(client_config), Arc::new(server_config))
}



#[test]
fn early_data_not_available_on_server_before_client_hello() {
    let mut server = ServerConnection::new(Arc::new(make_server_config(KeyType::Rsa))).unwrap();
    assert!(server.early_data().is_none());
}

#[test]
fn early_data_can_be_rejected_by_server() {
    let (client_config, server_config) = early_data_configs();

    let (mut client, mut server, mut recv_srv, mut recv_clnt) = make_pair_for_arc_configs(&client_config, &server_config);
    do_handshake(&mut client, &mut server, &mut recv_srv, &mut recv_clnt);

    let (mut client, mut server, mut recv_srv, mut recv_clnt) = make_pair_for_arc_configs(&client_config, &server_config);
    assert!(client.early_data().is_some());
    assert_eq!(
        client
            .early_data()
            .unwrap()
            .bytes_left(),
        1234
    );
    client
        .early_data()
        .unwrap()
        .flush()
        .unwrap();
    assert_eq!(
        client
            .early_data()
            .unwrap()
            .write(b"hello")
            .unwrap(),
        5
    );
    server.reject_early_data();

    do_handshake(&mut client, &mut server, &mut recv_srv, &mut recv_clnt);

    assert!(!client.is_early_data_accepted());
}


/*mod test_quic {
    use super::*;
    use rustls::quic::{self, ConnectionCommon};

    // Returns the sender's next secrets to use, or the receiver's error.
    fn step<L: SideData, R: SideData>(
        send: &mut ConnectionCommon<L>,
        recv: &mut ConnectionCommon<R>,
    ) -> Result<Option<quic::KeyChange>, Error> {
        let mut buf = Vec::new();
        let change = loop {
            let prev = buf.len();
            if let Some(x) = send.write_hs(&mut buf) {
                break Some(x);
            }
            if prev == buf.len() {
                break None;
            }
        };
        if let Err(e) = recv.read_hs(&buf) {
            return Err(e);
        } else {
            assert_eq!(recv.alert(), None);
        }

        Ok(change)
    }

    #[test]
    #[ignore]
    fn test_quic_handshake() {

        fn equal_packet_keys(x: &dyn quic::PacketKey, y: &dyn quic::PacketKey) -> bool {
            // Check that these two sets of keys are equal.
            let mut buf = [0; 32];
            let (header, payload_tag) = buf.split_at_mut(8);
            let (payload, tag_buf) = payload_tag.split_at_mut(8);
            let tag = x
                .encrypt_in_place(42, header, payload)
                .unwrap();
            tag_buf.copy_from_slice(tag.as_ref());

            let result = y.decrypt_in_place(42, header, payload_tag);
            match result {
                Ok(payload) => payload == [0; 8],
                Err(_) => false,
            }
        }

        fn compatible_keys(x: &quic::KeyChange, y: &quic::KeyChange) -> bool {
            fn keys(kc: &quic::KeyChange) -> &quic::Keys {
                match kc {
                    quic::KeyChange::Handshake { keys } => keys,
                    quic::KeyChange::OneRtt { keys, .. } => keys,
                }
            }

            let (x, y) = (keys(x), keys(y));

            equal_packet_keys(x.local.packet.as_ref(), y.remote.packet.as_ref())
                && equal_packet_keys(x.remote.packet.as_ref(), y.local.packet.as_ref())
        }

        let kt = KeyType::Rsa;
        let mut client_config = make_client_config_with_versions(kt, &[&rustls::version::TLS13]);
        client_config.enable_early_data = true;
        let client_config = Arc::new(client_config);
        let mut server_config = make_server_config_with_versions(kt, &[&rustls::version::TLS13]);
        server_config.max_early_data_size = 0xffffffff;
        let server_config = Arc::new(server_config);
        let client_params = &b"client params"[..];
        let server_params = &b"server params"[..];

        // full handshake
        let mut client = quic::ClientConnection::new(
            Arc::clone(&client_config),
            quic::Version::V1,

            server_name("localhost"),
            client_params.into(),
        )
        .unwrap();

        let mut server = quic::ServerConnection::new(
            Arc::clone(&server_config),
            quic::Version::V1,
            server_params.into(),
        )
        .unwrap();

        let client_initial = step(&mut client, &mut server).unwrap();
        assert!(client_initial.is_none());
        assert!(client.zero_rtt_keys().is_none());
        assert_eq!(server.quic_transport_parameters(), Some(client_params));
        let server_hs = step(&mut server, &mut client)
            .unwrap()
            .unwrap();
        assert!(server.zero_rtt_keys().is_none());
        let client_hs = step(&mut client, &mut server)
            .unwrap()
            .unwrap();
        assert!(compatible_keys(&server_hs, &client_hs));
        assert!(client.is_handshaking());
        let server_1rtt = step(&mut server, &mut client)
            .unwrap()
            .unwrap();
        assert!(!client.is_handshaking());
        assert_eq!(client.quic_transport_parameters(), Some(server_params));
        assert!(server.is_handshaking());
        let client_1rtt = step(&mut client, &mut server)
            .unwrap()
            .unwrap();
        assert!(!server.is_handshaking());
        assert!(compatible_keys(&server_1rtt, &client_1rtt));
        assert!(!compatible_keys(&server_hs, &server_1rtt));
        assert!(step(&mut client, &mut server)
            .unwrap()
            .is_none());
        assert!(step(&mut server, &mut client)
            .unwrap()
            .is_none());

        // 0-RTT handshake
        let mut client = quic::ClientConnection::new(
            Arc::clone(&client_config),
            quic::Version::V1,

            server_name("localhost"),
            client_params.into(),
        )
        .unwrap();
        assert!(client
            .negotiated_cipher_suite()
            .is_some());

        let mut server = quic::ServerConnection::new(
            Arc::clone(&server_config),
            quic::Version::V1,
            server_params.into(),
        )
        .unwrap();

        step(&mut client, &mut server).unwrap();
        assert_eq!(client.quic_transport_parameters(), Some(server_params));
        {
            let client_early = client.zero_rtt_keys().unwrap();
            let server_early = server.zero_rtt_keys().unwrap();
            assert!(equal_packet_keys(

                client_early.packet.as_ref(),
                server_early.packet.as_ref()
            ));
        }
        step(&mut server, &mut client)
            .unwrap()
            .unwrap();
        step(&mut client, &mut server)
            .unwrap()
            .unwrap();
        step(&mut server, &mut client)
            .unwrap()
            .unwrap();
        assert!(client.is_early_data_accepted());

        // 0-RTT rejection
        {
            let client_config = (*client_config).clone();
            let mut client = quic::ClientConnection::new(
                Arc::new(client_config),
                quic::Version::V1,
                server_name("localhost"),
                client_params.into(),
            )
            .unwrap();

            let mut server = quic::ServerConnection::new(
                Arc::clone(&server_config),
                quic::Version::V1,
                server_params.into(),
            )
            .unwrap();
            server.reject_early_data();

            step(&mut client, &mut server).unwrap();
            assert_eq!(client.quic_transport_parameters(), Some(server_params));
            assert!(client.zero_rtt_keys().is_some());
            assert!(server.zero_rtt_keys().is_none());
            step(&mut server, &mut client)
                .unwrap()
                .unwrap();
            step(&mut client, &mut server)
                .unwrap()
                .unwrap();
            step(&mut server, &mut client)
                .unwrap()
                .unwrap();
            assert!(!client.is_early_data_accepted());
        }

        // failed handshake
        let mut client = quic::ClientConnection::new(
            client_config,
            quic::Version::V1,
            server_name("example.com"),
            client_params.into(),
        )
        .unwrap();

        let mut server =
            quic::ServerConnection::new(server_config, quic::Version::V1, server_params.into())
                .unwrap();

        step(&mut client, &mut server).unwrap();
        step(&mut server, &mut client)
            .unwrap()
            .unwrap();
        assert!(step(&mut server, &mut client).is_err());
        assert_eq!(
            client.alert(),
            Some(rustls::AlertDescription::BadCertificate)
        );

        // Key updates

        let (mut client_secrets, mut server_secrets) = match (client_1rtt, server_1rtt) {
            (quic::KeyChange::OneRtt { next: c, .. }, quic::KeyChange::OneRtt { next: s, .. }) => {
                (c, s)
            }
            _ => unreachable!(),
        };

        let mut client_next = client_secrets.next_packet_keys();
        let mut server_next = server_secrets.next_packet_keys();

        assert!(equal_packet_keys(
            client_next.local.as_ref(),
            server_next.remote.as_ref()
        ));
        assert!(equal_packet_keys(
            server_next.local.as_ref(),
            client_next.remote.as_ref()
        ));

        client_next = client_secrets.next_packet_keys();
        server_next = server_secrets.next_packet_keys();
        assert!(equal_packet_keys(
            client_next.local.as_ref(),
            server_next.remote.as_ref()
        ));
        assert!(equal_packet_keys(
            server_next.local.as_ref(),
            client_next.remote.as_ref()
        ));
    }

    #[test]
    #[ignore]
    fn test_quic_rejects_missing_alpn() {
        let client_params = &b"client params"[..];
        let server_params = &b"server params"[..];
        for &kt in ALL_KEY_TYPES {
            let client_config = make_client_config_with_versions(kt, &[&rustls::version::TLS13]);
            let client_config = Arc::new(client_config);

            let mut server_config =
                make_server_config_with_versions(kt, &[&rustls::version::TLS13]);
            server_config.alpn_protocols = vec!["foo".into()];
            let server_config = Arc::new(server_config);

            let mut client = quic::ClientConnection::new(
                client_config,
                quic::Version::V1,
                server_name("localhost"),
                client_params.into(),
            )
            .unwrap();
            let mut server =
                quic::ServerConnection::new(server_config, quic::Version::V1, server_params.into())
                    .unwrap();

            assert_eq!(
                step(&mut client, &mut server)
                    .err()
                    .unwrap(),
                Error::NoApplicationProtocol
            );

            assert_eq!(
                server.alert(),
                Some(rustls::AlertDescription::NoApplicationProtocol)
            );
        }
    }

    #[cfg(feature = "tls12")]
    #[test]
    #[ignore]
    fn test_quic_no_tls13_error() {
        let mut client_config =
            make_client_config_with_versions(KeyType::Ed25519, &[&rustls::version::TLS12]);
        client_config.alpn_protocols = vec!["foo".into()];
        let client_config = Arc::new(client_config);

        assert!(quic::ClientConnection::new(
            client_config,
            quic::Version::V1,
            server_name("localhost"),
            b"client params".to_vec(),
        )
        .is_err());

        let mut server_config =
            make_server_config_with_versions(KeyType::Ed25519, &[&rustls::version::TLS12]);
        server_config.alpn_protocols = vec!["foo".into()];
        let server_config = Arc::new(server_config);

        assert!(quic::ServerConnection::new(
            server_config,
            quic::Version::V1,
            b"server params".to_vec(),
        )
        .is_err());
    }

    #[test]
    #[ignore]
    fn test_quic_invalid_early_data_size() {
        let mut server_config =
            make_server_config_with_versions(KeyType::Ed25519, &[&rustls::version::TLS13]);
        server_config.alpn_protocols = vec!["foo".into()];

        let cases = [
            (None, true),
            (Some(0u32), true),
            (Some(5), false),
            (Some(0xffff_ffff), true),
        ];

        for &(size, ok) in cases.iter() {
            println!("early data size case: {:?}", size);
            if let Some(new) = size {
                server_config.max_early_data_size = new;
            }

            let wrapped = Arc::new(server_config.clone());
            assert_eq!(
                quic::ServerConnection::new(wrapped, quic::Version::V1, b"server params".to_vec(),)
                    .is_ok(),
                ok
            );
        }
    }

    #[test]
    #[cfg(feature = "ring")] // uses ring APIs directly
    #[ignore]
    fn test_quic_server_no_params_received() {
        let server_config =
            make_server_config_with_versions(KeyType::Ed25519, &[&rustls::version::TLS13]);
        let server_config = Arc::new(server_config);

        let mut server = quic::ServerConnection::new(
            server_config,
            quic::Version::V1,
            b"server params".to_vec(),
        )
        .unwrap();
            use rustls::internal::msgs::enums::{Compression, NamedGroup};
        use rustls::internal::msgs::handshake::{
            ClientHelloPayload, HandshakeMessagePayload, KeyShareEntry, Random, SessionId,
        };
        use rustls::{CipherSuite, HandshakeType, SignatureScheme};
        let provider = provider::default_provider();
        let mut random = [0; 32];
        provider
            .secure_random
            .fill(&mut random)
            .unwrap();
        let random = Random::from(random);

        let rng = ring::rand::SystemRandom::new();
        let kx = ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::X25519, &rng)
            .unwrap()
            .compute_public_key()
            .unwrap();

        let client_hello = MessagePayload::handshake(HandshakeMessagePayload {
            typ: HandshakeType::ClientHello,
            payload: HandshakePayload::ClientHello(ClientHelloPayload {
                client_version: ProtocolVersion::TLSv1_3,
                random,
                session_id: SessionId::random(provider.secure_random).unwrap(),
                cipher_suites: vec![CipherSuite::TLS13_AES_128_GCM_SHA256],
                compression_methods: vec![Compression::Null],
                extensions: vec![
                    ClientExtension::SupportedVersions(vec![ProtocolVersion::TLSv1_3]),
                    ClientExtension::NamedGroups(vec![NamedGroup::X25519]),
                    ClientExtension::SignatureAlgorithms(vec![SignatureScheme::ED25519]),

                    ClientExtension::KeyShare(vec![KeyShareEntry::new(
                        NamedGroup::X25519,
                        kx.as_ref(),
                    )]),
                ],
            }),
        });

        let mut buf = Vec::with_capacity(512);
        client_hello.encode(&mut buf);
        assert_eq!(

            server.read_hs(buf.as_slice()).err(),
            Some(Error::PeerMisbehaved(
                PeerMisbehaved::MissingQuicTransportParameters
            ))
        );
    }

    #[test]
    #[cfg(feature = "ring")] // uses ring APIs directly
    #[ignore]
    fn test_quic_server_no_tls12() {
        let mut server_config =
            make_server_config_with_versions(KeyType::Ed25519, &[&rustls::version::TLS13]);
        server_config.alpn_protocols = vec!["foo".into()];
        let server_config = Arc::new(server_config);
            use rustls::internal::msgs::enums::{Compression, NamedGroup};
        use rustls::internal::msgs::handshake::{
            ClientHelloPayload, HandshakeMessagePayload, KeyShareEntry, Random, SessionId,
        };
        use rustls::{CipherSuite, HandshakeType, SignatureScheme};

        let provider = provider::default_provider();
        let mut random = [0; 32];
        provider
            .secure_random
            .fill(&mut random)
            .unwrap();
        let random = Random::from(random);

        let rng = ring::rand::SystemRandom::new();
        let kx = ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::X25519, &rng)
            .unwrap()
            .compute_public_key()
            .unwrap();

        let mut server = quic::ServerConnection::new(
            server_config,
            quic::Version::V1,
            b"server params".to_vec(),
        )
        .unwrap();

        let client_hello = MessagePayload::handshake(HandshakeMessagePayload {
            typ: HandshakeType::ClientHello,
            payload: HandshakePayload::ClientHello(ClientHelloPayload {
                client_version: ProtocolVersion::TLSv1_2,
                random,
                session_id: SessionId::random(provider.secure_random).unwrap(),
                cipher_suites: vec![CipherSuite::TLS13_AES_128_GCM_SHA256],
                compression_methods: vec![Compression::Null],
                extensions: vec![
                    ClientExtension::NamedGroups(vec![NamedGroup::X25519]),
                    ClientExtension::SignatureAlgorithms(vec![SignatureScheme::ED25519]),
                    ClientExtension::KeyShare(vec![KeyShareEntry::new(
                        NamedGroup::X25519,
                        kx.as_ref(),
                    )]),
                ],
            }),
        });

        let mut buf = Vec::with_capacity(512);
        client_hello.encode(&mut buf);
        assert_eq!(

            server.read_hs(buf.as_slice()).err(),
            Some(Error::PeerIncompatible(
                PeerIncompatible::SupportedVersionsExtensionRequired
            )),
        );
    }

    #[test]
    #[ignore]
    fn packet_key_api() {

        use cipher_suite::TLS13_AES_128_GCM_SHA256;
        use rustls::quic::{Keys, Version};
        use rustls::Side;

        // Test vectors: https://www.rfc-editor.org/rfc/rfc9001.html#name-client-initial
        const CONNECTION_ID: &[u8] = &[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        const PACKET_NUMBER: u64 = 2;
        const PLAIN_HEADER: &[u8] = &[
            0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,
            0x00, 0x00, 0x44, 0x9e, 0x00, 0x00, 0x00, 0x02,
        ];

        const PAYLOAD: &[u8] = &[
            0x06, 0x00, 0x40, 0xf1, 0x01, 0x00, 0x00, 0xed, 0x03, 0x03, 0xeb, 0xf8, 0xfa, 0x56,
            0xf1, 0x29, 0x39, 0xb9, 0x58, 0x4a, 0x38, 0x96, 0x47, 0x2e, 0xc4, 0x0b, 0xb8, 0x63,
            0xcf, 0xd3, 0xe8, 0x68, 0x04, 0xfe, 0x3a, 0x47, 0xf0, 0x6a, 0x2b, 0x69, 0x48, 0x4c,
            0x00, 0x00, 0x04, 0x13, 0x01, 0x13, 0x02, 0x01, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00,
            0x10, 0x00, 0x0e, 0x00, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e,
            0x63, 0x6f, 0x6d, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x06,
            0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x10, 0x00, 0x07, 0x00, 0x05, 0x04, 0x61,
            0x6c, 0x70, 0x6e, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33,
            0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x93, 0x70, 0xb2, 0xc9, 0xca, 0xa4,
            0x7f, 0xba, 0xba, 0xf4, 0x55, 0x9f, 0xed, 0xba, 0x75, 0x3d, 0xe1, 0x71, 0xfa, 0x71,
            0xf5, 0x0f, 0x1c, 0xe1, 0x5d, 0x43, 0xe9, 0x94, 0xec, 0x74, 0xd7, 0x48, 0x00, 0x2b,
            0x00, 0x03, 0x02, 0x03, 0x04, 0x00, 0x0d, 0x00, 0x10, 0x00, 0x0e, 0x04, 0x03, 0x05,
            0x03, 0x06, 0x03, 0x02, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x00, 0x2d, 0x00,
            0x02, 0x01, 0x01, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01, 0x00, 0x39, 0x00, 0x32, 0x04,
            0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x05, 0x04, 0x80, 0x00, 0xff,
            0xff, 0x07, 0x04, 0x80, 0x00, 0xff, 0xff, 0x08, 0x01, 0x10, 0x01, 0x04, 0x80, 0x00,
            0x75, 0x30, 0x09, 0x01, 0x10, 0x0f, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57,
            0x08, 0x06, 0x04, 0x80, 0x00, 0xff, 0xff,
        ];


        let client_keys = Keys::initial(
            Version::V1,
            TLS13_AES_128_GCM_SHA256
                .tls13()
                .unwrap(),
            TLS13_AES_128_GCM_SHA256
                .tls13()
                .unwrap()
                .quic
                .unwrap(),
            CONNECTION_ID,
            Side::Client,
        );
        assert_eq!(client_keys.local.packet.tag_len(), 16);

        let mut buf = Vec::new();
        buf.extend(PLAIN_HEADER);
        buf.extend(PAYLOAD);
        let header_len = PLAIN_HEADER.len();
        let tag_len = client_keys.local.packet.tag_len();
        let padding_len = 1200 - header_len - PAYLOAD.len() - tag_len;
        buf.extend(std::iter::repeat(0).take(padding_len));
        let (header, payload) = buf.split_at_mut(header_len);
        let tag = client_keys
            .local
            .packet

            .encrypt_in_place(PACKET_NUMBER, header, payload)
            .unwrap();

        let sample_len = client_keys.local.header.sample_len();
        let sample = &payload[..sample_len];
        let (first, rest) = header.split_at_mut(1);
        client_keys
            .local
            .header
            .encrypt_in_place(sample, &mut first[0], &mut rest[17..21])
            .unwrap();
        buf.extend_from_slice(tag.as_ref());

        const PROTECTED: &[u8] = &[
            0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,
            0x00, 0x00, 0x44, 0x9e, 0x7b, 0x9a, 0xec, 0x34, 0xd1, 0xb1, 0xc9, 0x8d, 0xd7, 0x68,
            0x9f, 0xb8, 0xec, 0x11, 0xd2, 0x42, 0xb1, 0x23, 0xdc, 0x9b, 0xd8, 0xba, 0xb9, 0x36,
            0xb4, 0x7d, 0x92, 0xec, 0x35, 0x6c, 0x0b, 0xab, 0x7d, 0xf5, 0x97, 0x6d, 0x27, 0xcd,
            0x44, 0x9f, 0x63, 0x30, 0x00, 0x99, 0xf3, 0x99, 0x1c, 0x26, 0x0e, 0xc4, 0xc6, 0x0d,
            0x17, 0xb3, 0x1f, 0x84, 0x29, 0x15, 0x7b, 0xb3, 0x5a, 0x12, 0x82, 0xa6, 0x43, 0xa8,
            0xd2, 0x26, 0x2c, 0xad, 0x67, 0x50, 0x0c, 0xad, 0xb8, 0xe7, 0x37, 0x8c, 0x8e, 0xb7,
            0x53, 0x9e, 0xc4, 0xd4, 0x90, 0x5f, 0xed, 0x1b, 0xee, 0x1f, 0xc8, 0xaa, 0xfb, 0xa1,
            0x7c, 0x75, 0x0e, 0x2c, 0x7a, 0xce, 0x01, 0xe6, 0x00, 0x5f, 0x80, 0xfc, 0xb7, 0xdf,
            0x62, 0x12, 0x30, 0xc8, 0x37, 0x11, 0xb3, 0x93, 0x43, 0xfa, 0x02, 0x8c, 0xea, 0x7f,
            0x7f, 0xb5, 0xff, 0x89, 0xea, 0xc2, 0x30, 0x82, 0x49, 0xa0, 0x22, 0x52, 0x15, 0x5e,
            0x23, 0x47, 0xb6, 0x3d, 0x58, 0xc5, 0x45, 0x7a, 0xfd, 0x84, 0xd0, 0x5d, 0xff, 0xfd,
            0xb2, 0x03, 0x92, 0x84, 0x4a, 0xe8, 0x12, 0x15, 0x46, 0x82, 0xe9, 0xcf, 0x01, 0x2f,
            0x90, 0x21, 0xa6, 0xf0, 0xbe, 0x17, 0xdd, 0xd0, 0xc2, 0x08, 0x4d, 0xce, 0x25, 0xff,
            0x9b, 0x06, 0xcd, 0xe5, 0x35, 0xd0, 0xf9, 0x20, 0xa2, 0xdb, 0x1b, 0xf3, 0x62, 0xc2,
            0x3e, 0x59, 0x6d, 0x11, 0xa4, 0xf5, 0xa6, 0xcf, 0x39, 0x48, 0x83, 0x8a, 0x3a, 0xec,
            0x4e, 0x15, 0xda, 0xf8, 0x50, 0x0a, 0x6e, 0xf6, 0x9e, 0xc4, 0xe3, 0xfe, 0xb6, 0xb1,
            0xd9, 0x8e, 0x61, 0x0a, 0xc8, 0xb7, 0xec, 0x3f, 0xaf, 0x6a, 0xd7, 0x60, 0xb7, 0xba,
            0xd1, 0xdb, 0x4b, 0xa3, 0x48, 0x5e, 0x8a, 0x94, 0xdc, 0x25, 0x0a, 0xe3, 0xfd, 0xb4,
            0x1e, 0xd1, 0x5f, 0xb6, 0xa8, 0xe5, 0xeb, 0xa0, 0xfc, 0x3d, 0xd6, 0x0b, 0xc8, 0xe3,
            0x0c, 0x5c, 0x42, 0x87, 0xe5, 0x38, 0x05, 0xdb, 0x05, 0x9a, 0xe0, 0x64, 0x8d, 0xb2,
            0xf6, 0x42, 0x64, 0xed, 0x5e, 0x39, 0xbe, 0x2e, 0x20, 0xd8, 0x2d, 0xf5, 0x66, 0xda,
            0x8d, 0xd5, 0x99, 0x8c, 0xca, 0xbd, 0xae, 0x05, 0x30, 0x60, 0xae, 0x6c, 0x7b, 0x43,
            0x78, 0xe8, 0x46, 0xd2, 0x9f, 0x37, 0xed, 0x7b, 0x4e, 0xa9, 0xec, 0x5d, 0x82, 0xe7,
            0x96, 0x1b, 0x7f, 0x25, 0xa9, 0x32, 0x38, 0x51, 0xf6, 0x81, 0xd5, 0x82, 0x36, 0x3a,
            0xa5, 0xf8, 0x99, 0x37, 0xf5, 0xa6, 0x72, 0x58, 0xbf, 0x63, 0xad, 0x6f, 0x1a, 0x0b,
            0x1d, 0x96, 0xdb, 0xd4, 0xfa, 0xdd, 0xfc, 0xef, 0xc5, 0x26, 0x6b, 0xa6, 0x61, 0x17,
            0x22, 0x39, 0x5c, 0x90, 0x65, 0x56, 0xbe, 0x52, 0xaf, 0xe3, 0xf5, 0x65, 0x63, 0x6a,
            0xd1, 0xb1, 0x7d, 0x50, 0x8b, 0x73, 0xd8, 0x74, 0x3e, 0xeb, 0x52, 0x4b, 0xe2, 0x2b,
            0x3d, 0xcb, 0xc2, 0xc7, 0x46, 0x8d, 0x54, 0x11, 0x9c, 0x74, 0x68, 0x44, 0x9a, 0x13,
            0xd8, 0xe3, 0xb9, 0x58, 0x11, 0xa1, 0x98, 0xf3, 0x49, 0x1d, 0xe3, 0xe7, 0xfe, 0x94,
            0x2b, 0x33, 0x04, 0x07, 0xab, 0xf8, 0x2a, 0x4e, 0xd7, 0xc1, 0xb3, 0x11, 0x66, 0x3a,
            0xc6, 0x98, 0x90, 0xf4, 0x15, 0x70, 0x15, 0x85, 0x3d, 0x91, 0xe9, 0x23, 0x03, 0x7c,
            0x22, 0x7a, 0x33, 0xcd, 0xd5, 0xec, 0x28, 0x1c, 0xa3, 0xf7, 0x9c, 0x44, 0x54, 0x6b,
            0x9d, 0x90, 0xca, 0x00, 0xf0, 0x64, 0xc9, 0x9e, 0x3d, 0xd9, 0x79, 0x11, 0xd3, 0x9f,
            0xe9, 0xc5, 0xd0, 0xb2, 0x3a, 0x22, 0x9a, 0x23, 0x4c, 0xb3, 0x61, 0x86, 0xc4, 0x81,
            0x9e, 0x8b, 0x9c, 0x59, 0x27, 0x72, 0x66, 0x32, 0x29, 0x1d, 0x6a, 0x41, 0x82, 0x11,
            0xcc, 0x29, 0x62, 0xe2, 0x0f, 0xe4, 0x7f, 0xeb, 0x3e, 0xdf, 0x33, 0x0f, 0x2c, 0x60,
            0x3a, 0x9d, 0x48, 0xc0, 0xfc, 0xb5, 0x69, 0x9d, 0xbf, 0xe5, 0x89, 0x64, 0x25, 0xc5,
            0xba, 0xc4, 0xae, 0xe8, 0x2e, 0x57, 0xa8, 0x5a, 0xaf, 0x4e, 0x25, 0x13, 0xe4, 0xf0,
            0x57, 0x96, 0xb0, 0x7b, 0xa2, 0xee, 0x47, 0xd8, 0x05, 0x06, 0xf8, 0xd2, 0xc2, 0x5e,
            0x50, 0xfd, 0x14, 0xde, 0x71, 0xe6, 0xc4, 0x18, 0x55, 0x93, 0x02, 0xf9, 0x39, 0xb0,
            0xe1, 0xab, 0xd5, 0x76, 0xf2, 0x79, 0xc4, 0xb2, 0xe0, 0xfe, 0xb8, 0x5c, 0x1f, 0x28,
            0xff, 0x18, 0xf5, 0x88, 0x91, 0xff, 0xef, 0x13, 0x2e, 0xef, 0x2f, 0xa0, 0x93, 0x46,
            0xae, 0xe3, 0x3c, 0x28, 0xeb, 0x13, 0x0f, 0xf2, 0x8f, 0x5b, 0x76, 0x69, 0x53, 0x33,
            0x41, 0x13, 0x21, 0x19, 0x96, 0xd2, 0x00, 0x11, 0xa1, 0x98, 0xe3, 0xfc, 0x43, 0x3f,
            0x9f, 0x25, 0x41, 0x01, 0x0a, 0xe1, 0x7c, 0x1b, 0xf2, 0x02, 0x58, 0x0f, 0x60, 0x47,
            0x47, 0x2f, 0xb3, 0x68, 0x57, 0xfe, 0x84, 0x3b, 0x19, 0xf5, 0x98, 0x40, 0x09, 0xdd,
            0xc3, 0x24, 0x04, 0x4e, 0x84, 0x7a, 0x4f, 0x4a, 0x0a, 0xb3, 0x4f, 0x71, 0x95, 0x95,
            0xde, 0x37, 0x25, 0x2d, 0x62, 0x35, 0x36, 0x5e, 0x9b, 0x84, 0x39, 0x2b, 0x06, 0x10,
            0x85, 0x34, 0x9d, 0x73, 0x20, 0x3a, 0x4a, 0x13, 0xe9, 0x6f, 0x54, 0x32, 0xec, 0x0f,
            0xd4, 0xa1, 0xee, 0x65, 0xac, 0xcd, 0xd5, 0xe3, 0x90, 0x4d, 0xf5, 0x4c, 0x1d, 0xa5,
            0x10, 0xb0, 0xff, 0x20, 0xdc, 0xc0, 0xc7, 0x7f, 0xcb, 0x2c, 0x0e, 0x0e, 0xb6, 0x05,
            0xcb, 0x05, 0x04, 0xdb, 0x87, 0x63, 0x2c, 0xf3, 0xd8, 0xb4, 0xda, 0xe6, 0xe7, 0x05,
            0x76, 0x9d, 0x1d, 0xe3, 0x54, 0x27, 0x01, 0x23, 0xcb, 0x11, 0x45, 0x0e, 0xfc, 0x60,
            0xac, 0x47, 0x68, 0x3d, 0x7b, 0x8d, 0x0f, 0x81, 0x13, 0x65, 0x56, 0x5f, 0xd9, 0x8c,
            0x4c, 0x8e, 0xb9, 0x36, 0xbc, 0xab, 0x8d, 0x06, 0x9f, 0xc3, 0x3b, 0xd8, 0x01, 0xb0,
            0x3a, 0xde, 0xa2, 0xe1, 0xfb, 0xc5, 0xaa, 0x46, 0x3d, 0x08, 0xca, 0x19, 0x89, 0x6d,
            0x2b, 0xf5, 0x9a, 0x07, 0x1b, 0x85, 0x1e, 0x6c, 0x23, 0x90, 0x52, 0x17, 0x2f, 0x29,
            0x6b, 0xfb, 0x5e, 0x72, 0x40, 0x47, 0x90, 0xa2, 0x18, 0x10, 0x14, 0xf3, 0xb9, 0x4a,
            0x4e, 0x97, 0xd1, 0x17, 0xb4, 0x38, 0x13, 0x03, 0x68, 0xcc, 0x39, 0xdb, 0xb2, 0xd1,
            0x98, 0x06, 0x5a, 0xe3, 0x98, 0x65, 0x47, 0x92, 0x6c, 0xd2, 0x16, 0x2f, 0x40, 0xa2,
            0x9f, 0x0c, 0x3c, 0x87, 0x45, 0xc0, 0xf5, 0x0f, 0xba, 0x38, 0x52, 0xe5, 0x66, 0xd4,
            0x45, 0x75, 0xc2, 0x9d, 0x39, 0xa0, 0x3f, 0x0c, 0xda, 0x72, 0x19, 0x84, 0xb6, 0xf4,
            0x40, 0x59, 0x1f, 0x35, 0x5e, 0x12, 0xd4, 0x39, 0xff, 0x15, 0x0a, 0xab, 0x76, 0x13,
            0x49, 0x9d, 0xbd, 0x49, 0xad, 0xab, 0xc8, 0x67, 0x6e, 0xef, 0x02, 0x3b, 0x15, 0xb6,
            0x5b, 0xfc, 0x5c, 0xa0, 0x69, 0x48, 0x10, 0x9f, 0x23, 0xf3, 0x50, 0xdb, 0x82, 0x12,
            0x35, 0x35, 0xeb, 0x8a, 0x74, 0x33, 0xbd, 0xab, 0xcb, 0x90, 0x92, 0x71, 0xa6, 0xec,
            0xbc, 0xb5, 0x8b, 0x93, 0x6a, 0x88, 0xcd, 0x4e, 0x8f, 0x2e, 0x6f, 0xf5, 0x80, 0x01,
            0x75, 0xf1, 0x13, 0x25, 0x3d, 0x8f, 0xa9, 0xca, 0x88, 0x85, 0xc2, 0xf5, 0x52, 0xe6,
            0x57, 0xdc, 0x60, 0x3f, 0x25, 0x2e, 0x1a, 0x8e, 0x30, 0x8f, 0x76, 0xf0, 0xbe, 0x79,
            0xe2, 0xfb, 0x8f, 0x5d, 0x5f, 0xbb, 0xe2, 0xe3, 0x0e, 0xca, 0xdd, 0x22, 0x07, 0x23,
            0xc8, 0xc0, 0xae, 0xa8, 0x07, 0x8c, 0xdf, 0xcb, 0x38, 0x68, 0x26, 0x3f, 0xf8, 0xf0,
            0x94, 0x00, 0x54, 0xda, 0x48, 0x78, 0x18, 0x93, 0xa7, 0xe4, 0x9a, 0xd5, 0xaf, 0xf4,
            0xaf, 0x30, 0x0c, 0xd8, 0x04, 0xa6, 0xb6, 0x27, 0x9a, 0xb3, 0xff, 0x3a, 0xfb, 0x64,
            0x49, 0x1c, 0x85, 0x19, 0x4a, 0xab, 0x76, 0x0d, 0x58, 0xa6, 0x06, 0x65, 0x4f, 0x9f,
            0x44, 0x00, 0xe8, 0xb3, 0x85, 0x91, 0x35, 0x6f, 0xbf, 0x64, 0x25, 0xac, 0xa2, 0x6d,
            0xc8, 0x52, 0x44, 0x25, 0x9f, 0xf2, 0xb1, 0x9c, 0x41, 0xb9, 0xf9, 0x6f, 0x3c, 0xa9,
            0xec, 0x1d, 0xde, 0x43, 0x4d, 0xa7, 0xd2, 0xd3, 0x92, 0xb9, 0x05, 0xdd, 0xf3, 0xd1,
            0xf9, 0xaf, 0x93, 0xd1, 0xaf, 0x59, 0x50, 0xbd, 0x49, 0x3f, 0x5a, 0xa7, 0x31, 0xb4,
            0x05, 0x6d, 0xf3, 0x1b, 0xd2, 0x67, 0xb6, 0xb9, 0x0a, 0x07, 0x98, 0x31, 0xaa, 0xf5,
            0x79, 0xbe, 0x0a, 0x39, 0x01, 0x31, 0x37, 0xaa, 0xc6, 0xd4, 0x04, 0xf5, 0x18, 0xcf,
            0xd4, 0x68, 0x40, 0x64, 0x7e, 0x78, 0xbf, 0xe7, 0x06, 0xca, 0x4c, 0xf5, 0xe9, 0xc5,
            0x45, 0x3e, 0x9f, 0x7c, 0xfd, 0x2b, 0x8b, 0x4c, 0x8d, 0x16, 0x9a, 0x44, 0xe5, 0x5c,
            0x88, 0xd4, 0xa9, 0xa7, 0xf9, 0x47, 0x42, 0x41, 0xe2, 0x21, 0xaf, 0x44, 0x86, 0x00,
            0x18, 0xab, 0x08, 0x56, 0x97, 0x2e, 0x19, 0x4c, 0xd9, 0x34,
        ];

        assert_eq!(&buf, PROTECTED);

        let (header, payload) = buf.split_at_mut(header_len);
        let (first, rest) = header.split_at_mut(1);
        let sample = &payload[..sample_len];


        let server_keys = Keys::initial(
            Version::V1,
            TLS13_AES_128_GCM_SHA256
                .tls13()
                .unwrap(),
            TLS13_AES_128_GCM_SHA256
                .tls13()
                .unwrap()
                .quic
                .unwrap(),
            CONNECTION_ID,
            Side::Server,
        );
        server_keys
            .remote
            .header
            .decrypt_in_place(sample, &mut first[0], &mut rest[17..21])
            .unwrap();
        let payload = server_keys
            .remote
            .packet
            .decrypt_in_place(PACKET_NUMBER, header, payload)
            .unwrap();

        assert_eq!(&payload[..PAYLOAD.len()], PAYLOAD);
        assert_eq!(payload.len(), buf.len() - header_len - tag_len);
    }

    #[test]
    #[ignore]
    fn test_quic_exporter() {

        for &kt in ALL_KEY_TYPES {
            let client_config = make_client_config_with_versions(kt, &[&rustls::version::TLS13]);
            let server_config = make_server_config_with_versions(kt, &[&rustls::version::TLS13]);

            do_exporter_test(client_config, server_config);
        }
    }


    #[test]
    #[ignore]
    fn test_fragmented_append() {
        // Create a QUIC client connection.
        let client_config = make_client_config_with_versions(KeyType::Rsa, &[&rustls::version::TLS13]);
        let client_config = Arc::new(client_config);
        let mut client = quic::ClientConnection::new(
            Arc::clone(&client_config),
            quic::Version::V1,
            server_name("localhost"),
            b"client params"[..].into(),
        )
        .unwrap();

        // Construct a message that is too large to fit in a single QUIC packet.
        // We want the partial pieces to be large enough to overflow the deframer's
        // 4096 byte buffer if mishandled.
        let mut out = vec![0; 4096];
        let len_bytes = u32::to_be_bytes(9266_u32);
        out[1..4].copy_from_slice(&len_bytes[1..]);

        // Read the message - this will put us into a joining handshake message state, buffering
        // 4096 bytes into the deframer buffer.
        client.read_hs(&out).unwrap();

        // Read the message again - once more it isn't a complete message, so we'll try to
        // append another 4096 bytes into the deframer buffer.
        //
        // If the deframer mishandles writing into the used buffer space this will panic with
        // an index out of range error:
        //   range end index 8192 out of range for slice of length 4096
        client.read_hs(&out).unwrap();
    }
} // mod test_quic*/

#[test]
fn test_client_does_not_offer_sha1() {
    use rustls::internal::msgs::{

        codec::Reader, handshake::HandshakePayload, message::MessagePayload, message::OutboundOpaqueMessage,
    };
    use rustls::HandshakeType;

    for kt in ALL_KEY_TYPES {
        for version in rustls::ALL_VERSIONS {
                 if version.version == ProtocolVersion::TLSv1_2 {
                continue
            }
            let client_config = make_client_config_with_versions(*kt, &[version]);
            let (mut client, _, _recv_srv,  _recv_clnt) = make_pair_for_configs(client_config, make_server_config(*kt));

            assert!(client.wants_write());
            let mut buf = [0u8; 262144];
            let sz = client
                .write_tls(&mut buf.as_mut(), 0)
                .unwrap();
            let msg = OutboundOpaqueMessage::read(&mut Reader::init(&buf[..sz])).unwrap();
            let msg = Message::try_from(msg.into_plain_message()).unwrap();
            assert!(msg.is_handshake_type(HandshakeType::ClientHello));

            let client_hello = match msg.payload {
                MessagePayload::Handshake { parsed, .. } => match parsed.payload {
                    HandshakePayload::ClientHello(ch) => ch,
                    _ => unreachable!(),
                },
                _ => unreachable!(),
            };

            let sigalgs = client_hello
                .sigalgs_extension()
                .unwrap();
            assert!(
                !sigalgs.contains(&SignatureScheme::RSA_PKCS1_SHA1),
                "sha1 unexpectedly offered"
            );
        }
    }
}

#[test]
fn test_client_config_keyshare() {

    let kx_groups = vec![provider::kx_group::SECP384R1];
    let client_config = make_client_config_with_kx_groups(KeyType::Rsa, kx_groups.clone());
    let server_config = make_server_config_with_kx_groups(KeyType::Rsa, kx_groups);
    let (mut client, mut server, mut recv_srv, mut recv_clnt) = make_pair_for_configs(client_config, server_config);
    do_handshake_until_error(&mut client, &mut server, &mut recv_srv, &mut recv_clnt).unwrap();
}

#[test]
fn test_client_config_keyshare_mismatch() {
    let client_config =
        make_client_config_with_kx_groups(KeyType::Rsa, vec![provider::kx_group::SECP384R1]);
    let server_config =
        make_server_config_with_kx_groups(KeyType::Rsa, vec![provider::kx_group::X25519]);
    let (mut client, mut server, mut recv_srv, mut recv_clnt) = make_pair_for_configs(client_config, server_config);
    assert!(do_handshake_until_error(&mut client, &mut server, &mut recv_srv, &mut recv_clnt).is_err());
}



#[test]
fn test_client_rejects_hrr_with_varied_session_id() {
    use rustls::internal::msgs::handshake::SessionId;
    let different_session_id =
        SessionId::random(provider::default_provider().secure_random).unwrap();

    let assert_client_sends_hello_with_secp384 = |msg: &mut Message| -> Altered {
        match &mut msg.payload {
            MessagePayload::Handshake { parsed, encoded } => match &mut parsed.payload {
                HandshakePayload::ClientHello(ch) => {
                    let keyshares = ch
                        .keyshare_extension()
                        .expect("missing key share extension");
                    assert_eq!(keyshares.len(), 1);
                    assert_eq!(keyshares[0].group(), rustls::NamedGroup::secp384r1);

                    ch.session_id = different_session_id;
                    *encoded = Payload::new(parsed.get_encoding());
                }
                _ => panic!("unexpected handshake message {parsed:?}"),
            },
            _ => panic!("unexpected non-handshake message {msg:?}"),
        };
        Altered::InPlace
    };

    let assert_server_requests_retry_and_echoes_session_id = |msg: &mut Message| -> Altered {
        match &msg.payload {
            MessagePayload::Handshake { parsed, .. } => match &parsed.payload {
                HandshakePayload::HelloRetryRequest(hrr) => {
                    let group = hrr.requested_key_share_group();
                    assert_eq!(group, Some(rustls::NamedGroup::X25519));

                    assert_eq!(hrr.session_id, different_session_id);
                }
                _ => panic!("unexpected handshake message {parsed:?}"),
            },
            MessagePayload::ChangeCipherSpec(_) => (),
            _ => panic!("unexpected non-handshake message {msg:?}"),
        };
        Altered::InPlace
    };

    // client prefers a secp384r1 key share, server only accepts x25519
    let client_config = make_client_config_with_kx_groups(
        KeyType::Rsa,
        vec![provider::kx_group::SECP384R1, provider::kx_group::X25519],
    );

    let server_config =
        make_server_config_with_kx_groups(KeyType::Rsa, vec![provider::kx_group::X25519]);

    let (client, server, mut recv_srv, mut recv_clnt) = make_pair_for_configs(client_config, server_config);
    let (mut client, mut server) = (client.into(), server.into());
    transfer_altered(
        &mut client,
        assert_client_sends_hello_with_secp384,
        &mut server,
    );
    server.process_new_packets(&mut recv_srv).unwrap();
    transfer_altered(
        &mut server,
        assert_server_requests_retry_and_echoes_session_id,
        &mut client,
    );
    assert_eq!(
        client.process_new_packets(&mut recv_clnt),
        Err(Error::PeerMisbehaved(
            PeerMisbehaved::IllegalHelloRetryRequestWithWrongSessionId
        ))
    );
}

#[cfg(feature = "tls12")]
#[test]
fn test_client_attempts_to_use_unsupported_kx_group() {
    // common to both client configs
    let shared_storage = Arc::new(ClientStorage::new());

    // first, client sends a x25519 and server agrees. x25519 is inserted
    //   into kx group cache.
    let mut client_config_1 =

        make_client_config_with_kx_groups(KeyType::Rsa, vec![provider::kx_group::X25519]);
    client_config_1.resumption = Resumption::store(shared_storage.clone());

    // second, client only supports secp-384 and so kx group cache
    //   contains an unusable value.
    let mut client_config_2 =

        make_client_config_with_kx_groups(KeyType::Rsa, vec![provider::kx_group::SECP384R1]);
    client_config_2.resumption = Resumption::store(shared_storage.clone());

    let server_config = make_server_config(KeyType::Rsa);


    // first handshake
    let (mut client_1, mut server, mut recv_srv, mut recv_clnt) = make_pair_for_configs(client_config_1, server_config.clone());
    do_handshake_until_error(&mut client_1, &mut server, &mut recv_srv, &mut recv_clnt).unwrap();

    let ops = shared_storage.ops();
    println!("storage {:#?}", ops);
    assert_eq!(ops.len(), 9);
    assert!(matches!(
        ops[3],
        ClientStorageOp::SetKxHint(_, rustls::NamedGroup::X25519)
    ));


    // second handshake
    let (mut client_2, mut server, mut recv_srv, mut recv_clnt) = make_pair_for_configs(client_config_2, server_config);
    do_handshake_until_error(&mut client_2, &mut server, &mut recv_srv, &mut recv_clnt).unwrap();

    let ops = shared_storage.ops();
    println!("storage {:?} {:#?}", ops.len(), ops);
    assert_eq!(ops.len(), 17);
    assert!(matches!(ops[9], ClientStorageOp::TakeTls13Ticket(_, true)));
    assert!(matches!(
        ops[10],
        ClientStorageOp::GetKxHint(_, Some(rustls::NamedGroup::X25519))
    ));
    assert!(matches!(
        ops[11],
        ClientStorageOp::SetKxHint(_, rustls::NamedGroup::secp384r1)
    ));
}

#[cfg(feature = "tls12")]
#[test]

fn test_client_sends_share_for_less_preferred_group() {
    // this is a test for the case described in:
    // https://datatracker.ietf.org/doc/draft-davidben-tls-key-share-prediction/

    // common to both client configs
    let shared_storage = Arc::new(ClientStorage::new());

    // first, client sends a secp384r1 share and server agrees. secp384r1 is inserted
    //   into kx group cache.
    let mut client_config_1 =
        make_client_config_with_kx_groups(KeyType::Rsa, vec![provider::kx_group::SECP384R1]);
    client_config_1.resumption = Resumption::store(shared_storage.clone());

    // second, client supports (x25519, secp384r1) and so kx group cache
    //   contains a supported but less-preferred group.
    let mut client_config_2 = make_client_config_with_kx_groups(
        KeyType::Rsa,
        vec![provider::kx_group::X25519, provider::kx_group::SECP384R1],
    );
    client_config_2.resumption = Resumption::store(shared_storage.clone());

    let server_config = make_server_config(KeyType::Rsa);

    // first handshake
    let (mut client_1, mut server, mut recv_srv, mut recv_clnt) = make_pair_for_configs(client_config_1, server_config.clone());
    do_handshake_until_error(&mut client_1, &mut server, &mut recv_srv, &mut recv_clnt).unwrap();

    let ops = shared_storage.ops();
    println!("storage {:#?}", ops);
    assert_eq!(ops.len(), 9);
    assert!(matches!(
        ops[3],
        ClientStorageOp::SetKxHint(_, rustls::NamedGroup::secp384r1)
    ));

    // second handshake (this must HRR to the most-preferred group)
    let assert_client_sends_secp384_share = |msg: &mut Message| -> Altered {
        match &msg.payload {
            MessagePayload::Handshake { parsed, .. } => match &parsed.payload {
                HandshakePayload::ClientHello(ch) => {
                    let keyshares = ch
                        .keyshare_extension()
                        .expect("missing key share extension");
                    assert_eq!(keyshares.len(), 1);
                    assert_eq!(keyshares[0].group(), rustls::NamedGroup::secp384r1);
                }
                _ => panic!("unexpected handshake message {:?}", parsed),
            },
            _ => panic!("unexpected non-handshake message {:?}", msg),
        };
        Altered::InPlace
    };

    let assert_server_requests_retry_to_x25519 = |msg: &mut Message| -> Altered {
        match &msg.payload {
            MessagePayload::Handshake { parsed, .. } => match &parsed.payload {
                HandshakePayload::HelloRetryRequest(hrr) => {
                    let group = hrr.requested_key_share_group();
                    assert_eq!(group, Some(rustls::NamedGroup::X25519));
                }
                _ => panic!("unexpected handshake message {:?}", parsed),
            },
            MessagePayload::ChangeCipherSpec(_) => (),
            _ => panic!("unexpected non-handshake message {:?}", msg),
        };
        Altered::InPlace
    };

    let (client_2, server, mut recv_srv, mut recv_clnt) = make_pair_for_configs(client_config_2, server_config);
    let (mut client_2, mut server) = (client_2.into(), server.into());
    transfer_altered(
        &mut client_2,
        assert_client_sends_secp384_share,
        &mut server,
    );
    server.process_new_packets(&mut recv_srv).unwrap();
    transfer_altered(
        &mut server,
        assert_server_requests_retry_to_x25519,
        &mut client_2,
    );
    client_2.process_new_packets(&mut recv_clnt).unwrap();
}

#[cfg(feature = "tls12")]
#[test]
fn test_tls13_client_resumption_does_not_reuse_tickets() {
    let shared_storage = Arc::new(ClientStorage::new());
        let mut client_config = make_client_config(KeyType::Rsa);
    client_config.resumption = Resumption::store(shared_storage.clone());
    let client_config = Arc::new(client_config);

    let mut server_config = make_server_config(KeyType::Rsa);
    server_config.send_tls13_tickets = 5;
    let server_config = Arc::new(server_config);

    // first handshake: client obtains 5 tickets from server.
    let (mut client, mut server, mut recv_srv, mut recv_clnt) = make_pair_for_arc_configs(&client_config, &server_config);
    do_handshake_until_error(&mut client, &mut server, &mut recv_srv, &mut recv_clnt).unwrap();
    let ops = shared_storage.ops_and_reset();
    println!("storage {:#?}", ops);
    assert_eq!(ops.len(), 10);
    assert!(matches!(ops[5], ClientStorageOp::InsertTls13Ticket(_)));
    assert!(matches!(ops[6], ClientStorageOp::InsertTls13Ticket(_)));
    assert!(matches!(ops[7], ClientStorageOp::InsertTls13Ticket(_)));
    assert!(matches!(ops[8], ClientStorageOp::InsertTls13Ticket(_)));
    assert!(matches!(ops[9], ClientStorageOp::InsertTls13Ticket(_)));

    // 5 subsequent handshakes: all are resumptions

    // Note: we don't do complete the handshakes, because that means
    // we get five additional tickets per connection which is unhelpful
    // in this test.  It also acts to record a "Happy Eyeballs"-type use
    // case, where a client speculatively makes many connection attempts
    // in parallel without knowledge of which will work due to underlying
    // connectivity uncertainty.
    for _ in 0..5 {
        let (mut client, mut server, mut recv_srv,  _recv_clnt) = make_pair_for_arc_configs(&client_config, &server_config);
        transfer(&mut client, &mut server, None);
        server.process_new_packets(&mut recv_srv).unwrap();

        let ops = shared_storage.ops_and_reset();
        assert!(matches!(ops[0], ClientStorageOp::TakeTls13Ticket(_, true)));
    }

    // 6th subsequent handshake: cannot be resumed; we ran out of tickets

    let (mut client, mut server, mut recv_srv,  _recv_clnt) = make_pair_for_arc_configs(&client_config, &server_config);
    transfer(&mut client, &mut server, None);
    server.process_new_packets(&mut recv_srv).unwrap();

    let ops = shared_storage.ops_and_reset();
    println!("last {:?}", ops);
    assert!(matches!(ops[0], ClientStorageOp::TakeTls13Ticket(_, false)));
}

#[test]
fn test_client_mtu_reduction() {
    struct CollectWrites {
        writevs: Vec<Vec<usize>>,
    }

    impl io::Write for CollectWrites {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            panic!()
        }
        fn flush(&mut self) -> io::Result<()> {
            panic!()
        }

        fn write_vectored(&mut self, b: &[io::IoSlice<'_>]) -> io::Result<usize> {
            let writes = b
                .iter()
                .map(|slice| slice.len())
                .collect::<Vec<usize>>();
            let len = writes.iter().sum();
            self.writevs.push(writes);
            Ok(len)
        }
    }

    fn collect_write_lengths(client: &mut ClientConnection) -> Vec<usize> {
        let mut collector = CollectWrites { writevs: vec![] };

        client
            .write_tls(&mut collector, 0)
            .unwrap();
        assert_eq!(collector.writevs.len(), 1);
        collector.writevs[0].clone()
    }


    for kt in ALL_KEY_TYPES {
        let mut client_config = make_client_config(*kt);
        client_config.max_fragment_size = Some(64);
        let mut client =
            ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();
        let writes = collect_write_lengths(&mut client);
        println!("writes at mtu=64: {:?}", writes);
        assert!(writes.iter().all(|x| *x <= 64));
        assert!(writes.len() > 1);
    }
}



fn check_client_max_fragment_size(size: usize) -> Option<Error> {
    let mut client_config = make_client_config(KeyType::Ed25519);
    client_config.max_fragment_size = Some(size);
    ClientConnection::new(Arc::new(client_config), server_name("localhost")).err()
}

#[test]
fn bad_client_max_fragment_sizes() {
    assert_eq!(
        check_client_max_fragment_size(31),
        Some(Error::BadMaxFragmentSize)
    );
    assert_eq!(check_client_max_fragment_size(32), None);
    assert_eq!(check_client_max_fragment_size(64), None);
    assert_eq!(check_client_max_fragment_size(1460), None);
    assert_eq!(check_client_max_fragment_size(0x4000), Some(Error::BadMaxFragmentSize));
    assert_eq!(check_client_max_fragment_size(0x4005), Some(Error::BadMaxFragmentSize));
    assert_eq!(
        check_client_max_fragment_size(0x4006),
        Some(Error::BadMaxFragmentSize)
    );
    assert_eq!(
        check_client_max_fragment_size(0xffff),
        Some(Error::BadMaxFragmentSize)
    );
}



fn assert_lt(left: usize, right: usize) {
    if left >= right {
        panic!("expected {} < {}", left, right);
    }
}

#[test]
fn connection_types_are_not_huge() {
    // Arbitrary sizes
    assert_lt(mem::size_of::<ServerConnection>(), 1600);
    assert_lt(mem::size_of::<ClientConnection>(), 1600);
}


#[test]
fn test_server_rejects_duplicate_sni_names() {
    fn duplicate_sni_payload(msg: &mut Message) -> Altered {
        if let MessagePayload::Handshake { parsed, encoded } = &mut msg.payload {
            if let HandshakePayload::ClientHello(ch) = &mut parsed.payload {
                for mut ext in ch.extensions.iter_mut() {
                    if let ClientExtension::ServerName(snr) = &mut ext {
                        snr.push(snr[0].clone());
                    }
                }
            }

            *encoded = Payload::new(parsed.get_encoding());
        }
        Altered::InPlace
    }

    let (client, server, mut recv_srv,  _recv_clnt) = make_pair(KeyType::Rsa);
    let (mut client, mut server) = (client.into(), server.into());
    transfer_altered(&mut client, duplicate_sni_payload, &mut server);
    assert_eq!(
        server.process_new_packets(&mut recv_srv),
        Err(Error::PeerMisbehaved(
            PeerMisbehaved::DuplicateServerNameTypes
        ))
    );
}

#[test]
fn test_server_rejects_empty_sni_extension() {
    fn empty_sni_payload(msg: &mut Message) -> Altered {
        if let MessagePayload::Handshake { parsed, encoded } = &mut msg.payload {
            if let HandshakePayload::ClientHello(ch) = &mut parsed.payload {
                for mut ext in ch.extensions.iter_mut() {
                    if let ClientExtension::ServerName(snr) = &mut ext {
                        snr.clear();
                    }
                }
            }

            *encoded = Payload::new(parsed.get_encoding());
        }

        Altered::InPlace
    }


    let (client, server, mut recv_srv,  _recv_clnt) = make_pair(KeyType::Rsa);
    let (mut client, mut server) = (client.into(), server.into());
    transfer_altered(&mut client, empty_sni_payload, &mut server);
    assert_eq!(
        server.process_new_packets(&mut recv_srv),
        Err(Error::PeerMisbehaved(
            PeerMisbehaved::ServerNameMustContainOneHostName
        ))
    );
}

#[test]
fn test_server_rejects_clients_without_any_kx_groups() {
    fn delete_kx_groups(msg: &mut Message) -> Altered {
        if let MessagePayload::Handshake { parsed, encoded } = &mut msg.payload {
            if let HandshakePayload::ClientHello(ch) = &mut parsed.payload {
                for mut ext in ch.extensions.iter_mut() {
                    if let ClientExtension::NamedGroups(ngs) = &mut ext {
                        ngs.clear();
                    }
                    if let ClientExtension::KeyShare(ks) = &mut ext {
                        ks.clear();
                    }
                }
            }

            *encoded = Payload::new(parsed.get_encoding());
        }
        Altered::InPlace
    }

    let (client, server, mut recv_srv,  _recv_clnt) = make_pair(KeyType::Rsa);
    let (mut client, mut server) = (client.into(), server.into());
    transfer_altered(&mut client, delete_kx_groups, &mut server);
    assert_eq!(
        server.process_new_packets(&mut recv_srv),
        Err(Error::PeerIncompatible(
            PeerIncompatible::NoKxGroupsInCommon
        ))
    );
}

#[test]

fn test_server_rejects_clients_without_any_kx_group_overlap() {
    for version in rustls::ALL_VERSIONS {
             if version.version == ProtocolVersion::TLSv1_2 {
                continue
            }
        let (mut client, mut server, mut recv_srv, mut recv_clnt) = make_pair_for_configs(
            make_client_config_with_kx_groups(KeyType::Rsa, vec![provider::kx_group::X25519]),
            finish_server_config(
                KeyType::Rsa,
                ServerConfig::builder_with_provider(
                    CryptoProvider {
                        kx_groups: vec![provider::kx_group::SECP384R1],
                        ..provider::default_provider()
                    }
                    .into(),
                )
                .with_protocol_versions(&[version])
                .unwrap(),
            ),
        );
        transfer(&mut client, &mut server, None);
        assert_eq!(
            server.process_new_packets(&mut recv_srv),
            Err(Error::PeerIncompatible(
                PeerIncompatible::NoKxGroupsInCommon
            ))
        );
        transfer(&mut server, &mut client, None);
        assert_eq!(
            client.process_new_packets(&mut recv_clnt),
            Err(Error::AlertReceived(AlertDescription::HandshakeFailure))
        );
    }
}

#[test]
fn test_client_rejects_illegal_tls13_ccs() {
    fn corrupt_ccs(msg: &mut Message) -> Altered {
        if let MessagePayload::ChangeCipherSpec(_) = &mut msg.payload {
            println!("seen CCS {:?}", msg);
            return Altered::Raw(vec![0x14, 0x03, 0x03, 0x00, 0x02, 0x01, 0x02]);
        }
        Altered::InPlace
    }

    let (mut client, mut server, mut recv_srv, mut recv_clnt) = make_pair(KeyType::Rsa);
    transfer(&mut client, &mut server, None);
    server.process_new_packets(&mut recv_srv).unwrap();
    let (mut server, mut client) = (server.into(), client.into());

    transfer_altered(&mut server, corrupt_ccs, &mut client);
    assert_eq!(

        client.process_new_packets(&mut recv_clnt),
        Err(Error::PeerMisbehaved(
            PeerMisbehaved::IllegalMiddleboxChangeCipherSpec
        ))
    );
}






/*#[cfg(feature = "tls12")]
fn remove_ems_request(msg: &mut Message) -> Altered {
    if let MessagePayload::Handshake { parsed, encoded } = &mut msg.payload {
        if let HandshakePayload::ClientHello(ch) = &mut parsed.payload {
            ch.extensions
                .retain(|ext| !matches!(ext, ClientExtension::ExtendedMasterSecretRequest))
        }

        *encoded = Payload::new(parsed.get_encoding());
    }

    Altered::InPlace
}*/








#[test]
fn test_no_warning_logging_during_successful_sessions() {
    CountingLogger::install();
    CountingLogger::reset();

    for kt in ALL_KEY_TYPES {
        for version in rustls::ALL_VERSIONS {
                 if version.version == ProtocolVersion::TLSv1_2 {
                continue
            }
            let client_config = make_client_config_with_versions(*kt, &[version]);
            let (mut client, mut server, mut recv_srv, mut recv_clnt) =
                make_pair_for_configs(client_config, make_server_config(*kt));
            do_handshake(&mut client, &mut server, &mut recv_srv, &mut recv_clnt);
        }
    }

    if cfg!(feature = "logging") {
        COUNTS.with(|c| {
            println!("After tests: {:?}", c.borrow());
            assert_eq!(c.borrow().warn, 0);
            assert_eq!(c.borrow().error, 0);
            assert_eq!(c.borrow().info, 0);
            assert!(c.borrow().trace > 0);
            assert!(c.borrow().debug > 0);
        });
    } else {
        COUNTS.with(|c| {
            println!("After tests: {:?}", c.borrow());
            assert_eq!(c.borrow().warn, 0);
            assert_eq!(c.borrow().error, 0);
            assert_eq!(c.borrow().info, 0);
            assert_eq!(c.borrow().trace, 0);
            assert_eq!(c.borrow().debug, 0);
        });
    }
}




/// Test that secrets cannot be extracted unless explicitly enabled, and until
/// the handshake is done.
#[cfg(feature = "tls12")]
#[test]
fn test_secret_extraction_disabled_or_too_early() {
    let kt = KeyType::Rsa;
    let provider = Arc::new(CryptoProvider {
        cipher_suites: vec![cipher_suite::TLS13_AES_128_GCM_SHA256],
        ..provider::default_provider()
    });

    for (server_enable, client_enable) in [(true, false), (false, true)] {
        let mut server_config = ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(kt.get_chain(), kt.get_key())
            .unwrap();
        server_config.enable_secret_extraction = server_enable;
        let server_config = Arc::new(server_config);

        let mut client_config = make_client_config(kt);
        client_config.enable_secret_extraction = client_enable;

        let client_config = Arc::new(client_config);

        let (client, server,  _recv_srv,  _recv_clnt) = make_pair_for_arc_configs(&client_config, &server_config);

        assert!(
            client
                .dangerous_extract_secrets()
                .is_err(),
            "extraction should fail until handshake completes"
        );
        assert!(
            server
                .dangerous_extract_secrets()
                .is_err(),
            "extraction should fail until handshake completes"
        );

        let (mut client, mut server, mut recv_srv, mut recv_clnt) = make_pair_for_arc_configs(&client_config, &server_config);

        do_handshake(&mut client, &mut server, &mut recv_srv, &mut recv_clnt);

        assert_eq!(
            server_enable,
            server
                .dangerous_extract_secrets()
                .is_ok()
        );
        assert_eq!(
            client_enable,
            client
                .dangerous_extract_secrets()
                .is_ok()
        );
    }
}

//#[test] // Test logic is no more applicable
/*fn test_received_plaintext_backpressure() {
    let kt = KeyType::Rsa;

    let server_config = Arc::new(
        ServerConfig::builder_with_provider(
            CryptoProvider {
                cipher_suites: vec![cipher_suite::TLS13_AES_128_GCM_SHA256],
                ..provider::default_provider()
            }
            .into(),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(kt.get_chain(), kt.get_key())
        .unwrap(),
    );

    let client_config = Arc::new(make_client_config(kt));
    let (mut client, mut server, mut recv_srv, mut recv_clnt) = make_pair_for_arc_configs(&client_config, &server_config);
    do_handshake(&mut client, &mut server, &mut recv_srv, &mut recv_clnt);

    // Fill the server's received plaintext buffer with 16k bytes
    let client_buf = [0; 16_385];
    dbg!(client
        .writer()
        .write(&client_buf)
        .unwrap());
    let mut network_buf = Vec::with_capacity(32_768);
    let sent = dbg!(client
        .write_tls(&mut network_buf, 0)
        .unwrap());
    let mut read = 0;
    while read < sent {
        let new = dbg!(server
            .read_tls(&mut &network_buf[read..sent])
            .unwrap());
        if new == 4096 {
            read += new;
        } else {
            break;
        }
    }
    server.process_new_packets(&mut recv_srv).unwrap();

    // Send two more bytes from client to server
    dbg!(client
        .writer()
        .write(&client_buf[..2])
        .unwrap());
    let sent = dbg!(client
        .write_tls(&mut network_buf, 0)
        .unwrap());

    // Get an error because the received plaintext buffer is full
    assert!(server
        .read_tls(&mut &network_buf[..sent])
        .is_err());

    // Read out some of the plaintext
    server
        .reader()
        .read_exact(&mut [0; 2])
        .unwrap();

    // Now there's room again in the plaintext buffer
    assert_eq!(
        server
            .read_tls(&mut &network_buf[..sent])
            .unwrap(),
        24
    );
}*/

#[test]
fn test_debug_server_name_from_ip() {
    assert_eq!(
        format!(
            "{:?}",
            ServerName::IpAddress(IpAddr::try_from("127.0.0.1").unwrap())
        ),
        "IpAddress(V4(Ipv4Addr([127, 0, 0, 1])))"
    )
}

#[test]
fn test_debug_server_name_from_string() {
    assert_eq!(
        format!("{:?}", ServerName::try_from("a.com").unwrap()),
        "DnsName(\"a.com\")"
    )
}

#[cfg(all(feature = "ring", feature = "aws_lc_rs"))]
#[test]
fn test_explicit_provider_selection() {
    let client_config = finish_client_config(
        KeyType::Rsa,
        rustls::ClientConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .unwrap(),
    );
    let server_config = finish_server_config(
        KeyType::Rsa,
        rustls::ServerConfig::builder_with_provider(
            rustls::crypto::aws_lc_rs::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .unwrap(),
    );

    let (mut client, mut server, mut recv_srv, mut recv_clnt) = make_pair_for_configs(client_config, server_config);
    do_handshake(&mut client, &mut server, &mut recv_srv, &mut recv_clnt);
}

#[derive(Debug)]
struct FaultyRandom {
    // when empty, `fill_random` requests return `GetRandomFailed`
    rand_queue: Mutex<&'static [u8]>,
}

impl rustls::crypto::SecureRandom for FaultyRandom {
    fn fill(&self, output: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
        let mut queue = self.rand_queue.lock().unwrap();

        println!(
            "fill_random request for {} bytes (got {})",
            output.len(),
            queue.len()
        );

        if queue.len() < output.len() {
            return Err(rustls::crypto::GetRandomFailed);
        }

        let fixed_output = &queue[..output.len()];
        output.copy_from_slice(fixed_output);
        *queue = &queue[output.len()..];
        Ok(())
    }
}

#[test]
fn test_client_construction_fails_if_random_source_fails_in_first_request() {
    static FAULTY_RANDOM: FaultyRandom = FaultyRandom {
        rand_queue: Mutex::new(b""),
    };

    let client_config = finish_client_config(
        KeyType::Rsa,
        rustls::ClientConfig::builder_with_provider(
            CryptoProvider {
                secure_random: &FAULTY_RANDOM,
                ..provider::default_provider()
            }
            .into(),
        )
        .with_safe_default_protocol_versions()
        .unwrap(),
    );

    assert_eq!(
        ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap_err(),
        Error::FailedToGetRandomBytes
    );
}

#[test]
fn test_client_construction_fails_if_random_source_fails_in_second_request() {
    static FAULTY_RANDOM: FaultyRandom = FaultyRandom {
        rand_queue: Mutex::new(b"nice random number generator huh"),
    };

    let client_config = finish_client_config(
        KeyType::Rsa,
        rustls::ClientConfig::builder_with_provider(
            CryptoProvider {
                secure_random: &FAULTY_RANDOM,
                ..provider::default_provider()
            }
            .into(),
        )
        .with_safe_default_protocol_versions()
        .unwrap(),
    );

    assert_eq!(
        ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap_err(),
        Error::FailedToGetRandomBytes
    );
}

#[test]
fn test_client_construction_requires_66_bytes_of_random_material() {
    static FAULTY_RANDOM: FaultyRandom = FaultyRandom {
        rand_queue: Mutex::new(
            b"nice random number generator !!!!!\
                                 it's really not very good is it?",
        ),
    };

    let client_config = finish_client_config(
        KeyType::Rsa,
        rustls::ClientConfig::builder_with_provider(
            CryptoProvider {
                secure_random: &FAULTY_RANDOM,
                ..provider::default_provider()
            }
            .into(),
        )
        .with_safe_default_protocol_versions()
        .unwrap(),
    );

    ClientConnection::new(Arc::new(client_config), server_name("localhost"))
        .expect("check how much random material ClientConnection::new consumes");
}












#[derive(Default, Debug)]
struct LogCounts {
    trace: usize,
    debug: usize,
    info: usize,
    warn: usize,
    error: usize,
}

impl LogCounts {
    fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    fn reset(&mut self) {
        *self = Self::new();
    }

    fn add(&mut self, level: log::Level) {
        match level {
            log::Level::Trace => self.trace += 1,
            log::Level::Debug => self.debug += 1,
            log::Level::Info => self.info += 1,
            log::Level::Warn => self.warn += 1,
            log::Level::Error => self.error += 1,
        }
    }
}


// this must be outside test_for_each_provider!, as we want
// one thread_local!, not one per provider.
thread_local!(static COUNTS: RefCell<LogCounts> = RefCell::new(LogCounts::new()));

struct CountingLogger;

#[allow(dead_code)]
static LOGGER: CountingLogger = CountingLogger;

#[allow(dead_code)]
impl CountingLogger {
    fn install() {
        let _ = log::set_logger(&LOGGER);
        log::set_max_level(log::LevelFilter::Trace);
    }

    fn reset() {
        COUNTS.with(|c| {
            c.borrow_mut().reset();
        });
    }
}

impl log::Log for CountingLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        println!("logging at {:?}: {:?}", record.level(), record.args());

        COUNTS.with(|c| {
            c.borrow_mut().add(record.level());
        });
    }

    fn flush(&self) {}
}

