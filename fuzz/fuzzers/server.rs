#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustls;

use rustls::server::ResolvesServerCert;
use rustls::{ServerConfig, ServerConnection};

use std::io;
use std::sync::Arc;

<<<<<<< HEAD
=======
#[derive(Debug)]
>>>>>>> 5bd3300 (Add files of rustls v0.23.1)
struct Fail;

impl ResolvesServerCert for Fail {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        None
    }
}

fuzz_target!(|data: &[u8]| {
    let config = Arc::new(
        ServerConfig::builder()
<<<<<<< HEAD
            .with_safe_defaults()
=======
>>>>>>> 5bd3300 (Add files of rustls v0.23.1)
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Fail)),
    );
    let mut server = ServerConnection::new(config).unwrap();
    let _ = server.read_tls(&mut io::Cursor::new(data));
    let _ = server.process_new_packets();
});
