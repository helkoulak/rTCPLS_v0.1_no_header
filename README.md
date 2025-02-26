<p align="center">

  <img width="460" height="300" src="./rTCPLS.png">
</p>


rTCPLS is a Rust implementation of the protocol TCPLS atop the TLS library [Rustls](https://github.com/rustls/rustls). It follows the
[TCPLS IETF draft](https://datatracker.ietf.org/doc/draft-piraux-tcpls/).


# Status

rTCPLS is an ongoing implementation of the protocol TCPLS. This implementation reflects the initial design of TCPLS that follows 
the draft [TCPLS IETF draft](https://datatracker.ietf.org/doc/draft-piraux-tcpls/).


# Building the code
To build the code, simply execute the following commands:
```
git clone https://forge.infosec.unamur.be/phd-elkoulak/r-tcpls-v-0-1-no-header.git
cd r-tcpls-v-0-1-no-header
git checkout master
$ cargo build --release
```

# Example code

Our [examples] directory contains demos that show different client-server scenarios as a proof of concept.
To run them use the following commands for the following examples:

### Client sends multiple streams to the server via a single tcp connection
```
$ cargo run --bin server_tcpls -- --verbose --certs test-ca/rsa/end.fullchain --key test-ca/rsa/end.rsa -p 8443
$ cargo run --bin client_tcpls -- --cafile test-ca/rsa/ca.cert -p 8443 localhost --verbose
```

### Client sends multiple streams to the server via three tcp connections
```
$ cargo run --bin server_tcpls_mp -- --verbose --certs test-ca/rsa/end.fullchain --key test-ca/rsa/end.rsa -p 8443
$ cargo run --bin client_tcpls_mp --  --cafile test-ca/rsa/ca.cert -p 8443 localhost --verbose
```


# Testing
To run the tests, execute the following command
```
$ cargo test
```

# Benchmarking
There are several benchmark tests to measure the CPU time taken to accomplish several tasks. Execute the following commands to run the
following tests:

### Measuring the average CPU time spent on decrypting into the application buffer one stream, of 600 TCPLS full records, sent over two connections.
```
$ cargo bench --bench srv_clnt_single_stream_two_connection
```

### Measuring the average CPU time spent on decrypting into the application buffers one stream, of 600 TCPLS full records, sent over a single connection.
```
$ cargo bench --bench srv_clnt_single_stream_single_connection
```


# License


As rTCPLS is built atop Rustls, it is distributed under the following three licenses:

- Apache License version 2.0.
- MIT license.
- ISC license.

These are included as LICENSE-APACHE, LICENSE-MIT and LICENSE-ISC
respectively.  You may use this software under the terms of any
of these licenses, at your option.


