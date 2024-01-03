<p align="center">
  <img width="460" height="300" src="rTCPLS.png">
</p>

<p align="center">
rTCPLS is an implementation of protocol TCPLS in RUST. TCPLS is a transport protocol that combines TCP and TLS1.3. It uses <a href = "https://github.com/briansmith/ring"><em>ring</em></a> for cryptography and <a href = "https://github.com/briansmith/webpki">webpki</a> for certificate
verification.
</p>


## Possible future features

* TCP multipath support.
* TCP connection failover handling.
* Onion routing.


### Platform support

TCPLS is an expansion of Rustls and Rustls in turn uses [`ring`](https://crates.io/crates/ring) for implementing the
cryptography in TLS. As a result, rustls only runs on platforms
[supported by `ring`](https://github.com/briansmith/ring#online-automated-testing).
At the time of writing this means x86, x86-64, armv7, and aarch64.

TCPLS requires Rust 1.57 or later as it is an expansion of Rustls.

# Example code
There are two example programs which use
[mio](https://github.com/carllerche/mio) to do asynchronous IO.

## Client example program
The client example program is named `client_tcpls`. Client connects to the TCPLS server at hostname:PORT. Once the TCPLS session is established, client will send three different files through 
a single tcp connection to the server. Each file will be hashed and stored on a different sending stream.

```client_tcpls
Usage:
  run --package rTcpls-examples --bin client_tcpls --  --cafile test-ca/rsa/ca.cert -p 8443 localhost --verbose

```


## Server example program
The server example program is named `server_tcpls`. Server program will 
receive the files sent by the client. Files sent will be decrypted in zero copy in Application receive buffers. Integrity of files will be checked by hashing them and comparing the resulting hash with the sent hash.

```tlsserver-mio

Usage:
  run --package rTcpls-examples --bin server_tcpls -- --verbose --certs test-ca/rsa/end.fullchain --key test-ca/rsa/end.rsa -p 8443 echo

```

# License

TCPLS is distributed under the following three licenses:

- Apache License version 2.0.
- MIT license.
- ISC license.

These are included as LICENSE-APACHE, LICENSE-MIT and LICENSE-ISC
respectively.  You may use this software under the terms of any
of these licenses, at your option.

# Code of conduct

This project adopts the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct).
Please email rustls-mod@googlegroups.com to report any instance of misconduct, or if you
have any comments or questions on the Code of Conduct.
