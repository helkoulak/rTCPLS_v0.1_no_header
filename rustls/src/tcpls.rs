#![allow(missing_docs)]
#![allow(unused_qualifications)]

/// This module contains optional APIs for implementing TCPLS.
use crate::cipher::{derive_connection_iv, Iv, MessageDecrypter, MessageEncrypter};
use crate::client::ClientConnectionData;
use crate::common_state::*;
use crate::conn::ConnectionCore;
use crate::enums::ProtocolVersion;
use crate::msgs::handshake::{ClientExtension, ServerExtension};
use crate::server::ServerConnectionData;
use crate::{ClientConfig, RootCertStore, ServerConfig, ServerName, ConnectionCommon, SupportedCipherSuite, ALL_CIPHER_SUITES, SupportedProtocolVersion, version, Certificate, PrivateKey, DEFAULT_CIPHER_SUITES, DEFAULT_VERSIONS, KeyLogFile, cipher, ALL_VERSIONS, Ticketer, server, ContentType, InvalidMessage, Error};
use crate::msgs::codec;
use crate::record_layer::RecordLayer;
use crate::verify::{AllowAnyAnonymousOrAuthenticatedClient, AllowAnyAuthenticatedClient, NoClientAuth};

use mio::net::{TcpListener, TcpStream};
use mio::Token;

use std::fmt::{self, Debug};
use std::{io, process, u32, vec};
use std::arch::{asm, is_aarch64_feature_detected};
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::fs;
use std::io::{BufReader, Read};
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use octets::BufferError;
use crate::tcpls::Frame::Stream;
use crate::vecbuf::ChunkVecBuffer;


pub const TCPLS_STREAM_FRAME_MAX_PAYLOAD_LENGTH: usize = crate::msgs::fragmenter::MAX_FRAGMENT_LEN - STREAM_FRAME_OVERHEAD;

pub const STREAM_FRAME_OVERHEAD: usize = 15; // Type = 1 Byte + Stream Id = 4 Bytes + Offset = 8 Bytes + Length = 2 Bytes

pub const DEFAULT_RECEIVED_PLAINTEXT_LIMIT: usize = 16 * 1024;
pub const DEFAULT_BUFFER_LIMIT: usize = 64 * 1024;


#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Frame {
    Padding,

    Ping,

    Stream {
        stream_data: Vec<u8>,
        length: u64,
        offset: u64,
        stream_id: u64,
        fin: u8,

    },

    ACK {
        highest_record_sn_received: u64,
        connection_id: u64,
    },

    NewToken {
        token: [u8; 32],
        sequence: u64,

    },

    ConnectionReset {
        connection_id: u64,

    },

    NewAddress {
        port: u64,
        address: Vec<u8>,
        address_version: u64,
        address_id: u64,

    },

    RemoveAddress {
        address_id: u64,

    },

    StreamChange {
        next_record_stream_id: u64,
        next_offset: u64,

    }
}


impl Frame {
    pub fn parse(
        b: &mut octets::Octets) -> Result<Frame, InvalidMessage> {
        let frame_type = b.get_u8_reverse().expect("failed");

        let frame = match frame_type {
            0x00 => Frame::Padding,


            0x01 => Frame::Ping,

            0x02..=0x03 => parse_stream_frame(frame_type, b).unwrap(),

            0x04 => parse_ack_frame(b).unwrap(),

            0x05 => parse_new_token_frame(b).unwrap(),

            0x06 => parse_connection_reset_frame(b).unwrap(),

            0x07 => parse_new_address_frame(b).unwrap(),

            0x08 => parse_remove_address_frame(b).unwrap(),

            0x09 => parse_stream_change_frame(b).unwrap(),


            _ => return Err(InvalidMessage::InvalidFrameType.into()),
        };


        Ok(frame)
    }

    pub fn encode(&self, b: &mut octets::OctetsMut) -> Result<usize, InvalidMessage> {
        let before = b.cap();

        match self {
            Frame::Padding => {b.put_varint(0x00).unwrap();},
            Frame::Ping => {b.put_varint(0x01).unwrap();},
            Frame::Stream {
                stream_data,
                length ,
                offset,
                stream_id,
                fin,
            } => {
                b.put_bytes(stream_data.as_ref()).unwrap();
                b.put_varint_reverse(*length).unwrap();
                b.put_varint_reverse(*offset).unwrap();
                b.put_varint_reverse(*stream_id).unwrap();
                if fin & 0x01 == 0 {
                    b.put_varint(0x02).unwrap();
                }else {
                    b.put_varint(0x03).unwrap();
                }
            },

            Frame::ACK {
                highest_record_sn_received,
                connection_id,
            } => {
                b.put_varint_reverse(*highest_record_sn_received).unwrap();
                b.put_varint_reverse(*connection_id).unwrap();
                b.put_varint(0x04).unwrap();
            },

            Frame::NewToken {
                token,
                sequence,
            } => {
                b.put_bytes(token).unwrap();
                b.put_varint_reverse(*sequence).unwrap();
                b.put_varint(0x05).unwrap();
            },

            Frame::ConnectionReset {
                connection_id,
            } => {
                b.put_varint_reverse(*connection_id).unwrap();
                b.put_varint(0x06).unwrap();
            },
            Frame::NewAddress {
                port,
                address,
                address_version,
                address_id,
            } => {
                b.put_varint_reverse(*port).unwrap();
                b.put_bytes(address.as_ref()).unwrap();
                b.put_varint_reverse(*address_version).unwrap();
                b.put_varint_reverse(*address_id).unwrap();
                b.put_varint(0x07).unwrap();

            },

            Frame::RemoveAddress {
                address_id
            } => {
                b.put_varint_reverse(*address_id).unwrap();
                b.put_varint(0x08).unwrap();
            },

            Frame::StreamChange {
                next_record_stream_id,
                next_offset,
            } => {
                b.put_varint_reverse(*next_record_stream_id).unwrap();
                b.put_varint_reverse(*next_offset).unwrap();
                b.put_varint(0x09).unwrap();
            },

            _ => {}
        }


        Ok(before - b.cap())
    }


}

// impl std::fmt::Debug for Frame {
//     fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
//         match self {
//             Frame::Padding { len } => {
//                 write!(f, "PADDING len={len}")?;
//             },
//
//             Frame::Ping => {
//                 write!(f, "PING")?;
//             },
//
//             Frame::ACK {
//                 ack_delay,
//                 ranges,
//                 ecn_counts,
//             } => {
//                 write!(
//                     f,
//                     "ACK delay={ack_delay} blocks={ranges:?} ecn_counts={ecn_counts:?}"
//                 )?;
//             },
//
//             Frame::ResetStream {
//                 stream_id,
//                 error_code,
//                 final_size,
//             } => {
//                 write!(
//                     f,
//                     "RESET_STREAM stream={stream_id} err={error_code:x} size={final_size}"
//                 )?;
//             },
//
//             Frame::StopSending {
//                 stream_id,
//                 error_code,
//             } => {
//                 write!(f, "STOP_SENDING stream={stream_id} err={error_code:x}")?;
//             },
//
//             Frame::Crypto { data } => {
//                 write!(f, "CRYPTO off={} len={}", data.off(), data.len())?;
//             },
//
//             Frame::CryptoHeader { offset, length } => {
//                 write!(f, "CRYPTO off={offset} len={length}")?;
//             },
//
//             Frame::NewToken { .. } => {
//                 write!(f, "NEW_TOKEN (TODO)")?;
//             },
//
//             Frame::Stream { stream_id, data } => {
//                 write!(
//                     f,
//                     "STREAM id={} off={} len={} fin={}",
//                     stream_id,
//                     data.off(),
//                     data.len(),
//                     data.fin()
//                 )?;
//             },
//
//             Frame::StreamHeader {
//                 stream_id,
//                 offset,
//                 length,
//                 fin,
//             } => {
//                 write!(
//                     f,
//                     "STREAM id={stream_id} off={offset} len={length} fin={fin}"
//                 )?;
//             },
//
//             Frame::MaxData { max } => {
//                 write!(f, "MAX_DATA max={max}")?;
//             },
//
//             Frame::MaxStreamData { stream_id, max } => {
//                 write!(f, "MAX_STREAM_DATA stream={stream_id} max={max}")?;
//             },
//
//             Frame::MaxStreamsBidi { max } => {
//                 write!(f, "MAX_STREAMS type=bidi max={max}")?;
//             },
//
//             Frame::MaxStreamsUni { max } => {
//                 write!(f, "MAX_STREAMS type=uni max={max}")?;
//             },
//
//             Frame::DataBlocked { limit } => {
//                 write!(f, "DATA_BLOCKED limit={limit}")?;
//             },
//
//             Frame::StreamDataBlocked { stream_id, limit } => {
//                 write!(
//                     f,
//                     "STREAM_DATA_BLOCKED stream={stream_id} limit={limit}"
//                 )?;
//             },
//
//             Frame::StreamsBlockedBidi { limit } => {
//                 write!(f, "STREAMS_BLOCKED type=bidi limit={limit}")?;
//             },
//
//             Frame::StreamsBlockedUni { limit } => {
//                 write!(f, "STREAMS_BLOCKED type=uni limit={limit}")?;
//             },
//
//             Frame::NewConnectionId {
//                 seq_num,
//                 retire_prior_to,
//                 conn_id,
//                 reset_token,
//             } => {
//                 write!(
//                     f,
//                     "NEW_CONNECTION_ID seq_num={seq_num} retire_prior_to={retire_prior_to} conn_id={conn_id:02x?} reset_token={reset_token:02x?}",
//                 )?;
//             },
//
//             Frame::RetireConnectionId { seq_num } => {
//                 write!(f, "RETIRE_CONNECTION_ID seq_num={seq_num}")?;
//             },
//
//             Frame::PathChallenge { data } => {
//                 write!(f, "PATH_CHALLENGE data={data:02x?}")?;
//             },
//
//             Frame::PathResponse { data } => {
//                 write!(f, "PATH_RESPONSE data={data:02x?}")?;
//             },
//
//             Frame::ConnectionClose {
//                 error_code,
//                 frame_type,
//                 reason,
//             } => {
//                 write!(
//                     f,
//                     "CONNECTION_CLOSE err={error_code:x} frame={frame_type:x} reason={reason:x?}"
//                 )?;
//             },
//
//             Frame::ApplicationClose { error_code, reason } => {
//                 write!(
//                     f,
//                     "APPLICATION_CLOSE err={error_code:x} reason={reason:x?}"
//                 )?;
//             },
//
//             Frame::HandshakeDone => {
//                 write!(f, "HANDSHAKE_DONE")?;
//             },
//
//             Frame::Datagram { data } => {
//                 write!(f, "DATAGRAM len={}", data.len())?;
//             },
//
//             Frame::DatagramHeader { length } => {
//                 write!(f, "DATAGRAM len={length}")?;
//             },
//         }
//
//         Ok(())
//     }
// }

// fn parse_ack_frame(ty: u64, b: &mut octets::Octets) -> Result<Frame, E> {
//     let first = ty as u8;
//
//     let largest_ack = b.get_varint()?;
//     let ack_delay = b.get_varint()?;
//     let block_count = b.get_varint()?;
//     let ack_block = b.get_varint()?;
//
//     if largest_ack < ack_block {
//         return Err(Error::InvalidFrame);
//     }
//
//     let mut smallest_ack = largest_ack - ack_block;
//
//     let mut ranges = ranges::RangeSet::default();
//
//     ranges.insert(smallest_ack..largest_ack + 1);
//
//     for _i in 0..block_count {
//         let gap = b.get_varint()?;
//
//         if smallest_ack < 2 + gap {
//             return Err(Error::InvalidFrame);
//         }
//
//         let largest_ack = (smallest_ack - gap) - 2;
//         let ack_block = b.get_varint()?;
//
//         if largest_ack < ack_block {
//             return Err(Error::InvalidFrame);
//         }
//
//         smallest_ack = largest_ack - ack_block;
//
//         ranges.insert(smallest_ack..largest_ack + 1);
//     }
//
//     let ecn_counts = if first & 0x01 != 0 {
//         let ecn = EcnCounts {
//             ect0_count: b.get_varint()?,
//             ect1_count: b.get_varint()?,
//             ecn_ce_count: b.get_varint()?,
//         };
//
//         Some(ecn)
//     } else {
//         None
//     };
//
//     Ok(Frame::ACK {
//         highest_record_sn_received: u64,
//         connection_id: u32,
//     })
// }
//
// pub fn encode_crypto_header(
//     offset: u64, length: u64, b: &mut octets::OctetsMut,
// ) -> Result<()> {
//     b.put_varint(0x06)?;
//
//     b.put_varint(offset)?;
//
//     // Always encode length field as 2-byte varint.
//     b.put_varint_with_len(length, 2)?;
//
//     Ok(())
// }
//
// pub fn encode_stream_header(
//     stream_id: u64, offset: u64, length: u64, fin: bool,
//     b: &mut octets::OctetsMut,
// ) -> Result<()> {
//     let mut ty: u8 = 0x08;
//
//     // Always encode offset.
//     ty |= 0x04;
//
//     // Always encode length.
//     ty |= 0x02;
//
//     if fin {
//         ty |= 0x01;
//     }
//
//     b.put_varint(u64::from(ty))?;
//
//     b.put_varint(stream_id)?;
//     b.put_varint(offset)?;
//
//     // Always encode length field as 2-byte varint.
//     b.put_varint_with_len(length, 2)?;
//
//     Ok(())
// }
//
// pub fn encode_dgram_header(length: u64, b: &mut octets::OctetsMut) -> Result<()> {
//     let mut ty: u8 = 0x30;
//
//     // Always encode length
//     ty |= 0x01;
//
//     b.put_varint(u64::from(ty))?;
//
//     // Always encode length field as 2-byte varint.
//     b.put_varint_with_len(length, 2)?;
//
//     Ok(())
// }

fn parse_stream_frame(frame_type: u8, b: &mut octets::Octets) -> octets::Result<Frame> {

    let stream_id = b.get_varint_reverse().unwrap();

    let offset = b.get_varint_reverse().unwrap();

    let length = b.get_varint_reverse().unwrap();

    let stream_bytes = b.get_bytes_reverse(length as usize)?.to_vec();


    let fin = frame_type & 0x01 ;



    Ok(Frame::Stream {
        stream_data: stream_bytes,
        length,
        offset,
        stream_id,
        fin
    })
}

fn parse_ack_frame(b: &mut octets::Octets) -> octets::Result<Frame> {

    let connection_id = b.get_varint_reverse().unwrap();

    let highest_record_seq_received = b.get_varint_reverse().unwrap();

    Ok(Frame::ACK {
        highest_record_sn_received: highest_record_seq_received,
        connection_id,
    })
}


fn parse_new_token_frame(b: &mut octets::Octets) -> octets::Result<Frame> {

    let sequence = b.get_varint_reverse().unwrap();

    let token = b.get_bytes_reverse(32).unwrap().buf();

    Ok(Frame::NewToken {
        token: <[u8; 32]>::try_from(token).unwrap(),
       sequence,

    })
}


fn parse_connection_reset_frame(b: &mut octets::Octets) -> octets::Result<Frame> {

    let connection_id = b.get_varint_reverse().unwrap();

    Ok(Frame::ConnectionReset {
        connection_id
    })
}

fn parse_new_address_frame(b: &mut octets::Octets) -> octets::Result<Frame> {

    let address_id = b.get_varint_reverse().unwrap();

    let address_version = b.get_varint_reverse().unwrap();


    let address = match address_version {
        4 => {
            b.get_bytes_reverse(4).unwrap().to_vec()

        },
        6 => {
            b.get_bytes_reverse(16).unwrap().to_vec()
        },
        _ => panic!("Wrong ip address version"),
    };

    let port = b.get_varint_reverse().unwrap();

    Ok(Frame::NewAddress {
        port,
        address,
        address_version,
        address_id
    })
}

fn parse_remove_address_frame(b: &mut octets::Octets) -> octets::Result<Frame> {

    let address_id = b.get_varint_reverse().unwrap();

    Ok(Frame::RemoveAddress {
        address_id
    })
}

fn parse_stream_change_frame(b: &mut octets::Octets) -> octets::Result<Frame> {

    let next_offset = b.get_varint_reverse().unwrap();

    let next_record_stream_id = b.get_varint_reverse().unwrap();



    Ok(Frame::StreamChange {
        next_record_stream_id,
        next_offset,
    })
}




    pub struct TcplsSession {
        pub tls_config: Option<TlsConfig>,
        pub client_tls_conn: Option<ClientConnection>,
        pub server_tls_conn: Option<ServerConnection>,
        pub tcp_connections: HashMap<u32, TcpConnection>,
        pub pending_tcp_connections: HashMap<u32, TcpConnection>,
        pub next_connection_id: u32,
        pub next_local_address_id: u8,
        pub next_remote_address_id: u8,
        pub addresses_advertised: Vec<SocketAddr>,
        pub next_stream_id: u32,
        pub is_server: bool,
        pub is_closed: bool,
        pub tls_hs_completed: bool,

    }

    impl TcplsSession {
        pub fn new() -> Self{
            Self{
                tls_config: None,
                client_tls_conn: None,
                server_tls_conn: None,
                tcp_connections: HashMap::new(),
                pending_tcp_connections: HashMap::new(),
                next_connection_id: 0,
                next_local_address_id: 0,
                addresses_advertised: Vec::new(),
                next_remote_address_id: 0,
                next_stream_id: 0,
                is_server: false,
                is_closed: false,
                tls_hs_completed: false,
            }
        }



    }

    pub enum TlsConfig {
        Client(Arc<ClientConfig>),
        Server(Arc<ServerConfig>),
    }


    pub struct TcpConnection {
        pub connection_id: u32,
        pub socket: TcpStream,
        pub local_address_id: u8,
        pub remote_address_id: u8,
        pub nbr_bytes_received: u32,
        // nbr records received on this con since the last ack sent
        pub nbr_records_received: u32,
        // nbr records received on this con since the last ack sent
        pub is_primary: bool,
        // Is this connection the default one?
        pub state: TcplsConnectionState,

    }


    impl TcpConnection {
        pub fn new(socket: TcpStream) -> Self{
            Self{
                connection_id: 0,
                socket: socket,
                local_address_id: 0,
                remote_address_id: 0,
                nbr_bytes_received: 0,
                nbr_records_received: 0,
                is_primary: false,
                state: TcplsConnectionState::CLOSED,
            }

        }
    }

    pub enum TcplsConnectionState {
        CLOSED,
        INITIALIZED,
        STARTED,         // Handshake started.
        FAILED,
        CONNECTING,
        CONNECTED,       // Handshake completed.
        JOINED,
    }


    pub struct BiStream {

        pub stream_id: u32,

        /**
         * the stream should be cleaned up the next time tcpls_send is called
         */
        pub marked_for_close: bool,

        /**
         * Whether we still have to initialize the aead context for this stream.
         * That may happen if this stream is created before the handshake took place.
         */
        pub aead_initialized: bool,

        /// buffers the decryption of the received TLS records
        pub(crate) received_plaintext: ChunkVecBuffer,
        /// buffers data to be sent if TLS handshake is still ongoing
        pub(crate) sendable_plaintext: ChunkVecBuffer,
        /// buffers encrypted TLS records that to be sent on the TCP socket
        pub(crate) sendable_tls: ChunkVecBuffer,

    }

    impl BiStream {
       pub fn new(id: u32) -> Self {
            Self{
                stream_id: id,
                marked_for_close: false,
                aead_initialized: false,
                received_plaintext: ChunkVecBuffer::new(Some(DEFAULT_RECEIVED_PLAINTEXT_LIMIT)),
                sendable_plaintext: ChunkVecBuffer::new(Some(DEFAULT_BUFFER_LIMIT)),
                sendable_tls: ChunkVecBuffer::new(Some(DEFAULT_BUFFER_LIMIT)),
            }
       }
    }

    pub struct StreamMap {
       pub streams: HashMap<u32, BiStream>,
    }

    impl StreamMap {

        /// Build stream map
        pub fn build_stream_map() -> Self {
            let mut map = HashMap::new();
            let stream = BiStream::new(0);
            map.insert(0, stream);
            Self {
                streams: map,
            }

        }
        /// open a new stream for the specified TCP connection
        pub(crate) fn open_stream(&mut self, conn_id: u32) {
            if !self.streams.contains_key(&conn_id) {
                let stream = BiStream::new(conn_id);
                self.streams.insert(conn_id, stream);
            }
        }

    }



    pub fn lookup_address(host: &str, port: u16) -> SocketAddr {

        let mut  addrs = (host, port).to_socket_addrs().unwrap(); // resolves hostname and return an itr
        addrs.next().expect("Cannot lookup address")
    }


    pub fn build_cert_store(cert_file_path: Option<&String>, cert_store: Option<RootCertStore>) -> RootCertStore {
        let mut root_store = RootCertStore::empty();

        if cert_file_path.is_some(){
            let ca_path = cert_file_path.unwrap();

            let cert_file = fs::File::open(ca_path).expect("Cannot open CA file");
            let mut reader = BufReader::new(cert_file);
            root_store.add_parsable_certificates(&rustls_pemfile::certs(&mut reader).unwrap());

        } else if cert_store.is_none(){
            panic!("either a file path for a cert store or an RootCertStore should be provided")
        } else {
            root_store = cert_store.unwrap();
        }

        root_store
    }

    fn load_ocsp(filename: &Option<String>) -> Vec<u8> {
        let mut ret = Vec::new();
        if let Some(name) = filename {
            fs::File::open(name)
                .expect("cannot open ocsp file")
                .read_to_end(&mut ret)
                .unwrap();
        }
        ret
    }


    /// Find a ciphersuite with the given name
    pub fn find_suite(name: &str) -> Option<SupportedCipherSuite> {
        for suite in ALL_CIPHER_SUITES {
            let sname = format!("{:?}", suite.suite()).to_lowercase();

            if sname == name.to_string().to_lowercase() {
                return Some(*suite);
            }
        }

        None
    }

    /// Make a vector of ciphersuites named in `suites`
    pub fn lookup_suites(suites: &[String]) -> Vec<SupportedCipherSuite> {
        let mut out = Vec::new();

        for csname in suites {
            let scs = find_suite(csname);
            match scs {
                Some(s) => out.push(s),
                None => panic!("cannot look up ciphersuite '{}'", csname),
            }
        }

        out
    }

    /// Make a vector of protocol versions named in `versions`
    pub fn lookup_versions(versions: &[String]) -> Vec<&'static SupportedProtocolVersion> {
        let mut out = Vec::new();

        for vname in versions {
            let version = match vname.as_ref() {
                "1.3" => &version::TLS13,
                _ => panic!(
                    "cannot look up version '{}', TCPLS supports only TLS '1.3'",
                    vname
                ),
            };
            out.push(version);
        }

        out
    }

    pub fn load_certs(filename: &str) -> Vec<Certificate> {
        let certfile = fs::File::open(filename).expect("cannot open certificate file");
        let mut reader = BufReader::new(certfile);
        rustls_pemfile::certs(&mut reader)
            .unwrap()
            .iter()
            .map(|v| Certificate(v.clone()))
            .collect()
    }

    pub fn load_private_key(filename: &str) -> PrivateKey {
        let keyfile = fs::File::open(filename).expect("cannot open private key file");
        let mut reader = BufReader::new(keyfile);

        loop {
            match rustls_pemfile::read_one(&mut reader).expect("cannot parse private key .pem file") {
                Some(rustls_pemfile::Item::RSAKey(key)) => return PrivateKey(key),
                Some(rustls_pemfile::Item::PKCS8Key(key)) => return PrivateKey(key),
                Some(rustls_pemfile::Item::ECKey(key)) => return PrivateKey(key),
                None => break,
                _ => {}
            }
        }

        panic!(
            "no keys found in {:?} (encrypted keys not supported)",
            filename
        );
    }


    pub fn create_tcpls_connection_object(tcpls_session: &mut TcplsSession, socket: TcpStream, is_server: bool) -> u32{
        let mut tcp_conn = TcpConnection::new(socket);

        let new_conn_id = tcpls_session.next_connection_id;
        tcp_conn.connection_id = new_conn_id;
        tcp_conn.local_address_id = tcpls_session.next_local_address_id;
        tcp_conn.remote_address_id = tcpls_session.next_remote_address_id;

        if tcp_conn.connection_id == 0 {
            tcp_conn.is_primary = true;
        }

        // tcpls_session.open_connections_ids.push(tcp_conn.connection_id);
        if !is_server{
            tcpls_session.tcp_connections.insert(new_conn_id, tcp_conn);
        }else {
            tcpls_session.pending_tcp_connections.insert(new_conn_id, tcp_conn);
        }

        tcpls_session.next_connection_id += 1;
        tcpls_session.next_local_address_id += 1;
        tcpls_session.next_remote_address_id += 1;

        new_conn_id

    }




    pub fn tcpls_connect(dest_address: SocketAddr, tcpls_session: &mut TcplsSession, config: Arc<ClientConfig>, server_name: ServerName) {

        let tls_config = config.clone();

        let socket = TcpStream::connect(dest_address).expect("TCP connection establishment failed");
        let new_tcp_conn_id= create_tcpls_connection_object(tcpls_session, socket, false);
        if new_tcp_conn_id == 0{
            let client_conn = ClientConnection::new(tls_config, server_name).expect("Establishment of TLS session failed");
            let _ = tcpls_session.client_tls_conn.insert(client_conn);
            let _ = tcpls_session.tls_config.insert(TlsConfig::Client(config.clone()));
        }

            // prepare_connection_crypto_context(&mut tcpls_session.client_tls_conn.as_mut().unwrap().core.common_state, new_tcp_conn_id);
    }




    // pub(crate) fn prepare_connection_crypto_context(common: &mut CommonState, new_conn_id: u32) {
    //     if new_conn_id > 0 && ! common.is_handshaking() {
    //
    //         common.record_layer.derive_enc_connection_iv(new_conn_id);
    //         common.record_layer.derive_dec_connection_iv(new_conn_id);
    //     }
    // }

    pub fn client_new_tls_connection(config: Arc<ClientConfig>, name: ServerName) -> ClientConnection{

        ClientConnection::new(config, name).expect("Establishing a TLS session has failed")
    }


    /// Build a `rustls::ClientConfig`
    pub fn build_tls_client_config(cert_path: Option<&String>, cert_store: Option<RootCertStore>, cipher_suites: Vec<String>,
                                   protocol_ver: Vec<String>, auth_key: Option<String>, auth_certs: Option<String>,
                                   no_tickets: bool, no_sni: bool, proto: Vec<String>, max_frag_size: Option<usize>) -> Arc<ClientConfig> {

        let root_store = build_cert_store(cert_path, cert_store);

        let suites = if !cipher_suites.is_empty() {
            lookup_suites(&cipher_suites)
        } else {
            DEFAULT_CIPHER_SUITES.to_vec()
        };

        let versions = if !protocol_ver.is_empty() {
            lookup_versions(&protocol_ver)
        } else {
            DEFAULT_VERSIONS.to_vec()
        };

        let config = ClientConfig::builder()
            .with_cipher_suites(&suites)
            .with_safe_default_kx_groups()
            .with_protocol_versions(&versions)
            .expect("inconsistent cipher-suite/versions selected")
            .with_root_certificates(root_store);

        let mut config = match (&auth_key, &auth_certs) {
            (Some(key_file), Some(certs_file)) => {
                let certs = load_certs(certs_file);
                let key = load_private_key(key_file);
                config
                    .with_single_cert(certs, key)
                    .expect("invalid client auth certs/key")
            }
            (None, None) => config.with_no_client_auth(),
            (_, _) => {
                panic!("must provide --auth-certs and --auth-key together");
            }
        };

        config.key_log = Arc::new(KeyLogFile::new());

        if no_tickets {
            config.resumption = config
                .resumption
                .tls12_resumption(crate::client::Tls12Resumption::SessionIdOnly);
        }

        if no_sni {
            config.enable_sni = false;
        }

        config.alpn_protocols =
            proto.iter().map(|proto| proto.as_bytes().to_vec()).collect();

        if max_frag_size.is_some() {
            config.max_fragment_size = max_frag_size;
        }


        Arc::new(config)
    }

    pub fn build_tls_server_config(client_verify: Option<String>, require_auth: bool, suite: Vec<String>,
                               protover: Vec<String>,  certs: Option<String>, key: Option<String>,
                               ocsp: Option<String>, resumption: bool, tickets: bool, proto: Vec<String>) -> Arc<ServerConfig> {
        let client_auth = if client_verify.is_some() {
            let roots = load_certs(client_verify.as_ref().unwrap());
            let mut client_auth_roots = RootCertStore::empty();
            for root in roots {
                client_auth_roots.add(&root).unwrap();
            }
            if require_auth {
                AllowAnyAuthenticatedClient::new(client_auth_roots).boxed()
            } else {
                AllowAnyAnonymousOrAuthenticatedClient::new(client_auth_roots).boxed()
            }
        } else {
            NoClientAuth::boxed()
        };

        let suites = if !suite.is_empty() {
            lookup_suites(&suite)
        } else {
            ALL_CIPHER_SUITES.to_vec()
        };

        let versions = if !protover.is_empty() {
            lookup_versions(&protover)
        } else {
            ALL_VERSIONS.to_vec()
        };

        let certs = load_certs(
            certs
                .as_ref()
                .expect("--certs option missing"),
        );
        let privkey = load_private_key(
            key
                .as_ref()
                .expect("--key option missing"),
        );
        let ocsp = load_ocsp(&ocsp);

        let mut config = ServerConfig::builder()
            .with_cipher_suites(&suites)
            .with_safe_default_kx_groups()
            .with_protocol_versions(&versions)
            .expect("inconsistent cipher-suites/versions specified")
            .with_client_cert_verifier(client_auth)
            .with_single_cert_with_ocsp_and_sct(certs, privkey, ocsp, vec![])
            .expect("bad certificates/private key");

        config.key_log = Arc::new(KeyLogFile::new());

        if resumption {
            config.session_storage = server::ServerSessionMemoryCache::new(256);
        }

        if tickets {
            config.ticketer = Ticketer::new().unwrap();
        }

        config.alpn_protocols = proto
            .iter()
            .map(|proto| proto.as_bytes().to_vec())
            .collect::<Vec<_>>();


        Arc::new(config)
    }


    pub fn server_create_listener(local_address: &str, port: u16) -> TcpListener {

        let mut addr: SocketAddr = local_address.parse().unwrap();

        addr.set_port(port);

        TcpListener::bind(addr).expect("cannot listen on port")
    }

    pub fn server_accept_connection(listener: TcpListener, tcpls_session: &mut TcplsSession, config: Arc<ServerConfig>) {
        let (socket, remote_address) =
            listener.accept().expect("encountered error while accepting connection");

        let conn_id = create_tcpls_connection_object(tcpls_session, socket, true);
        if conn_id == 0 {
            tcpls_session.is_server = true;

            let server_conn =  ServerConnection::new(config.clone()).
                expect("Establishing a TLS session has failed");
            let _ = tcpls_session.server_tls_conn.insert(server_conn);
            let _ = tcpls_session.tls_config.insert(TlsConfig::Server(config.clone()));
        }
    }

    pub fn server_new_tls_connection(config: Arc<ServerConfig>) -> ServerConnection {
        ServerConnection::new(config).expect("Establishing a TLS session has failed")
    }





/// A TLS client or server connection.
// #[derive(Debug)]
// pub enum Connection {
//     /// A client connection
//     Client(ClientConnection),
//     /// A server connection
//     Server(ServerConnection),
// }


/// A TCPLS client connection.
pub struct ClientConnection {
    inner: ConnectionCommon<ClientConnectionData>,
}

impl ClientConnection {
    /// Make a new TLS ClientConnection.
    pub fn new(
        config: Arc<ClientConfig>,
        name: ServerName,
    ) -> Result<Self, Error> {
        if !config.supports_version(ProtocolVersion::TLSv1_3) {
            return Err(Error::General(
                "TLS 1.3 support is required for TCPLS".into(),
            ));
        }

        let ext = ClientExtension::TCPLS;

        Ok(Self {
            inner: ConnectionCore::for_client(config, name, vec![ext], Protocol::Tcpls)?.into(),
        })
    }

}


impl Deref for ClientConnection {
    type Target = ConnectionCommon<ClientConnectionData>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for ClientConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Debug for ClientConnection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("tcpls::ClientConnection")
            .finish()
    }
}
// impl From<ClientConnection> for Connection {
//     fn from(c: ClientConnection) -> Self {
//         Client(c)
//     }
// }

/// A TCPLS server connection.
pub struct ServerConnection {
    inner: ConnectionCommon<ServerConnectionData>,
}

impl ServerConnection {
    /// Make a new TLS ServerConnection.
    pub fn new(
        config: Arc<ServerConfig>,
    ) -> Result<Self, Error> {
        if !config.supports_version(ProtocolVersion::TLSv1_3) {
            return Err(Error::General(
                "TLS 1.3 support is required for TCPLS".into(),
            ));
        }

        let ext = ServerExtension::TCPLS;

        let mut core = ConnectionCore::for_server(config, vec![ext])?;
        core.common_state.protocol = Protocol::Tcpls;
        Ok(Self { inner: core.into() })
    }
}
impl Deref for ServerConnection {
    type Target = ConnectionCommon<ServerConnectionData>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for ServerConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Debug for ServerConnection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("tcpls::ServerConnection")
            .finish()
    }
}
// impl From<ServerConnection> for Connection {
//     fn from(c: ServerConnection) -> Self {
//         Self::Server(c)
//     }
// }

// #[test]
/*fn test_prep_crypto_context(){

    let mut iv= Iv::copy(&[0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]) ;
    let mut iv_vec = vec![iv];

    let iv_2= Iv::copy(&[0x0C, 0x0B, 0x0A, 0x08, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]) ;
    let connection_id:u32 = 0x01;
    derive_connection_iv(&mut iv_vec, connection_id);
   assert_eq!(iv_2.value(), iv_vec.get(1).unwrap().value())

   }*/


//#[test]
 fn test_encode_decode_stream_frame(){

    let mut buf = [0;32] ;

    let mut stream_frame = Frame::Stream {
        stream_data: vec![0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF],
        length: 24,
        offset: 66000,
        stream_id: 500,
        fin: 1,
    };

    let mut d = octets::OctetsMut::with_slice(&mut buf);

    stream_frame.encode(&mut d).unwrap();

    let mut c = octets::Octets::with_slice_reverse(&mut buf);

   let stream_frame_2 = Frame::parse(&mut c).unwrap();

    assert_eq!(stream_frame, stream_frame_2);

}


#[test]
fn test_encode_decode_ack_frame(){

    let mut buf = [0;6] ;

    let mut ack_frame = Frame::ACK {
      highest_record_sn_received: 1753698,
        connection_id: 8,
    };

    let mut d = octets::OctetsMut::with_slice(&mut buf);

    ack_frame.encode(&mut d).unwrap();

    let mut c = octets::Octets::with_slice_reverse(&mut buf);

    let ack_frame_2 = Frame::parse(&mut c).unwrap();

    assert_eq!(ack_frame, ack_frame_2);

}

//#[test]
fn test_encode_decode_new_token_frame(){

    let mut buf = [0;37] ;

    let mut token_frame = Frame::NewToken {
        token: [0x0F;32],
        sequence: 854785486,
    };

    let mut d = octets::OctetsMut::with_slice(&mut buf);

    token_frame.encode(&mut d).unwrap();

    let mut c = octets::Octets::with_slice_reverse(&mut buf);

    let token_frame_2 = Frame::parse(&mut c).unwrap();

    assert_eq!(token_frame, token_frame_2);

}



//#[test]
fn test_parse_new_address_frame(){

    let mut v4 = [0;12] ;

    let mut v4_frame= Frame::NewAddress {
        port: 9874,
        address: vec![0x0A, 0x00, 0x00, 0x0C],
        address_version: 0x04,
        address_id: 47854755,

    };

    let mut d = octets::OctetsMut::with_slice(&mut v4);

    v4_frame.encode(&mut d).unwrap();

    let mut c = octets::Octets::with_slice_reverse(&mut v4);

    let v4_frame_2 = Frame::parse(&mut c).unwrap();

    assert_eq!(v4_frame, v4_frame_2);


    let mut v6 = [0;30] ;

    let mut v6_frame= Frame::NewAddress {
        port: 987455,
        address: vec![0x0A, 0x00, 0x00, 0x0C, 0x0A, 0x00, 0x00, 0x0C, 0x0A, 0x00, 0x00, 0x0C, 0x0A, 0x00, 0x00, 0x0C],
        address_version: 0x06,
        address_id: 4785475585858,

    };

    let mut d = octets::OctetsMut::with_slice(&mut v6);

    v6_frame.encode(&mut d).unwrap();

    let mut c = octets::Octets::with_slice_reverse(&mut v6);

    let v6_frame_2 = Frame::parse(&mut c).unwrap();

    assert_eq!(v6_frame, v6_frame_2);

}