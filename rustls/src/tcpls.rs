#![allow(missing_docs)]

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
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::fs;
use std::io::{BufReader, Read};
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use octets::BufferTooShortError;


pub const TCPLS_STREAM_FRAME_MAX_PAYLOAD_LENGTH: usize = crate::msgs::fragmenter::MAX_FRAGMENT_LEN - STREAM_FRAME_OVERHEAD;

pub const STREAM_FRAME_OVERHEAD: usize = 15; // Type = 1 Byte + Stream Id = 4 Bytes + Offset = 8 Bytes + Length = 2 Bytes


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
    pub fn from_bytes(
        b: &mut octets::Octets) -> Result<Frame, InvalidMessage> {
        let frame_type = b.peek_u8().expect("failed");

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

    pub fn to_bytes(&self, b: &mut octets::OctetsMut) -> Result<usize, InvalidMessage> {
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
                b.put_varint_backwards(*length).unwrap();
                b.put_varint_backwards(*offset).unwrap();
                b.put_varint_backwards(*stream_id).unwrap();
                if fin == 0 {
                    b.put_varint(0x02).unwrap();
                }else {
                    b.put_varint(0x03).unwrap();
                }
            },

            Frame::ACK {
                highest_record_sn_received,
                connection_id,
            } => {
                b.put_varint_backwards(*highest_record_sn_received).unwrap();
                b.put_varint_backwards(*connection_id).unwrap();
                b.put_varint(0x04).unwrap();
            },

            Frame::NewToken {
                token,
                sequence,
            } => {
                b.put_bytes(token).unwrap();
                b.put_varint_backwards(*sequence).unwrap();
                b.put_varint(0x05).unwrap();
            },

            Frame::ConnectionReset {
                connection_id,
            } => {
                b.put_varint_backwards(*connection_id).unwrap();
                b.put_varint(0x06).unwrap();
            },
            Frame::NewAddress {
                port,
                address,
                address_version,
                address_id,
            } => {
                b.put_varint_backwards(*port).unwrap();
                b.put_bytes(address.as_ref()).unwrap();
                b.put_varint_backwards(*address_version).unwrap();
                b.put_varint_backwards(*address_id).unwrap();
                b.put_varint(0x07).unwrap();

            },

            Frame::RemoveAddress {
                address_id
            } => {
                b.put_varint_backwards(*address_id).unwrap();
                b.put_varint(0x08).unwrap();
            },

            Frame::StreamChange {
                next_record_stream_id,
                next_offset,
            } => {
                b.put_varint_backwards(*next_record_stream_id).unwrap();
                b.put_varint_backwards(*next_offset).unwrap();
                b.put_varint(0x09).unwrap();
            },

            _ => {}
        }

    //
    //         Frame::ResetStream {
    //             stream_id,
    //             error_code,
    //             final_size,
    //         } => {
    //             b.put_varint(0x04)?;
    //
    //             b.put_varint(*stream_id)?;
    //             b.put_varint(*error_code)?;
    //             b.put_varint(*final_size)?;
    //         },
    //
    //         Frame::StopSending {
    //             stream_id,
    //             error_code,
    //         } => {
    //             b.put_varint(0x05)?;
    //
    //             b.put_varint(*stream_id)?;
    //             b.put_varint(*error_code)?;
    //         },
    //
    //         Frame::Crypto { data } => {
    //             encode_crypto_header(data.off(), data.len() as u64, b)?;
    //
    //             b.put_bytes(data)?;
    //         },
    //
    //         Frame::CryptoHeader { .. } => (),
    //
    //         Frame::NewToken { token } => {
    //             b.put_varint(0x07)?;
    //
    //             b.put_varint(token.len() as u64)?;
    //             b.put_bytes(token)?;
    //         },
    //
    //         Frame::Stream { stream_id, data } => {
    //             encode_stream_header(
    //                 *stream_id,
    //                 data.off(),
    //                 data.len() as u64,
    //                 data.fin(),
    //                 b,
    //             )?;
    //
    //             b.put_bytes(data)?;
    //         },
    //
    //         Frame::StreamHeader { .. } => (),
    //
    //         Frame::MaxData { max } => {
    //             b.put_varint(0x10)?;
    //
    //             b.put_varint(*max)?;
    //         },
    //
    //         Frame::MaxStreamData { stream_id, max } => {
    //             b.put_varint(0x11)?;
    //
    //             b.put_varint(*stream_id)?;
    //             b.put_varint(*max)?;
    //         },
    //
    //         Frame::MaxStreamsBidi { max } => {
    //             b.put_varint(0x12)?;
    //
    //             b.put_varint(*max)?;
    //         },
    //
    //         Frame::MaxStreamsUni { max } => {
    //             b.put_varint(0x13)?;
    //
    //             b.put_varint(*max)?;
    //         },
    //
    //         Frame::DataBlocked { limit } => {
    //             b.put_varint(0x14)?;
    //
    //             b.put_varint(*limit)?;
    //         },
    //
    //         Frame::StreamDataBlocked { stream_id, limit } => {
    //             b.put_varint(0x15)?;
    //
    //             b.put_varint(*stream_id)?;
    //             b.put_varint(*limit)?;
    //         },
    //
    //         Frame::StreamsBlockedBidi { limit } => {
    //             b.put_varint(0x16)?;
    //
    //             b.put_varint(*limit)?;
    //         },
    //
    //         Frame::StreamsBlockedUni { limit } => {
    //             b.put_varint(0x17)?;
    //
    //             b.put_varint(*limit)?;
    //         },
    //
    //         Frame::NewConnectionId {
    //             seq_num,
    //             retire_prior_to,
    //             conn_id,
    //             reset_token,
    //         } => {
    //             b.put_varint(0x18)?;
    //
    //             b.put_varint(*seq_num)?;
    //             b.put_varint(*retire_prior_to)?;
    //             b.put_u8(conn_id.len() as u8)?;
    //             b.put_bytes(conn_id.as_ref())?;
    //             b.put_bytes(reset_token.as_ref())?;
    //         },
    //
    //         Frame::RetireConnectionId { seq_num } => {
    //             b.put_varint(0x19)?;
    //
    //             b.put_varint(*seq_num)?;
    //         },
    //
    //         Frame::PathChallenge { data } => {
    //             b.put_varint(0x1a)?;
    //
    //             b.put_bytes(data.as_ref())?;
    //         },
    //
    //         Frame::PathResponse { data } => {
    //             b.put_varint(0x1b)?;
    //
    //             b.put_bytes(data.as_ref())?;
    //         },
    //
    //         Frame::ConnectionClose {
    //             error_code,
    //             frame_type,
    //             reason,
    //         } => {
    //             b.put_varint(0x1c)?;
    //
    //             b.put_varint(*error_code)?;
    //             b.put_varint(*frame_type)?;
    //             b.put_varint(reason.len() as u64)?;
    //             b.put_bytes(reason.as_ref())?;
    //         },
    //
    //         Frame::ApplicationClose { error_code, reason } => {
    //             b.put_varint(0x1d)?;
    //
    //             b.put_varint(*error_code)?;
    //             b.put_varint(reason.len() as u64)?;
    //             b.put_bytes(reason.as_ref())?;
    //         },
    //
    //         Frame::HandshakeDone => {
    //             b.put_varint(0x1e)?;
    //         },
    //
    //         Frame::Datagram { data } => {
    //             encode_dgram_header(data.len() as u64, b)?;
    //
    //             b.put_bytes(data.as_ref())?;
    //         },
    //
    //         Frame::DatagramHeader { .. } => (),
    //     }
    //
        Ok(before - b.cap())
    }

    // pub fn wire_len(&self) -> usize {
    //     match self {
    //         Frame::Padding { len } => *len,
    //
    //         Frame::Ping => 1,
    //
    //         Frame::ACK {
    //             ack_delay,
    //             ranges,
    //             ecn_counts,
    //         } => {
    //             let mut it = ranges.iter().rev();
    //
    //             let first = it.next().unwrap();
    //             let ack_block = (first.end - 1) - first.start;
    //
    //             let mut len = 1 + // frame type
    //                 octets::varint_len(first.end - 1) + // largest_ack
    //                 octets::varint_len(*ack_delay) + // ack_delay
    //                 octets::varint_len(it.len() as u64) + // block_count
    //                 octets::varint_len(ack_block); // first_block
    //
    //             let mut smallest_ack = first.start;
    //
    //             for block in it {
    //                 let gap = smallest_ack - block.end - 1;
    //                 let ack_block = (block.end - 1) - block.start;
    //
    //                 len += octets::varint_len(gap) + // gap
    //                     octets::varint_len(ack_block); // ack_block
    //
    //                 smallest_ack = block.start;
    //             }
    //
    //             if let Some(ecn) = ecn_counts {
    //                 len += octets::varint_len(ecn.ect0_count) +
    //                     octets::varint_len(ecn.ect1_count) +
    //                     octets::varint_len(ecn.ecn_ce_count);
    //             }
    //
    //             len
    //         },
    //
    //         Frame::ResetStream {
    //             stream_id,
    //             error_code,
    //             final_size,
    //         } => {
    //             1 + // frame type
    //                 octets::varint_len(*stream_id) + // stream_id
    //                 octets::varint_len(*error_code) + // error_code
    //                 octets::varint_len(*final_size) // final_size
    //         },
    //
    //         Frame::StopSending {
    //             stream_id,
    //             error_code,
    //         } => {
    //             1 + // frame type
    //                 octets::varint_len(*stream_id) + // stream_id
    //                 octets::varint_len(*error_code) // error_code
    //         },
    //
    //         Frame::Crypto { data } => {
    //             1 + // frame type
    //                 octets::varint_len(data.off()) + // offset
    //                 2 + // length, always encode as 2-byte varint
    //                 data.len() // data
    //         },
    //
    //         Frame::CryptoHeader { offset, length, .. } => {
    //             1 + // frame type
    //                 octets::varint_len(*offset) + // offset
    //                 2 + // length, always encode as 2-byte varint
    //                 length // data
    //         },
    //
    //         Frame::NewToken { token } => {
    //             1 + // frame type
    //                 octets::varint_len(token.len() as u64) + // token length
    //                 token.len() // token
    //         },
    //
    //         Frame::Stream { stream_id, data } => {
    //             1 + // frame type
    //                 octets::varint_len(*stream_id) + // stream_id
    //                 octets::varint_len(data.off()) + // offset
    //                 2 + // length, always encode as 2-byte varint
    //                 data.len() // data
    //         },
    //
    //         Frame::StreamHeader {
    //             stream_id,
    //             offset,
    //             length,
    //             ..
    //         } => {
    //             1 + // frame type
    //                 octets::varint_len(*stream_id) + // stream_id
    //                 octets::varint_len(*offset) + // offset
    //                 2 + // length, always encode as 2-byte varint
    //                 length // data
    //         },
    //
    //         Frame::MaxData { max } => {
    //             1 + // frame type
    //                 octets::varint_len(*max) // max
    //         },
    //
    //         Frame::MaxStreamData { stream_id, max } => {
    //             1 + // frame type
    //                 octets::varint_len(*stream_id) + // stream_id
    //                 octets::varint_len(*max) // max
    //         },
    //
    //         Frame::MaxStreamsBidi { max } => {
    //             1 + // frame type
    //                 octets::varint_len(*max) // max
    //         },
    //
    //         Frame::MaxStreamsUni { max } => {
    //             1 + // frame type
    //                 octets::varint_len(*max) // max
    //         },
    //
    //         Frame::DataBlocked { limit } => {
    //             1 + // frame type
    //                 octets::varint_len(*limit) // limit
    //         },
    //
    //         Frame::StreamDataBlocked { stream_id, limit } => {
    //             1 + // frame type
    //                 octets::varint_len(*stream_id) + // stream_id
    //                 octets::varint_len(*limit) // limit
    //         },
    //
    //         Frame::StreamsBlockedBidi { limit } => {
    //             1 + // frame type
    //                 octets::varint_len(*limit) // limit
    //         },
    //
    //         Frame::StreamsBlockedUni { limit } => {
    //             1 + // frame type
    //                 octets::varint_len(*limit) // limit
    //         },
    //
    //         Frame::NewConnectionId {
    //             seq_num,
    //             retire_prior_to,
    //             conn_id,
    //             reset_token,
    //         } => {
    //             1 + // frame type
    //                 octets::varint_len(*seq_num) + // seq_num
    //                 octets::varint_len(*retire_prior_to) + // retire_prior_to
    //                 1 + // conn_id length
    //                 conn_id.len() + // conn_id
    //                 reset_token.len() // reset_token
    //         },
    //
    //         Frame::RetireConnectionId { seq_num } => {
    //             1 + // frame type
    //                 octets::varint_len(*seq_num) // seq_num
    //         },
    //
    //         Frame::PathChallenge { .. } => {
    //             1 + // frame type
    //                 8 // data
    //         },
    //
    //         Frame::PathResponse { .. } => {
    //             1 + // frame type
    //                 8 // data
    //         },
    //
    //         Frame::ConnectionClose {
    //             frame_type,
    //             error_code,
    //             reason,
    //             ..
    //         } => {
    //             1 + // frame type
    //                 octets::varint_len(*error_code) + // error_code
    //                 octets::varint_len(*frame_type) + // frame_type
    //                 octets::varint_len(reason.len() as u64) + // reason_len
    //                 reason.len() // reason
    //         },
    //
    //         Frame::ApplicationClose { reason, error_code } => {
    //             1 + // frame type
    //                 octets::varint_len(*error_code) + // error_code
    //                 octets::varint_len(reason.len() as u64) + // reason_len
    //                 reason.len() // reason
    //         },
    //
    //         Frame::HandshakeDone => {
    //             1 // frame type
    //         },
    //
    //         Frame::Datagram { data } => {
    //             1 + // frame type
    //                 2 + // length, always encode as 2-byte varint
    //                 data.len() // data
    //         },
    //
    //         Frame::DatagramHeader { length } => {
    //             1 + // frame type
    //                 2 + // length, always encode as 2-byte varint
    //                 *length // data
    //         },
    //     }
    // }

    // pub fn ack_eliciting(&self) -> bool {
    //     // Any other frame is ack-eliciting (note the `!`).
    //     !matches!(
    //         self,
    //         Frame::Padding { .. } |
    //             Frame::ACK { .. } |
    //             Frame::ApplicationClose { .. } |
    //             Frame::ConnectionClose { .. }
    //     )
    // }
    //
    // pub fn probing(&self) -> bool {
    //     matches!(
    //         self,
    //         Frame::Padding { .. } |
    //             Frame::NewConnectionId { .. } |
    //             Frame::PathChallenge { .. } |
    //             Frame::PathResponse { .. }
    //     )
    // }


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

fn parse_stream_frame(frame_type: u8, b: &mut octets::Octets) -> Result<Frame, BufferTooShortError> {


    b.reverse(size_of::<u8>())?; // check first byte after 'type' byte
    let stream_id = b.peek_varint_backwards().unwrap();

    b.reverse(size_of::<u8>())?; // go one step backwards to check the encoding length of the next VaInt
    let offset = b.peek_varint_backwards().unwrap();

    b.reverse(size_of::<u8>())?;
    let length = b.peek_varint_backwards().unwrap();

    b.reverse(length as usize)?;

    let stream_bytes = b.peek_bytes(length as usize)?.to_vec();


    let fin = frame_type & 0x01 ;



    Ok(Frame::Stream {
        stream_data: stream_bytes,
        length,
        offset,
        stream_id,
        fin
    })
}

fn parse_ack_frame(b: &mut octets::Octets) -> Result<Frame, BufferTooShortError> {

    b.reverse(size_of::<u8>())?;
    let connection_id = b.peek_varint_backwards().unwrap();

    b.reverse(size_of::<u8>())?;
    let highest_record_seq_received = b.peek_varint_backwards().unwrap();

    Ok(Frame::ACK {
        highest_record_sn_received: highest_record_seq_received,
        connection_id,
    })
}


fn parse_new_token_frame(b: &mut octets::Octets) -> Result<Frame, BufferTooShortError> {

    b.reverse(size_of::<u8>())?;
    let sequence = b.peek_varint_backwards().unwrap();

    b.reverse(32)?;
    let token = b.peek_bytes(32).unwrap().buf();

    Ok(Frame::NewToken {
        token: <[u8; 32]>::try_from(token).unwrap(),
       sequence,

    })
}


fn parse_connection_reset_frame(b: &mut octets::Octets) -> Result<Frame, BufferTooShortError> {

    b.reverse(size_of::<u8>())?;
    let connection_id = b.peek_varint_backwards().unwrap();

    Ok(Frame::ConnectionReset {
        connection_id
    })
}

fn parse_new_address_frame(b: &mut octets::Octets) -> Result<Frame, BufferTooShortError> {

    b.reverse(size_of::<u8>())?;
    let address_id = b.peek_varint_backwards().unwrap();

    b.reverse(size_of::<u8>())?;
    let address_version = b.peek_varint_backwards().unwrap();


    let address = match address_version {
        4 => {
            b.reverse(size_of::<u32>())?;
            b.peek_bytes(4).unwrap().to_vec()

        },
        6 => {
            b.reverse(16)?;
            b.peek_bytes(16).unwrap().to_vec()
        },
        _ => panic!("Wrong ip address version"),
    };
    b.reverse(size_of::<u8>())?;
    let port = b.peek_varint_backwards().unwrap();

    Ok(Frame::NewAddress {
        port,
        address,
        address_version,
        address_id
    })
}

fn parse_remove_address_frame(b: &mut octets::Octets) -> Result<Frame, BufferTooShortError> {

    b.reverse(size_of::<u8>())?;
    let address_id = b.peek_varint_backwards().unwrap();

    Ok(Frame::RemoveAddress {
        address_id
    })
}

fn parse_stream_change_frame(b: &mut octets::Octets) -> Result<Frame, BufferTooShortError> {

    b.reverse(size_of::<u8>())?;
    let next_offset = b.peek_varint_backwards().unwrap();

    b.reverse(size_of::<u8>())?;
    let next_record_stream_id = b.peek_varint_backwards().unwrap();



    Ok(Frame::StreamChange {
        next_record_stream_id,
        next_offset,
    })
}


// fn bytes_to_ipv6(bytes: &[u8]) -> IpAddr {
//     IpAddr::V6(Ipv6Addr::new(u16::from_be_bytes(bytes[..2].try_into().unwrap()),
//                              u16::from_be_bytes(bytes[2..4].try_into().unwrap()),
//                              u16::from_be_bytes(bytes[4..6].try_into().unwrap()),
//                              u16::from_be_bytes(bytes[6..8].try_into().unwrap()),
//                              u16::from_be_bytes(bytes[8..10].try_into().unwrap()),
//                              u16::from_be_bytes(bytes[10..12].try_into().unwrap()),
//                              u16::from_be_bytes(bytes[12..14].try_into().unwrap()),
//                              u16::from_be_bytes(bytes[14..16].try_into().unwrap())))
// }

// fn parse_datagram_frame(ty: u64, b: &mut octets::Octets) -> Result<Frame> {
//     let first = ty as u8;
//
//     let len = if first & 0x01 != 0 {
//         b.get_varint()? as usize
//     } else {
//         b.cap()
//     };
//
//     let data = b.get_bytes(len)?;
//
//     Ok(Frame::Datagram {
//         data: Vec::from(data.buf()),
//     })
// }

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
        pub attached_stream: Option<Stream>,
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
                attached_stream: None,
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


    pub struct Stream {

        stream_id: u32,
        /** when this stream should first send an attach event before
                            * sending any packet */
        need_sending_attach_event: u32,
        /**
         * As soon as we have sent a stream attach event to the other peer, this
         * stream is usable
         */
        stream_usable: bool,

        /**
         * the stream should be cleaned up the next time tcpls_send is called
         */
        marked_for_close: bool,

        /**
         * Whether we still have to initialize the aead context for this stream.
         * That may happen if this stream is created before the handshake took place.
         */
        aead_initialized: bool,

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

#[test]
fn test_prep_crypto_context(){

    let mut iv= Iv::copy(&[0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]) ;
    let mut iv_vec = vec![iv];

    let iv_2= Iv::copy(&[0x0C, 0x0B, 0x0A, 0x08, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]) ;
    let connection_id:u32 = 0x01;
    derive_connection_iv(&mut iv_vec, connection_id);
   assert_eq!(iv_2.value(), iv_vec.get(1).unwrap().value())

   }


#[test]
fn test_parse_stream_frame(){

    let mut buf:&[u8] = &[0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x02, 0x03] ;

    let mut d = octets::Octets::with_slice_reverse(&mut buf);

    let stream_frame = Frame::from_bytes(&mut d).unwrap();

    let stream_frame_2 = Frame::Stream {
        stream_data:vec![0x0C, 0x0B, 0x0A, 0x09, 0x08],
        length: 5,
        offset: 6,
        stream_id: 2,
        fin: 1,
    };

    assert_eq!(stream_frame, stream_frame_2);

}
#[test]
fn test_parse_new_token_frame(){

    let mut buf:&[u8] = &[0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x02, 0x03
                                , 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x02, 0x03, 0x02, 0x05];

    let mut d = octets::Octets::with_slice_reverse(&mut buf);

    let new_token_frame = Frame::from_bytes(&mut d).unwrap();

    let new_token_frame_2 = Frame::NewToken {
        token: [0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x06, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x02, 0x03],
        sequence: 0x02,
    };

    assert_eq!(new_token_frame, new_token_frame_2);

}
#[test]
fn test_parse_new_address_frame(){

    let mut v4:&[u8] = &[0x00, 0x06, 0x0A, 0x00, 0x00, 0x02, 0x04, 0x02, 0x07];


    let mut d = octets::Octets::with_slice_reverse(&mut v4);

    let new_v4_frame = Frame::from_bytes(&mut d).unwrap();

    let new_v4_frame_2 = Frame::NewAddress {
        port: 6,
        address: vec![0x0A, 0x00, 0x00, 0x02],
        address_version: 0x04,
        address_id:0x02,
    };

    assert_eq!(new_v4_frame, new_v4_frame_2);

    let mut v6: &[u8] = &[0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x06, 0x03, 0x07];
    
    let mut d = octets::Octets::with_slice_reverse(&mut v6);

    let new_v6_frame = Frame::from_bytes(&mut d).unwrap();

    let new_v6_frame_2 = Frame::NewAddress {
        port: 0x0C0B,
        address: bytes_to_ipv6(&[0x0A, 0x09, 0x08, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00]),
        address_version: 0x06,
        address_id:0x03,
    };
    assert_eq!(new_v6_frame, new_v6_frame_2);

}