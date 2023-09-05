use crate::InvalidMessage;

pub const STREAM_FRAME_MAX_OVERHEAD: usize = 25; // Type = 1 Byte + Stream Id = 8 Bytes + Offset = 8 Bytes + Length = 8 Bytes

pub const TCPLS_STREAM_FRAME_MAX_PAYLOAD_LENGTH: usize =
    crate::msgs::fragmenter::MAX_FRAGMENT_LEN - STREAM_FRAME_MAX_OVERHEAD;

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
    },
}

impl Frame {
    pub fn parse(b: &mut octets::Octets) -> Result<Frame, InvalidMessage> {
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
            Frame::Padding => {
                b.put_varint(0x00).unwrap();
            }
            Frame::Ping => {
                b.put_varint(0x01).unwrap();
            }
            Frame::Stream {
                stream_data,
                length,
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
                } else {
                    b.put_varint(0x03).unwrap();
                }
            }

            Frame::ACK {
                highest_record_sn_received,
                connection_id,
            } => {
                b.put_varint_reverse(*highest_record_sn_received).unwrap();
                b.put_varint_reverse(*connection_id).unwrap();
                b.put_varint(0x04).unwrap();
            }

            Frame::NewToken { token, sequence } => {
                b.put_bytes(token).unwrap();
                b.put_varint_reverse(*sequence).unwrap();
                b.put_varint(0x05).unwrap();
            }

            Frame::ConnectionReset { connection_id } => {
                b.put_varint_reverse(*connection_id).unwrap();
                b.put_varint(0x06).unwrap();
            }
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
            }

            Frame::RemoveAddress { address_id } => {
                b.put_varint_reverse(*address_id).unwrap();
                b.put_varint(0x08).unwrap();
            }

            Frame::StreamChange {
                next_record_stream_id,
                next_offset,
            } => {
                b.put_varint_reverse(*next_record_stream_id).unwrap();
                b.put_varint_reverse(*next_offset).unwrap();
                b.put_varint(0x09).unwrap();
            }

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

    let fin = frame_type & 0x01;

    Ok(Frame::Stream {
        stream_data: stream_bytes,
        length,
        offset,
        stream_id,
        fin,
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

    Ok(Frame::ConnectionReset { connection_id })
}

fn parse_new_address_frame(b: &mut octets::Octets) -> octets::Result<Frame> {
    let address_id = b.get_varint_reverse().unwrap();

    let address_version = b.get_varint_reverse().unwrap();

    let address = match address_version {
        4 => b.get_bytes_reverse(4).unwrap().to_vec(),
        6 => b.get_bytes_reverse(16).unwrap().to_vec(),
        _ => panic!("Wrong ip address version"),
    };

    let port = b.get_varint_reverse().unwrap();

    Ok(Frame::NewAddress {
        port,
        address,
        address_version,
        address_id,
    })
}

fn parse_remove_address_frame(b: &mut octets::Octets) -> octets::Result<Frame> {
    let address_id = b.get_varint_reverse().unwrap();

    Ok(Frame::RemoveAddress { address_id })
}

fn parse_stream_change_frame(b: &mut octets::Octets) -> octets::Result<Frame> {
    let next_offset = b.get_varint_reverse().unwrap();

    let next_record_stream_id = b.get_varint_reverse().unwrap();

    Ok(Frame::StreamChange {
        next_record_stream_id,
        next_offset,
    })
}

#[test]
fn test_encode_decode_stream_frame() {
    let mut buf = [0; 32];

    let mut stream_frame = Frame::Stream {
        stream_data: vec![
            0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD,
            0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
        ],
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
fn test_encode_decode_ack_frame() {
    let mut buf = [0; 6];

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

#[test]
fn test_encode_decode_new_token_frame() {
    let mut buf = [0; 37];

    let mut token_frame = Frame::NewToken {
        token: [0x0F; 32],
        sequence: 854785486,
    };

    let mut d = octets::OctetsMut::with_slice(&mut buf);

    token_frame.encode(&mut d).unwrap();

    let mut c = octets::Octets::with_slice_reverse(&mut buf);

    let token_frame_2 = Frame::parse(&mut c).unwrap();

    assert_eq!(token_frame, token_frame_2);
}

#[test]
fn test_parse_new_address_frame() {
    let mut v4 = [0; 12];

    let mut v4_frame = Frame::NewAddress {
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

    let mut v6 = [0; 30];

    let mut v6_frame = Frame::NewAddress {
        port: 987455,
        address: vec![
            0x0A, 0x00, 0x00, 0x0C, 0x0A, 0x00, 0x00, 0x0C, 0x0A, 0x00, 0x00, 0x0C, 0x0A, 0x00,
            0x00, 0x0C,
        ],
        address_version: 0x06,
        address_id: 4785475585858,
    };

    let mut d = octets::OctetsMut::with_slice(&mut v6);

    v6_frame.encode(&mut d).unwrap();

    let mut c = octets::Octets::with_slice_reverse(&mut v6);

    let v6_frame_2 = Frame::parse(&mut c).unwrap();

    assert_eq!(v6_frame, v6_frame_2);
}
