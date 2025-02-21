use std::prelude::rust_2021::Vec;

use octets::varint_len;
use crate::{Error, InvalidMessage};
use crate::msgs::fragmenter::MAX_FRAGMENT_LEN;


pub const SAMPLE_PAYLOAD_LENGTH: usize = 16;

pub const STREAM_FRAME_HEADER_SIZE: usize = 15;

pub const MAX_TCPLS_FRAGMENT_LEN: usize = MAX_FRAGMENT_LEN - TCPLS_OVERHEAD;

pub const TCPLS_OVERHEAD: usize = STREAM_FRAME_HEADER_SIZE;


#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Frame {
    Padding,

    Ping,

    Stream {
        length: u16,
        offset: u64,
        stream_id: u32,
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
        next_record_stream_id: u32,
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
                length,
                offset,
                stream_id,
                fin,

            } => {
                b.put_u16(*length).unwrap();
                b.put_u64(*offset).unwrap();
                b.put_u32(*stream_id).unwrap();
                match fin {
                    1 => b.put_u8(0x03).unwrap(),
                    0 => b.put_u8(0x02).unwrap(),
                    _ => panic!("invalid value for flag fin"),

                };
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
                b.put_u32(*next_record_stream_id).unwrap();
                b.put_u64(*next_offset).unwrap();
                b.put_varint(0x09).unwrap();
            }

        }

        Ok(before - b.cap())
    }

    pub fn get_frame_size_reverse(b: &mut octets::Octets) -> Result<usize, InvalidMessage> {

        let frame_type = b.get_u8_reverse().expect("failed");

        let frame_size = match frame_type {
            0x00 => 1 ,

            0x01 => 1 ,

            0x02..=0x03 => 3,

            0x04 => {
                1 + varint_len(b.get_varint_reverse().unwrap()) +
                    varint_len(b.get_varint_reverse().unwrap())
            },


            0x05 => {
                1 + varint_len(b.get_varint_reverse().unwrap()) + 32
            },

            0x06 => {
                1 + varint_len(b.get_varint_reverse().unwrap())
            },

            0x07 => {
                let mut frame_len = 1 + varint_len(b.get_varint_reverse().unwrap());
                let address_len = match b.get_varint_reverse().unwrap() {
                    4 => {
                        b.rewind(4).unwrap();
                        4
                    },
                    6 => {
                        b.rewind(16).unwrap();
                        16
                    },
                    _ => panic!("Wrong ip address version"),
                };
                // one byte for address version + address length + length of port encoding
                   frame_len += 1 + address_len + varint_len(b.get_varint_reverse().unwrap());
                frame_len

            },

            0x08 => { 1 + varint_len(b.get_varint_reverse().unwrap()) },

            0x09 => { 1 + varint_len(b.get_varint_reverse().unwrap())
                        + varint_len(b.get_varint_reverse().unwrap())
            },

            _ => return Err(InvalidMessage::InvalidFrameType.into()),
        };

        Ok(frame_size)
    }



}

fn parse_stream_frame(frame_type: u8, b: &mut octets::Octets) -> octets::Result<Frame> {
    let stream_id = b.get_u32_reverse().unwrap();
    let offset = b.get_u64_reverse().unwrap();
    let length = b.get_u16_reverse().unwrap();

    let fin = match frame_type {
        2 => 0,
        3 => 1,
        _ => panic!("Invalid frame type"),
    };

    Ok(Frame::Stream {
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
    let offset = b.get_u64_reverse().unwrap();
    let stream_id = b.get_u32_reverse().unwrap();


    Ok(Frame::StreamChange {
        next_record_stream_id: stream_id,
        next_offset: offset,
    })
}
#[derive(Default, PartialEq, Debug)]
pub struct TcplsHeader {
    pub chunk_num: u32,
    pub offset_step: u16,
    pub stream_id: u16,
}

impl TcplsHeader {
    pub fn new(chunk_num: u32, offset: u16, stream_id: u16) -> Self {
        Self {
            chunk_num,
            offset_step: offset,
            stream_id,
        }
    }

    pub fn encode_tcpls_header(
        &mut self,
        b: &mut octets::OctetsMut,
    ) -> Result<(), Error> {
        b.put_u32(self.chunk_num).unwrap();
        b.put_u16(self.offset_step).unwrap();
        b.put_u16(self.stream_id).unwrap();

        Ok(())
    }

    pub fn decode_tcpls_header(b: &mut octets::Octets) -> Self {
        Self{
            chunk_num: b.get_u32().unwrap(),
            offset_step: b.get_u16().unwrap(),
            stream_id: b.get_u16().unwrap(),
        }
    }

    pub fn decode_tcpls_header_from_slice(b: &[u8]) -> Self {
        Self{
            chunk_num: u32::from_be_bytes(b[0..4].try_into().unwrap()),
            offset_step: u16::from_be_bytes(b[4..6].try_into().unwrap()),
            stream_id: u16::from_be_bytes(b[6..8].try_into().unwrap()),
        }
    }

   /* pub fn get_header_size_reverse(b: &mut octets::Octets) -> usize {
        b.rewind(1).unwrap();
        1 + varint_len(b.get_varint_reverse().unwrap()) +
            varint_len(b.get_varint_reverse().unwrap()) +
            varint_len(b.get_varint_reverse().unwrap())

    }*/
}

/*impl Default for StreamFrameHeader {
    fn default() -> Self {
        Self {
            ..Default::default()
        }
    }
}*/

#[test]
fn test_encode_decode_stream_frame() {
    let mut buf = [0; 15];

    let stream_frame = Frame::Stream {
        length: 24,
        offset: 456,
        stream_id: 9123,
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

    let ack_frame = Frame::ACK {
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

    let token_frame = Frame::NewToken {
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

    let v4_frame = Frame::NewAddress {
        port: 9874,
        address: std::vec![0x0A, 0x00, 0x00, 0x0C],
        address_version: 0x04,
        address_id: 47854755,
    };


    let mut d = octets::OctetsMut::with_slice(&mut v4);

    v4_frame.encode(&mut d).unwrap();

    let mut c = octets::Octets::with_slice_reverse(&mut v4);

    let v4_frame_2 = Frame::parse(&mut c).unwrap();

    assert_eq!(v4_frame, v4_frame_2);

    let mut v6 = [0; 30];

    let v6_frame = Frame::NewAddress {
        port: 987455,
        address: std::vec![
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