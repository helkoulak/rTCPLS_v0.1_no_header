#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustls;

use rustls::internal::msgs::codec::Reader;
<<<<<<< HEAD
use rustls::internal::msgs::message::{Message, OpaqueMessage, PlainMessage};

fuzz_target!(|data: &[u8]| {
    let mut rdr = Reader::init(data);
    if let Ok(m) = OpaqueMessage::read(&mut rdr) {
=======
use rustls::internal::msgs::message::{Message, OutboundOpaqueMessage, PlainMessage};

fuzz_target!(|data: &[u8]| {
    let mut rdr = Reader::init(data);
    if let Ok(m) = OutboundOpaqueMessage::read(&mut rdr) {
>>>>>>> 5bd3300 (Add files of rustls v0.23.1)
        let msg = match Message::try_from(m.into_plain_message()) {
            Ok(msg) => msg,
            Err(_) => return,
        };
        //println!("msg = {:#?}", m);
        let enc = PlainMessage::from(msg)
            .into_unencrypted_opaque()
            .encode();
        //println!("data = {:?}", &data[..rdr.used()]);
        assert_eq!(enc, data[..rdr.used()]);
    }
});
