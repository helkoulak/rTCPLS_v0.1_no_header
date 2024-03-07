#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustls;

use rustls::internal::msgs::codec::{Codec, Reader};
use rustls::internal::msgs::persist;

fn try_type<T>(data: &[u8])
where
<<<<<<< HEAD
    T: Codec,
=======
    T: for<'a> Codec<'a>,
>>>>>>> 5bd3300 (Add files of rustls v0.23.1)
{
    let mut rdr = Reader::init(data);

    let _ = T::read(&mut rdr);
}

fuzz_target!(|data: &[u8]| {
    try_type::<persist::ServerSessionValue>(data);
});
