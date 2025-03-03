use std::io;
use std::io::Write;
use std::ops::{Deref, DerefMut};


#[path = "../tests/common/mod.rs"]
mod test_utils;
struct OtherSession<C, S>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    S: SideData,
{
    sess: C,
    pub reads: usize,
    pub writevs: Vec<Vec<usize>>,
    pub short_writes: bool,
}

impl<C, S> OtherSession<C, S>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    S: SideData,
{
    fn new(sess: C) -> OtherSession<C, S> {
        OtherSession {
            sess,
            reads: 0,
            writevs: vec![],

            short_writes: false,

        }
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

impl<C, S> io::Read for OtherSession<C, S>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    S: SideData,
{
    fn read(&mut self, mut b: &mut [u8]) -> io::Result<usize> {
        self.reads += 1;
        self.sess.write_tls(b.by_ref(), 0)
    }
}

impl<C, S> io::Write for OtherSession<C, S>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    S: SideData,
{
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let mut buf = input;
        self.sess.read_tls(&mut buf)

    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn write_vectored<'b>(&mut self, b: &[io::IoSlice<'b>]) -> io::Result<usize> {
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

        self.writevs.push(lengths);
        Ok(total)
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

use criterion::{criterion_group, criterion_main, Criterion, Throughput, BenchmarkId, BatchSize};

use rustls::{ConnectionCommon, ContentType, ProtocolVersion, ServerConnection, SideData};

use rustls::recvbuf::RecvBufMap;

use crate::bench_util::CPUTime;
use rustls::crypto::ring as provider;
use rustls::crypto::cipher::{OutboundChunks, OutboundPlainMessage};
use rustls::server::ServerConnectionData;
use rustls::tcpls::frame::{Frame, MAX_TCPLS_FRAGMENT_LEN};
use crate::test_utils::{do_handshake, KeyType, make_pair};

pub(crate) fn process_received(pipe: &mut OtherSession<ServerConnection,
    ServerConnectionData>, app_bufs: &mut RecvBufMap, data_len: u64) {
    let conn_ids: Vec<u32> = vec![0,1];
    let stream_ids: Vec<u32> = vec![1];
    for str_id in stream_ids {
        loop {
            for id in &conn_ids {
                pipe.sess.set_connection_in_use(*id);
                pipe.sess.process_new_packets(app_bufs).unwrap();
            }
            if app_bufs.get(str_id as u16).unwrap().data_length() >= data_len { break }
        }

    }

}

mod bench_util;
fn criterion_benchmark(c: &mut Criterion<CPUTime>) {
    let data_len= 50 * MAX_TCPLS_FRAGMENT_LEN;
    let capacity = 70 * MAX_TCPLS_FRAGMENT_LEN;
    let sendbuf1 = vec![1u8; data_len];
    let mut group = c.benchmark_group("Data_recv");
    group.throughput(Throughput::Bytes((data_len) as u64));
    group.bench_with_input(BenchmarkId::new("Data_recv_single_stream_two_connection", data_len), &sendbuf1,
                           |b, _sendbuf| {

                               b.iter_batched_ref(|| {
                                   // Finish handshake
                                   let (mut client, mut server, mut recv_svr, mut recv_clnt) =
                                       make_pair(KeyType::Rsa);
                                   do_handshake(&mut client, &mut server, &mut recv_svr, &mut recv_clnt);
                                   server.set_deframer_cap(0, capacity);
                                   server.set_deframer_cap(1, capacity);

                                   let mut pipe = OtherSession::new(server);
                                   let mut conn_id: u32 = 0;
                                   client.write_to = 1;
                                   let mut last_stream: Vec<Option<u32>> = Vec::default();
                                   let mut buf: Vec<u8>;


                                   // Write each chunk in a different deframer buffer to simulate multipath. Here we simulate sending
                                   // a single stream over two connections
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
                                       if conn_id == 2 {
                                           conn_id = 0;
                                       }

                                   }
                                   // Create app receive buffer
                                   recv_svr.get_or_create(1, Some(capacity));
                                   (pipe, recv_svr)
                               },

                                                  |(ref mut pipe, recv_svr)| process_received(pipe, recv_svr, data_len as u64),
                                                  BatchSize::SmallInput)
                           });
    group.finish();
}


/*criterion_group!{
    name = benches;
    config = Criterion::default()
        .with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)))
        .measurement_time(std::time::Duration::from_secs(15))
        .sample_size(9000);
    targets = criterion_benchmark
}
criterion_main!(benches);*/

criterion_group! {
    name = benches;
    config = Criterion::default()
        .measurement_time(std::time::Duration::from_secs(1))
        .with_measurement(CPUTime)
        .sample_size(5000);
    targets = criterion_benchmark
}

/*criterion_group!{
    name = benches;
    config = Criterion::default()
    .with_measurement(CPUTime)
    .sample_size(5000)
    .with_profiler({
        let mut options = pprof::flamegraph::Options::default();
        PProfProfiler::new(200, Output::Flamegraph(Some(options)))
    });
    targets = criterion_benchmark
}*/
criterion_main!(benches);