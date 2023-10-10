use std::{
    io::{self, Read, Write},
    net::{Shutdown, TcpStream},
    thread::{self, JoinHandle},
};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use crossbeam::channel::{bounded, select, Receiver, Sender};
use serde::{de::DeserializeOwned, Serialize};

const TCPSTREAM_CAP: usize = 1000;

fn try_shutdown(stream: &TcpStream) {
    match stream.shutdown(Shutdown::Both) {
        Ok(()) => (),
        Err(e) => eprintln!("shutdown error: {:?}", e),
    }
}

fn read_length<R: io::Read>(reader: &mut R) -> io::Result<usize> {
    reader.read_u64::<LittleEndian>().map(|x| x as usize)
}

fn write_length<W: io::Write>(writer: &mut W, len: usize) -> io::Result<()> {
    writer.write_u64::<LittleEndian>(len as u64)
}

// TODO: we could also wrap reader/writer
/// Wrap a TcpStream into channels
fn wrap_tcpstream<S, R>(
    stream: TcpStream,
) -> (
    Sender<S>,
    Receiver<R>,
    Sender<()>,
    JoinHandle<Result<(), std::io::Error>>,
)
where
    S: 'static + Sync + Send + Clone + Serialize,
    R: 'static + Sync + Send + Clone + DeserializeOwned,
{
    let (reader_s, reader_r) = bounded(TCPSTREAM_CAP);
    let (writer_s, writer_r) = bounded(TCPSTREAM_CAP);
    let (shutdown_s, shutdown_r) = bounded(1);
    let mut reader = stream.try_clone().unwrap();
    let mut writer = stream.try_clone().unwrap();

    let hdl = thread::spawn(move || {
        // read data from a stream and then forward it to a channel
        let read_hdl = thread::spawn(move || {
            loop {
                let mut f = || -> Result<(), std::io::Error> {
                    let n = read_length(&mut reader)?;
                    let mut value_buf = vec![0u8; n];
                    reader.read_exact(&mut value_buf)?;

                    // TODO find a generic way to do serializatioin
                    let msg: R = bincode::deserialize(&value_buf)
                        .map_err(|e| std::io::Error::new(io::ErrorKind::Other, e))?;
                    match reader_s.send(msg) {
                        Ok(()) => Ok(()),
                        Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
                    }
                };

                match f() {
                    Ok(()) => {}
                    Err(e) => {
                        if e.kind() == io::ErrorKind::UnexpectedEof {
                            // this is ok since the sender has shutdown
                            return Ok(());
                        }
                        // try to shutdown because the writer might've closed the stream too
                        try_shutdown(&reader);
                        eprintln!("reader error: {:?}", e);
                        return Err(e);
                    }
                }
            }
        });

        // read data from a channel and then send it into a stream
        let mut select_loop = || -> io::Result<()> {
            loop {
                select! {
                    recv(writer_r) -> msg_res => {
                        // we put these in a function so that we can always
                        // run shutdown later when an error occurs
                        let mut f = || -> io::Result<()> {
                            let msg = msg_res
                                .map_err(|e| std::io::Error::new(io::ErrorKind::Other, e))?;
                            let data = bincode::serialize(&msg)
                                .map_err(|e| std::io::Error::new(io::ErrorKind::Other, e))?;
                            write_length(&mut writer, data.len())?;
                            (&mut writer).write_all(&data)?;
                            Ok(())
                        };

                        match f() {
                            Ok(()) => {},
                            e => {
                                try_shutdown(&writer);
                                eprintln!("channel error: {:?}", e);
                                return e;
                            },
                        }
                    }
                    recv(shutdown_r) -> msg_res => {
                        try_shutdown(&writer);
                        return msg_res.map_err(|e| std::io::Error::new(io::ErrorKind::Other, e));
                    }
                }
            }
        };

        // TODO combine the errors
        let _ = select_loop();
        read_hdl.join().expect("reader thread panicked")
    });

    (writer_s, reader_r, shutdown_s, hdl)
}

#[cfg(test)]
mod test {
    use std::net::TcpListener;

    use serde::Deserialize;

    use super::*;

    #[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
    struct DummyMsg {
        v: usize,
    }

    #[test]
    fn test_tcpstream_wrapper() {
        // TODO use port 0 to let OS pick, but we need to connect to the port that OS picked
        const ADDR: &str = "127.0.0.1:11111";
        const MSG1: DummyMsg = DummyMsg { v: 1 };
        const MSG2: DummyMsg = DummyMsg { v: 2 };

        // we need some synchronization for the test to run correctly,
        // i.e., client only connects to server when the server is ready
        let (s, r) = bounded(1);
        // start server in a thread
        // the server writes and reads the tcpstream
        // and the result should come back into the channel
        let server_hdl: JoinHandle<DummyMsg> = thread::spawn(move || {
            let listener = TcpListener::bind(ADDR).unwrap();
            s.send(()).unwrap();
            let (mut stream, _) = listener.accept().unwrap();

            // write a message
            let mut msg1_buf = bincode::serialized_size(&MSG1)
                .unwrap()
                .to_le_bytes()
                .to_vec();
            msg1_buf.extend(bincode::serialize(&MSG1).unwrap());
            stream.write_all(&msg1_buf).unwrap();

            // read a message
            let read_len = read_length(&mut stream).unwrap();
            let mut read_buf = vec![0u8; read_len];
            stream.read_exact(&mut read_buf).unwrap();
            s.send(()).unwrap();
            bincode::deserialize(&read_buf).unwrap()
        });

        // wait for server to start and get a client stream
        assert_eq!((), r.recv().unwrap());
        let stream = TcpStream::connect(ADDR).unwrap();

        // test the wrapper, first receive the first message from server
        let (sender, receiver, shutdown_sender, handle) =
            wrap_tcpstream::<DummyMsg, DummyMsg>(stream);
        let msg1: DummyMsg = receiver.recv().unwrap();
        assert_eq!(msg1, MSG1);

        // send MSG2 and send a close message
        sender.send(MSG2).unwrap();
        assert_eq!((), r.recv().unwrap());
        shutdown_sender.send(()).unwrap();

        assert_eq!(server_hdl.join().unwrap(), MSG2);
        handle.join().unwrap().unwrap();
    }
}
