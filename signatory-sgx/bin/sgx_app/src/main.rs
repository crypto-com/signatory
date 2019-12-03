mod logger;
use signatory_sgx::backend::serve;
use signatory_sgx::error::ErrorKind;
use signatory_sgx::protocol::{Encode, Response};
use std::io::prelude::*;
use std::net::TcpStream;

fn main() {
    logger::init().expect("init log failed");
    loop {
        let mut stream = TcpStream::connect("sgx").expect("failed to connect sgx");

        if let Err(e) = serve(&mut stream) {
            if e.kind == ErrorKind::Stop {
                break;
            }
            log::error!("error to handle request: {:?}", e);
            let _ = Response::Error(e.what.to_string())
                .encode(true)
                .map(|data| {
                    let _ = stream.write(&data);
                })
                .map_err(|e| {
                    log::error!("encode data failed: {}", e);
                });
        } else {
            log::info!("handle request success!");
        }
    }
}
