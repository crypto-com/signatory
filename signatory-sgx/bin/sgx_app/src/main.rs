mod logger;
use log::{error, info};
use signatory_sgx::backend::serve;
use signatory_sgx::protocol::{Encode, Response};
use std::io::prelude::*;
use std::net::TcpStream;

fn main() {
    logger::init().expect("init log failed");
    let mut stream = TcpStream::connect("sgx").expect("failed to connect sgx");
    if let Err(e) = serve(&mut stream) {
        error!("error to handle request: {:?}", e);
        let _ = Response::Error(e.what().to_string())
            .encode(true)
            .map(|data| {
                let _ = stream.write(&data);
            })
            .map_err(|e| {
                error!("encode data failed: {}", e);
            });
    } else {
        info!("handle request success!");
    }
}
