extern crate signatory_sgx;
use log::{info, warn};
use signatory_sgx::backend::serve;
use std::net::TcpListener;
use std::time::Duration;

const TIMEOUT_SEC: u64 = 5;

fn main() {
    let addr = "127.0.0.1:8888";
    info!("listen on address: {:?}", addr);
    let listener = TcpListener::bind(addr).unwrap();

    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let _ = stream.set_read_timeout(Some(Duration::new(TIMEOUT_SEC, 0)));
        let _ = stream.set_write_timeout(Some(Duration::new(TIMEOUT_SEC, 0)));
        let _ = serve(&mut stream);
        warn!("Connection closed!");
    }
}
