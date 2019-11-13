mod logger;
extern crate signatory_sgx;
use log::{error, info};
use signatory_sgx::backend::serve;
use std::net::TcpListener;
use std::time::Duration;

const TIMEOUT_SEC: u64 = 5;

fn main() {
    let _ = logger::init();
    let addr = "127.0.0.1:8888";
    info!("listen on address: {:?}", addr);
    let listener = TcpListener::bind(addr).unwrap();

    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => {
                info!("get connection from {:}", s.peer_addr().unwrap());
                s
            }
            Err(e) => {
                error!("{:?}", e);
                continue;
            }
        };
        let _ = stream.set_read_timeout(Some(Duration::new(TIMEOUT_SEC, 0)));
        let _ = stream.set_write_timeout(Some(Duration::new(TIMEOUT_SEC, 0)));
        if let Err(e) = serve(&mut stream) {
            error!("error to handle request: {:?}", e);
        } else {
            info!("handle request success!");
        };
        info!("Connection closed!");
    }
}
