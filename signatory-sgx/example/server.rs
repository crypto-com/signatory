mod logger;
extern crate signatory_sgx;
use log::{error, info};
use signatory_sgx::backend::serve;
use signatory_sgx::error::Error;
use signatory_sgx::protocol::{Encode, Response};
use std::io::Write;
use std::net::TcpListener;
use std::time::Duration;

const TIMEOUT_SEC: u64 = 5;

fn main() -> Result<(), Error> {
    let _ = logger::init();
    let addr = "127.0.0.1:8888";
    let listener = TcpListener::bind(addr).unwrap();
    info!("listening {:?}", addr);

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
            let response = Response::Error(e.what().to_string());
            let data = response.encode()?;
            let _ = stream.write(&data)?;
        } else {
            info!("handle request success!");
        };
        info!("Connection closed!");
    }
    Ok(())
}
