mod runner;

use log::info;
use runner::{run_sgx, STREAM_CONTAINER};
use std::net::TcpListener;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "server", about = "sgx server")]
pub struct Opt {
    /// set address that server listening on
    #[structopt(short, long, default_value = "127.0.0.1:8888")]
    addr: String,

    /// set sgxs file path
    #[structopt(short, long, parse(from_os_str))]
    file: PathBuf,
}

fn main() {
    let opt = Opt::from_args();
    let file = opt.file;
    env_logger::init();
    info!("listening on address {}", opt.addr);
    let listener = TcpListener::bind(opt.addr).unwrap();
    for stream in listener.incoming() {
        let s = stream.unwrap();
        STREAM_CONTAINER.with(|container| {
            *container.borrow_mut() = Some(s);
        });
        run_sgx(&file);
    }
}
