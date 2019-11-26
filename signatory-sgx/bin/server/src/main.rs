mod runner;

use log::info;
use runner::{run_sgx, SGX_RECEIVER, SGX_SENDER};
use std::net::TcpListener;
use std::path::PathBuf;
use structopt::StructOpt;
#[macro_use]
extern crate lazy_static;

use std::io::{Read, Write};
use std::sync::mpsc::channel;
use std::thread;

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
    let (tx_host, rx_sgx) = channel();
    {
        let mut sgx_receiver = SGX_RECEIVER.lock().unwrap();
        *sgx_receiver = Some(rx_sgx);
        info!("set global sgx receiver");
    }

    let (tx_sgx, rx_host) = channel();
    {
        let mut sgx_sender = SGX_SENDER.lock().unwrap();
        *sgx_sender = Some(tx_sgx);
        info!("set global sgx sender");
    }
    info!("run sgx enclave");
    let t = thread::spawn(move || run_sgx(&file));
    let listener = TcpListener::bind(opt.addr).unwrap();
    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        // send data
        let mut len_info = [0_u8; 8];
        let _ = stream.read(&mut len_info).unwrap();
        tx_host.send(len_info.to_vec()).unwrap();
        let data_len = usize::from_le_bytes(len_info);
        let mut data = vec![0_u8; data_len];
        let _ = stream.read(&mut data).unwrap();
        tx_host.send(data.to_vec()).unwrap();

        // wait for the result from the sgx enclave
        let data = rx_host.recv().unwrap();
        stream.write(&data[..]).unwrap();
    }
    t.join().unwrap();
}
