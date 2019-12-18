pub mod runner;
use crate::error::Error;
use crossbeam_channel::{unbounded, Receiver, Sender};
use runner::run_sgx;
use std::path::PathBuf;
use std::thread;

// C2S: short for client2server
pub type C2S = (Sender<Vec<u8>>, Vec<u8>);

pub fn run_server(client2server_rx: Receiver<C2S>, sgx_app_file: PathBuf) -> Result<(), Error> {
    let (server2sgx_tx, server2sgx_rx) = unbounded();
    let (sgx2server_tx, sgx2server_rx) = unbounded();
    log::info!("run sgx enclave");
    let t = thread::spawn(move ||
        if let Err(e) = run_sgx(&sgx_app_file, server2sgx_rx, sgx2server_tx) {
            log::error!("run sgx error: {:?}", e);
        });
    for (tx, data) in client2server_rx {
        // have to send length info and then the data
        server2sgx_tx.send(data[0..8].to_vec())?;
        server2sgx_tx.send(data[8..].to_vec())?;

        // get response from sgx and send to client
        let data = sgx2server_rx.recv()?;
        // send to client which is `SgxSigner`
        tx.send(data)?;
    }
    // drop server2sgx_tx so that we can stop the sgx thread at `rx.recv()`
    drop(server2sgx_tx);
    let _ = t
        .join()
        .map_err(|e| format!("join sgx thread error: {:?}", e))?;
    Ok(())
}

// when pass the tx into this function, please do **not** use `tx.clone`
#[inline]
pub fn stop_server(client2server_tx: Sender<C2S>) {
    drop(client2server_tx);
}
