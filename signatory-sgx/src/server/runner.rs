/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
use crate::error::Error;
use aesm_client::AesmClient;
use crossbeam_channel::{Receiver, Sender};
use enclave_runner::usercalls::{SyncStream, UsercallExtension};
use enclave_runner::EnclaveBuilder;
use log;
use sgxs_loaders::isgx::Device as IsgxDevice;
use std::cell::RefCell;
use std::io::Result as IoResult;
use std::path::Path;

/// User call extension allow the enclave code to "connect" to an external service via a customized enclave runner.
/// Here we customize the runner to intercept calls to connect to an address "sgx" which actually connects the enclave application to

struct SgxServer;

thread_local! {
    pub static SERVER2SGX_RX: RefCell<Option<Receiver<Vec<u8>>>> = RefCell::new(None);
    pub static SGX2SERVER_TX: RefCell<Option<Sender<Vec<u8>>>> = RefCell::new(None);
}

impl SyncStream for SgxServer {
    fn read(&self, buf: &mut [u8]) -> IoResult<usize> {
        log::debug!("read to buffer");
        SERVER2SGX_RX.with(|rx| {
            let receiver = rx.borrow();
            match receiver.as_ref().unwrap().recv() {
                Ok(data) => {
                    buf.copy_from_slice(&data);
                    Ok(data.len())
                }
                // return Ok(0) to tell sgx that the stream is finished
                Err(_e) => Ok(0),
            }
        })
    }

    fn write(&self, buf: &[u8]) -> IoResult<usize> {
        log::debug!("write data: {:?}", buf);
        SGX2SERVER_TX.with(|tx| {
            let sender = tx.borrow();
            sender
                .as_ref()
                .unwrap()
                .send(buf[..].to_vec())
                .expect("send error");
            Ok(buf.len())
        })
    }

    fn flush(&self) -> IoResult<()> {
        Ok(())
    }
}

#[derive(Debug)]
struct ExternalService;
// Ignoring local_addr and peer_addr, as they are not relavent in the current context.
impl UsercallExtension for ExternalService {
    fn connect_stream(
        &self,
        addr: &str,
        _local_addr: Option<&mut String>,
        _peer_addr: Option<&mut String>,
    ) -> IoResult<Option<Box<dyn SyncStream>>> {
        // If the passed address is not "sgx", we return none, whereby the passed address gets treated as
        // an IP address which is the default behavior.
        match &*addr {
            "sgx" => {
                let stream = SgxServer;
                Ok(Some(Box::new(stream)))
            }
            _ => Ok(None),
        }
    }
}

pub fn run_sgx<P: AsRef<Path>>(
    file: P,
    server2sgx_rx: Receiver<Vec<u8>>,
    sgx2server_tx: Sender<Vec<u8>>,
) -> Result<(), Error> {
    log::info!("set global sgx receiver");
    SERVER2SGX_RX.with(|rx| {
        *rx.borrow_mut() = Some(server2sgx_rx);
    });
    log::info!("set global sgx sender");
    SGX2SERVER_TX.with(|tx| {
        *tx.borrow_mut() = Some(sgx2server_tx);
    });
    let mut device = IsgxDevice::new()
        .map_err(|_e| "get sgx device error")?
        .einittoken_provider(AesmClient::new())
        .build();
    let mut enclave_builder = EnclaveBuilder::new(file.as_ref());
    enclave_builder
        .coresident_signature()
        .map_err(|_e| "sign enclave error")?;
    enclave_builder.usercall_extension(ExternalService);
    let enclave = enclave_builder
        .build(&mut device)
        .map_err(|_e| "build enclave error")?;
    enclave
        .run()
        .map_err(|e| format!("run enclave error: {:?}", e))?;
    Ok(())
}
