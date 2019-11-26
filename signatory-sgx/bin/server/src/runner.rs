/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
use aesm_client::AesmClient;
use enclave_runner::usercalls::{SyncStream, UsercallExtension};
use enclave_runner::EnclaveBuilder;
use log::error;
use sgxs_loaders::isgx::Device as IsgxDevice;
use std::io::Result as IoResult;
use std::path::Path;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Mutex;

/// User call extension allow the enclave code to "connect" to an external service via a customized enclave runner.
/// Here we customize the runner to intercept calls to connect to an address "sgx" which actually connects the enclave application to

struct SgxServer;

lazy_static! {
    // sgx get request from SGX_RECEIVER
    pub static ref SGX_RECEIVER: Mutex<Option<Receiver<Vec<u8>>>> = Mutex::new(None);
    // sgx send response to SGX_SENDER
    pub static ref SGX_SENDER: Mutex<Option<Sender<Vec<u8>>>> = Mutex::new(None);
}

impl SyncStream for SgxServer {
    fn read(&self, buf: &mut [u8]) -> IoResult<usize> {
        let c = SGX_RECEIVER.lock().expect("get sgx_recv lock");
        let receiver = c.as_ref().expect("get receiver failed");
        let data = receiver.recv().expect("get data from recv failed");
        buf.copy_from_slice(&data);
        Ok(data.len())
    }

    fn write(&self, buf: &[u8]) -> IoResult<usize> {
        let sender = SGX_SENDER.lock().expect("get sender lock");
        sender
            .as_ref()
            .unwrap()
            .send(buf.to_vec())
            .expect("send error");
        Ok(buf.len())
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

pub fn run_sgx<P: AsRef<Path>>(file: P) {
    let mut device = IsgxDevice::new()
        .expect("get sgx device failed")
        .einittoken_provider(AesmClient::new())
        .build();
    let mut enclave_builder = EnclaveBuilder::new(file.as_ref());
    enclave_builder
        .coresident_signature()
        .expect("sign enclave failed");
    enclave_builder.usercall_extension(ExternalService);
    let enclave = enclave_builder
        .build(&mut device)
        .expect("get enclave failed");
    if let Err(e) = enclave.run() {
        error!("Error while executing SGX enclave:{}", e);
        std::process::exit(1)
    }
}
