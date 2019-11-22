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
use std::cell::RefCell;
use std::io::Result as IoResult;
use std::net::TcpStream;
use std::path::Path;

/// User call extension allow the enclave code to "connect" to an external service via a customized enclave runner.
/// Here we customize the runner to intercept calls to connect to an address "cat" which actually connects the enclave application to
/// stdin and stdout of `cat` process.

struct SgxServer;

thread_local! {
    pub static STREAM_CONTAINER: RefCell<Option<TcpStream>> = RefCell::new(None);
}

impl SyncStream for SgxServer {
    fn read(&self, buf: &mut [u8]) -> IoResult<usize> {
        STREAM_CONTAINER.with(|container| {
            let s = container.borrow();
            let stream = s.as_ref().unwrap();
            stream.read(buf)
        })
    }

    fn write(&self, buf: &[u8]) -> IoResult<usize> {
        STREAM_CONTAINER.with(|container| {
            let s = container.borrow_mut();
            let stream = s.as_ref().unwrap();
            stream.write(buf)
        })
    }

    fn flush(&self) -> IoResult<()> {
        STREAM_CONTAINER.with(|container| {
            let s = container.borrow_mut();
            let stream = s.as_ref().unwrap();
            stream.flush()
        })
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
