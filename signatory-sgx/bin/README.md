# signatory-sgx  usage example
This is a example of how to usage signatory-sgx including:

- sgx_app: Fortanix Rust EDP enclave app
- server: A runner as tcp server that using `user call extention` to run the sgx_app
- client: a cli command to talk with the server

## build
```
cd client && cargo build --release && cd -
cd server && cargo +nightly build --release && cd -
cd sgx_app && cargo +nightly build --target=x86_64-fortanix-unknown-sgx --release
```
  
### running server
Before start the server, you have to convert the sgx_app into SGX stream (SGXS) format, and the SGX enclaves must be signed, see `run_server.sh`.

> note: make sure the `*.sgxs` file and the `*.sig` are in the same directory.
