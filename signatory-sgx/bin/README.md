# signatory-sgx  usage example
This is a example of how to usage signatory-sgx including:

- sgx_app: Fortanix Rust EDP enclave app
- cmd: a cli command to run the sgx_app using `user call extention`

## build
```
cd cmd && cargo +nightly build --release && cd -
cd sgx_app && sh build.sh debug
```

> note: The runner will look for a signature file ending in `*.sig` next to the `*.sgxs` file, so please put them in the same directory and make their name matched each other.