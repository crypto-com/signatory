# signatory-sgx

[Signatory](https://github.com/tendermint/signatory) provider for Tendermint Validator app on cloud deployments, using [Fortranix Enclaves](https://dep.fortanix.com) run as isolated services that communicate via TCP. It can provide:

* generate a key pair.
* query public key.
* sign

## build server
1. setup [Fortanix EDP](https://edp.fortanix.com/docs/installation/guide/) on your machine
2. build server:
```
cargo +nightly build \
--release \
--bin server \
--features=sgx \
--no-default-features \
--target x86_64-fortanix-unknown-sgx \
```

3. Follow the [deployment](https://edp.fortanix.com/docs/tasks/deployment/) convert the binary `server` to `SGXS` format and run server using `ftxsgx-runner`.

## build client example
`cargo build --release --bin client`


## test
```
cargo test --features sgx \
--no-default-features \
--target x86_64-fortanix-unknown-sgx
```