# signatory-sgx

[Signatory](https://github.com/tendermint/signatory) provider for Tendermint Validator app on cloud deployments, using [Fortranix Enclaves](https://dep.fortanix.com) run as isolated services that communicate via TCP. It can provide:

* generate a key pair
* query public key
* sign data
* import secret key

## requirement
Follow the [fortanix guide](https://edp.fortanix.com/docs/installation/guide/) to prepare the envrionment including:

* install rust nightly 1.36+
* install SGX driver
* run AESM service
* Install Fortanix EDP utilities

## usage
Please go to the `bin` directory to see how to use it.

## cargo test
```
cargo +nightly test --features sgx \
--no-default-features \
--target x86_64-fortanix-unknown-sgx
```

