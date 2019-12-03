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
The native format for SGX enclaves is the SGX stream (SGXS) format. Your compiler probably doesn't output binaries in that format, so they must be converted. In addition, your SGX enclaves must be signed. Then, to run your enclave applications, a runner program must be executed with the SGXS and signature as input. In development, these steps are done automatically, and a default runner is provided. For deployment, these steps can and should be customized.

Please go to the `bin` directory to see the details.

## cargo test
```
cargo +nightly test --features sgx \
--no-default-features \
--target x86_64-fortanix-unknown-sgx

cargo +nightly test
```

