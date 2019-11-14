# TODO: introduction

# compile

## compile example server
```
cargo build --bin server \
--target x86_64-fortanix-unknown-sgx \
--features=sgx \
--no-default-features
```
compile client
`cargo build --bin client`

# test
```
cargo test --features sgx \
--no-default-features \
--target x86_64-fortanix-unknown-sgx
```