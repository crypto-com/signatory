
# compile server
`cargo build --bin server --target x86_64-fortanix-unknown-sgx --features=sgx --no-default-features`

# compile client
`cargo build --bin client`