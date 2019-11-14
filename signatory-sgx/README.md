
# compile server
`cargo build --example server --target x86_64-fortanix-unknown-sgx --features=sgx --no-default-features`

# compile client
`cargo build --example client`