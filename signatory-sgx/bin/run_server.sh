#!/bin/bash
set e+x

SIGN_FILE="key.pem"
SERVER_PATH="server"
APP_PATH="sgx_app"
MODE="debug" # or release
SERVER_BIN=../target/${MODE}/server
SOURCE_FILE=../target/x86_64-fortanix-unknown-sgx/${MODE}/sgx_app

CARGO_MODE=""
if [[ $MODE == "release" ]]; then
  CARGO_MODE="--release"
fi;

# Build custom server
cd ${SERVER_PATH}
cargo +nightly build ${CARGO_MODE}
cd -
if [ $? -ne "0" ]; then
  exit 1
fi

# Build APP
cd ${APP_PATH}
cargo +nightly build --target=x86_64-fortanix-unknown-sgx ${CARGO_MODE}
cd -
if [ $? -ne "0" ]; then
  exit 1
fi

# Convert the APP
ftxsgx-elf2sgxs ${SOURCE_FILE}  --heap-size 0x20000 --stack-size 0x20000 --threads 1 --debug

# signing https://edp.fortanix.com/docs/tasks/deployment/
if [ -f "$SIGN_FILE" ]; then
    echo "$SIGN_FILE exist, use it to sgin the sgx_app"
else
    echo "$SIGN_FILE does not exist, create one to sign the sgx_app"
    openssl genrsa -3 3072 > ${SIGN_FILE}
fi
sgxs-sign --key $SIGN_FILE ${SOURCE_FILE}.sgxs ${SOURCE_FILE}.sig -d --xfrm 7/0 --isvprodid 0 --isvsvn 0
if [ $? -ne "0" ]; then
  exit 1
fi
# Execute
if [ $? -eq "0" ]; then
  echo "sign  the sgxs file success, now run it"
  RUST_LOG=info ${SERVER_BIN} --file ${SOURCE_FILE}.sgxs --addr 127.0.0.1:8888
else
  echo "sign failed"
fi
