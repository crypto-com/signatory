#!/bin/bash
set e+x

SIGN_FILE="key.pem"

if [ $# -eq 1 ]; then
  MODE="debug"
else
  MODE=$1
fi;


if [ X${MODE}="Xrelease" ]; then
  CARGO_MODE="--release"
elif [ X${MODE}="Xdebug" ]; then
  CARGO_MODE=""
else
  echo "usage: build.sh [debug|release]"
fi;
SOURCE_FILE=../../target/x86_64-fortanix-unknown-sgx/${MODE}/sgx_app


# Build APP
cargo +nightly build --target=x86_64-fortanix-unknown-sgx ${CARGO_MODE}

# Convert the APP
ftxsgx-elf2sgxs ${SOURCE_FILE}  --heap-size 0x20000 --stack-size 0x20000 --threads 1 --debug

# signing app, see https://edp.fortanix.com/docs/tasks/deployment/
if [ -f "$SIGN_FILE" ]; then
    echo "$SIGN_FILE exist, use it to sgin the sgx_app"
else
    echo "$SIGN_FILE does not exist, create one to sign the sgx_app"
    openssl genrsa -3 3072 > ${SIGN_FILE}
fi;

sgxs-sign --key $SIGN_FILE ${SOURCE_FILE}.sgxs ${SOURCE_FILE}.sig -d --xfrm 7/0 --isvprodid 0 --isvsvn 0
