#!/bin/bash
echo "Library Test"
cargo test --release
echo "compiling executables"
cargo build --release --examples

pwd
echo "test key exchange"
./target/release/examples/coord localhost&
./target/release/examples/rachet localhost bob alice&
sleep 0.75
./target/release/examples/rachet localhost alice bob init>> performance

echo "avow 1 transcript"
echo "Generating keys(via key exchangea)"

./target/release/examples/avow 1 >> performance

echo "1 script avowed"
echo "avow 10 transcript"
echo "Generating keys(via key exchangea)"

./target/release/examples/avow 10 >> performance

echo "10 scripts avowed"
echo "avow 100 transcript"
echo "Generating keys(via key exchangea)"

./target/release/examples/avow 100 >> performance

echo "100 scripts avowed"
echo "avow 1000 transcript"
echo "Generating keys(via key exchangea)"

./target/release/examples/avow 1000 >> performance

echo "1000 scripts avowed"

echo "Test key exchange of signal"
cd libsignal/rust/protocol/
cargo build --release --examples
../../target/release/examples/ratchet >> ../../../performance