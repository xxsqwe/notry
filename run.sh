#!/bin/bash
rm performance

rustup install nightly-2022-06-22
rustup default nightly-2022-06-22

echo "Library Test"
cargo test --release
echo "compiling executables"
cargo build --release --examples

echo "Test DAKEA key exchange"
./target/release/examples/coord localhost&
./target/release/examples/rachet localhost bob alice&
sleep 0.75
./target/release/examples/rachet localhost alice bob init >> performance

echo "Test the Signal key exchange"
cd libsignal/rust/protocol/
cargo build --release --examples
../../target/release/examples/ratchet >> ../../../performance

cd ../../../
echo "avow 1 transcript"
echo "Generating keys(via key exchange)"

./target/release/examples/avow 1 >> performance

echo "1 script avowed"
echo "avow 10 transcript"
echo "Generating keys(via key exchange)"

./target/release/examples/avow 10 >> performance

echo "10 scripts avowed"
echo "avow 100 transcript"
echo "Generating keys(via key exchange)"

./target/release/examples/avow 100 >> performance

echo "100 scripts avowed"
echo "avow 1000 transcript"
echo "Generating keys(via key exchange)"

./target/release/examples/avow 1000 >> performance

echo "1000 scripts avowed"

echo "plotting results"
python3 plot.py

