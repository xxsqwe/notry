#!/bin/bash
cargo test --release
cargo build --release --examples

pwd
echo "test key exchange"
./target/release/examples/coord localhost&
./target/release/examples/rachet localhost bob alice&
sleep 0.75
./target/release/examples/rachet localhost alice bob init>> performance

echo "avow 1 transcript"
echo "Generating keys(viw key exchangea)"

./target/release/examples/avow 1 >> performance

echo "avow 10 transcript"
echo "Generating keys(viw key exchangea)"

./target/release/examples/avow 10 >> performance

echo "avow 100 transcript"
echo "Generating keys(viw key exchangea)"

./target/release/examples/avow 100 >> performance

echo "avow 100 transcript"
echo "Generating keys(viw key exchangea)"

./target/release/examples/avow 1000 >> performance

matlab -nodisplay -nosplash -nodesktop -r "run('figure.m');exit;"

cd libsingal
cargo build --release --examples
./target/release/examples/ratchet >> performance