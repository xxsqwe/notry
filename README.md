[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)
![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)


# notry (Not on the Record yet) - Deniable Messaging with Retroactive Avowal

## Device for reproduction
NOTE: This repo will **NOT** work under the Apple MacBook M1/M2 chip. 
Tested on Apple Macbook Intel chip, Thinkpad, and the artifact VM Ubuntu 22.04 machine.
## Overview
===============================================================================

Our implementation is written in Rust, supports both single- and
multiple-message transcript avowal, and follows community best
practices—though we note our code is NOT YET READY for production
use. We set the security parameter for our implementation to provide 256-bit equivalent security. 

All experiments were performed on an Intel 12th generation core i7-12700K pinned to 3.6GHz with
32GB RAM.
We especially acknowledge [Dalke](http://dalek.rs/#home) Cryptograph](http://dalek.rs/#home) and [CONEC](https://github.com/kwantam/conec) library.

## Directory Structure
===============================================================================
- certs - certificates for the coordinator(also for the Judge)
-  examples - evaluation code for avowal and key exchange protocol
     - examples/avow.rs - evaluation code for avowal, timers are set in this code.
     - examples/coord.rs - evaluation code for coordinator(also for the avowal Judge)
     - examples/gencert.rs - a script for generating a certificate of the Judge
examples/rachet.rs - integrated code for key exchange evaluation. Parties can either be Alice or Bob when running this program. Also, timers are set in this code.
- src - source code for the main branch
     - src/avow.rs - implementation of avowal
     - src/key_exchange - implementation of the key exchange protocol
     - src/lib.rs - interfaces
     - src/macros.rs - Internal macros for defining points addition/subtraction
     - src/network.rs - network interfaces for communication
     - src/sok.rs - implementation of the Signature-of-Knowledge
     - src/tests.rs - test codes for network channels, SoK generation, SoK verification, Simulator of the Schnorr protocol(gen/verify)
     - src/utils.rs - constants deifinition. Including the pk of the Judege, Publickey(Privatekey) class implementations, three generators we used in our protocol, hash interface, and AES encryption/decryption in the avowal phase.
libsignal - comparison experiment, the library of the **Signal** Protocol
     - libsignal/rust/protocol/examples/ratchet.rs - We tailored this key exchange evaluation script of X3DH and Double Ratchet in the key exchange.
- target - after running cargo build, executable files will be placed in this automatically created folder.
     - target/release/examples/avow - executable file of **avowal** evaluation
     - target/release/examples/rachet - executable file of **DAKE** evaluation

## Primitives instantiation
===============================================================================

> Random Oracle: SHA256

> HKDF is based on the Rust crate hkdf

> Our implementation works on the special Ristretto Group, a ECC group without cofactors
# TO USE
## With Docker
===============================================================================
```
git clone --recurse-submodules https://github.com/xxsqwe/notry.git && cd notry
```
```
docker build -t notry_test .
```
```
docker run --rm --net=host -it notry_test:latest
```
> After evaluation, export the performance figure.
```
containerID=$(docker ps -a | grep notry_test | awk '{print $1;}')
docker cp $containerID:/notry/performance.png .
```
> You can check the generated figure outside the container.
## Build from scratch 
===============================================================================
### Prerequisite
> Python3 and the plot library

```
sudo apt install python3-pip
```
```
pip3 install matplotlib
``` 

> Install Rust via 
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
> Proceed with the default installation
> Switch to a stable version
```
rustup install nightly-2022-06-22
```
```
rustup default nightly-2022-06-22
```
### Clone
```
 git clone --recurse-submodules https://github.com/xxsqwe/notry.git
```
### To test:
===============================================================================


> test implementations
```
cd notry
```
```
cargo test
```
> delete the  **performance** file
```
rm performance
```
> Run experiments to reproduce our results 
```
./run.sh
```

## Interpret results:
===============================================================================
> Figure 7 in our paper is reproduced and saved as performance.png. Note that the generated diagram won't be the same on different test devices. But the trend is always holding.

> Results of Table 1 are reflected in the first 7 lines of the performance file.

## Customized Evaluation:
===============================================================================
> To collect more results for **key exchange** evaluation, Try to modify the **round** variable in examples/rachet.rs: 92

> To collect more results for **avow** evaluation, you can simply pass the number of transcripts to 
```
./target/release/examples/avow <number of scripts>
```
