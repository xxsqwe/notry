# notry(Not on the Record yet) - Deniable Messaging with Retroactive Avowal

## Device for reproduction
NOTE: this repo will **NOT** work under the MACBOOK M1/M2 chip. 

## Overview
===============================================================================

Our implementation is written in Rust, supports both single- and
multiple-message transcript avowal and follows community best
practices—though we note our code is NOT YET READY for production
use. For our implementation, we set the security parameter to pro-
vide 256-bit equivalent security. 

All experiments were performed on an Intel 12th generation core i7-12700K pinned to 3.6GHz with
32GB RAM.

We specially acknowledge [Dalke Cryptograph](http://dalek.rs/#home) and [CONEC](https://github.com/kwantam/conec) library.

## Directory Structure
===============================================================================
- certs - certificates for the coordinator(also for the Judge)
-  examples - evaluation code for avowal and key exchange protocl
     - examples/avow.rs - evaluation code for avowal, timers are setted in this code.
     - examples/coord.rs - evaluation code for coordinator(also for the avowal Judge)
     - examples/gencert.rs - a script for generating certificate of the Judge
     - examples/rachet.rs - integreted code for key exchange evaluation. Parties can either be Alice or Bob when running this program. Also timers are setted in this code.
- src - source code for the main branch
     - src/avow.rs - implementation of avowal
     - src/key_exchange - implementation of the key exchange protocol
     - src/lib.rs - interfaces
     - src/macros.rs - Internal macros for defining points addition/subtraction
     - src/network.rs - network interfaces for communication
     - src/sok.rs - implementation of the Signature-of-Knowledge
     - src/tests.rs - test codes for network channels, SoK generation, SoK verification, Simulator of the Schnorr protocol(gen/verify)
     - src/utils.rs - constants deifinition. Including the pk of the Judege, Publickey(Privatekey) class implementations, three generators we used in our protocol, hash interface, and AES encryption/decrytion in the avowal phase.
- libsignal - comparision experiment, library of the **Signal** Protocol
     - libsignal/rust/protocol/examples/ratchet.rs - We talioreed this key exchange evaluation scirpt of X3DH and Double Ratchet in key exchange.
- target - after running cargo build, executable files will be placed in this automatically created folder.
     - target/release/examples/avow - executable file of **avowal** evaluation
     - target/release/examples/rachet - executable file of **DAKE** evaluation

## Primitives instantiation
===============================================================================

> Random Oracle: SHA256

> HKDF is based on the Rust crate hkdf

> Our implementation works on the special Ristretto Group, a ECC group without cofactors
# Using
## Prerequisite
===============================================================================

> Python3

```
pip3 install matplotlib, matplotlib_latex_bridge
``` 

> Install Rust via 
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
## Clone
```
 git clone -b main https://github.com/xxsqwe/notry.git
```
## To test:
===============================================================================


> test implementations
```
cd notry

cargo test
```
> delete the  **performance** file
```
rm performance
```
> run experiments to reprocude our results 
```
./run.sh
```

## Interpret results:
===============================================================================
> Figure 7 in our paper is reproduced and saved as performance.png

>

## Customized Evaluation:
===============================================================================
> To collect more results for **key exchange** evaluation, Try to modify the **round** variable in examples/rachet.rs: 92

> To collect more results for **avow** evaluation, you can simply pass the number of transcripts to 
"""
./target/release/examples/avow <number of scripts>
"""
