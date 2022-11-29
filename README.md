# notry(Not on the Record yet) - Deniable Messaging with Retroactive Avowal

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
- examples - evaluation code for avowal and key exchange protocl
- examples/avow.rs - evaluation code for avowal
- examples/coord.rs - evaluation code for coordinator(also for the avowal Judge)
- examples/gencert.rs - a script for generating certificate of the Judge
- examples/rachet.rs - integreted code for key exchange evaluation. Participants are indicated by their roles passing to this program.
- src - source code for the development branch
- src/avow.rs - implementation of avowal
- src/key_exchange - implementation of the key exchange protocol
- src/lib.rs - interfaces
- src/macros.rs - Internal macros for defining points addition/subtraction
- src/network.rs - network interfaces for communication
- src/sok.rs - implementation of the Signature-of-Knowledge
- src/tests.rs - test codes for network channels, SoK generation, SoK verification, Simulator of the Schnorr protocol(gen/verify)
- src/utils.rs - constants deifinition. Including the pk of the Judege, Publickey(Privatekey) class implementations, three generators we used in our protocol, hash interface, and AES encryption/decrytion in the avowal phase.

## Primitives instantiation
===============================================================================

> Random Oracle: SHA256

> HKDF is based on the Rust crate hkdf

> Our curve works on the Ristretto Group to eliminate cofactors
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
 git clone --recurse-submodules git@github.com:xxsqwe/notry.git 
```
## To test:
===============================================================================


> test implementations by 
```
cargo test
```
> delete the \emph{performance} file

> run experiments to reprocude our results 
```
./run.sh
```




