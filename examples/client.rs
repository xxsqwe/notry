// Copyright 2020 Riad S. Wahby <rsw@cs.stanford.edu>
//
// This file is part of conec.
//
// Licensed under the Apache License, Version 2.0 (see
// LICENSE or https://www.apache.org/licenses/LICENSE-2.0).
// This file may not be copied, modified, or distributed
// except according to those terms.

use bytes::Bytes;
use conec::{Client, ClientConfig};
use futures::{future, prelude::*};
use tokio::stream::StreamExt;
use std::{env::args, path::PathBuf};
use tokio::io::AsyncBufReadExt;

use tokio_serde::{formats::SymmetricalBincode, SymmetricallyFramed};
use subtle::Choice;
use rand_core::OsRng;
use notry::sok::{sok,sok_verify};
use notry::utils::{hash,PublicKey,StaticSecret,xor,RISTRETTO_BASEPOINT2,get_cert_paths};

fn get_cert_path() -> PathBuf {
    let dir = directories_next::ProjectDirs::from("am.kwant", "conec", "conec-tests").unwrap();
    let path = dir.data_local_dir();
    path.join("cert.der")
}

fn main() {
    let mut args: Vec<String> = args().skip(1).collect();
    if args.len() < 3 {
        println!("Usage: test_client <server> <id> <peer> [initiate]");
        std::process::exit(1);
    }
    let initiate = if args.len() > 3 {
        args.truncate(3);
        true
    } else {
        false
    };
    let peer = args.pop().unwrap();
    let id = args.pop().unwrap();
    let server = args.pop().unwrap();

    let cpath = get_cert_path();
    let mut cfg = ClientConfig::new(id, server);
    cfg.set_ca_from_file(&cpath).unwrap();

    run_client(cfg, peer, initiate)
}

#[tokio::main]
async fn run_client(cfg: ClientConfig, peer: String, initiate: bool) {
    use std::io::{stderr, Write};
    eprint!("*** Connecting to coordinator... ");
    stderr().flush().unwrap();
    let (mut client, mut incoming) = Client::new(cfg).await.unwrap();
    eprintln!("Done.");

    let (mut send, mut recv) = if initiate {
        eprint!("*** Connecting to peer... ");
        stderr().flush().unwrap();
        client.new_channel(peer.clone()).await.unwrap();
        eprint!("Channel connected... ");
        stderr().flush().unwrap();
        let ret = client.new_direct_stream(peer.clone()).await.unwrap();
        eprintln!("Stream connected.");
        ret
    } else {
        eprint!("*** Waiting to receive stream from peer... ");
        stderr().flush().unwrap();
        let (_, _, send, recv) = tokio::stream::StreamExt::next(&mut incoming).await.unwrap();
        eprintln!("Received.");
        (send, recv)
    };
    if peer == "bob".to_string(){
    let secret_a = StaticSecret::new(&mut OsRng);
    let A = PublicKey::from(&secret_a);
    
    
    send.send(Bytes::copy_from_slice(& A.to_bytes())).await.unwrap();
    let sok = tokio::stream::StreamExt::try_next(&mut recv).await.unwrap().unwrap().freeze();
    println!("sok recv:{:?}",sok);

}
    else{
        let secret_b = StaticSecret::new(&mut OsRng);
        let B = PublicKey::from(&secret_b);
        let sk = StaticSecret::new(&mut OsRng);
        let pk = &sk.0 * &RISTRETTO_BASEPOINT2.decompress().unwrap();

        let Arecv = tokio::stream::StreamExt::next(&mut recv).await.unwrap().unwrap().freeze();
        let signature_of_knowledge = sok(Arecv.clone().try_into().unwrap(),B,PublicKey(pk),secret_b,sk,Choice::from(1));
        println!("recevied A:{:?}",Arecv);
        send.send(Bytes::copy_from_slice( &signature_of_knowledge[0].to_bytes())).await.unwrap();
    }
    /* 
    eprintln!("Go ahead and type.");
    let rfut = SymmetricallyFramed::new(recv, SymmetricalBincode::<String>::default()).for_each(|s| {
        println!("---> {}", s.unwrap());
        future::ready(())
    });

    let stdin = tokio::io::BufReader::new(tokio::io::stdin());
    let sfut = stdin
        .lines()
        .forward(SymmetricallyFramed::new(send, SymmetricalBincode::<String>::default()))
        .then(|sf| async {
            sf.ok();
            eprintln!("*** STDIN closed.");
        });

    futures::future::join(sfut, rfut).await;*/
}