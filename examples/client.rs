// Copyright 2020 Riad S. Wahby <rsw@cs.stanford.edu>
//
// This file is part of conec.
//
// Licensed under the Apache License, Version 2.0 (see
// LICENSE or https://www.apache.org/licenses/LICENSE-2.0).
// This file may not be copied, modified, or distributed
// except according to those terms.
use std::time::Instant;
use bytes::Bytes;
use conec::{Client, ClientConfig};
#[allow(unused_imports)]

use futures::{future, prelude::*};
#[allow(unused_imports)]

use tokio::stream::StreamExt;

use std::{env::args, path::PathBuf};
use std::mem::size_of;
#[allow(unused_imports)]
use tokio_serde::{formats::SymmetricalBincode, SymmetricallyFramed};
use subtle::Choice;
use rand_core::OsRng;
#[allow(unused_imports)]

use aes_gcm::{
    aead::{Aead, KeyInit, consts::U12},
    Aes256Gcm, Nonce};
#[allow(unused_imports)]

use aes_gcm::aead::generic_array::GenericArray;

use curve25519_dalek::{scalar::Scalar, ristretto::CompressedRistretto,constants::RISTRETTO_BASEPOINT_TABLE};

use notry::{sok::{sok,sok_verify,SigmaOr}};
#[allow(unused_imports)]

use notry::utils::{PublicKey,StaticSecret,xor,AES_Dec,AES_Enc,RISTRETTO_BASEPOINT2,RISTRETTO_BASEPOINT_RANDOM,RISTRETTO_JUDGE_PUBK};
use notry::key_exchange::{init_key,derive_key};
#[allow(unused_imports)]
use notry::avow::{Judge,avow_proof, prove_avow};

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
#[allow(non_snake_case,unused_variables)]
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
    let pk_J = PublicKey(RISTRETTO_JUDGE_PUBK.decompress().unwrap());
    if peer == "bob".to_string(){

        //Side of Alice
        let start = Instant::now();

        let  (secret_a ,A ,sk ,pk ) = init_key();
    
        send.send(Bytes::copy_from_slice(& A.to_bytes())).await.unwrap();

        let sok_rec_0 = tokio::stream::StreamExt::next(&mut recv).await.unwrap().unwrap().freeze();
        let sok_rec_1 = tokio::stream::StreamExt::next(&mut recv).await.unwrap().unwrap().freeze();
        let sok_recv = vec![SigmaOr::from(&sok_rec_0.to_vec().try_into().unwrap()),SigmaOr::from(&sok_rec_1.to_vec().try_into().unwrap())];
        
        if sok_verify(sok_recv.clone(),Choice::from(1)){
        
            println!("[+] SoK_B recv verified");

        }
        else{
            panic!("SoK_B is not valid");
        }

        let recv_B = tokio::stream::StreamExt::next(&mut recv).await.unwrap().unwrap().freeze();
        println!("[+] Recevied B:{:?}",recv_B);

        let signature_of_knowledge = sok(A.clone().try_into().unwrap(),recv_B.clone().try_into().unwrap(),pk,secret_a.clone(),sk,Choice::from(0));

        send.send(Bytes::copy_from_slice( &signature_of_knowledge[0].to_bytes())).await.unwrap();
        send.send(Bytes::copy_from_slice( &signature_of_knowledge[1].to_bytes())).await.unwrap();


        let (K,rho_A,alpha) = derive_key(A, PublicKey::from(recv_B.clone()), secret_a.clone(), signature_of_knowledge, sok_recv.clone(),  Choice::from(0));
        let duration = start.elapsed();
        println!("[+] Alice finished key exchange in {:?}",duration);
        println!("[+] key established:{:?}",K);

        println!("[+] Start Avow");
        let (c_A 
        , z_A 
        , s_A 
        , r_A 
        , E_A
        , R_A) = notry::avow::Init();

        println!("z_A:{:?}",z_A);
        send.send(Bytes::copy_from_slice(& E_A.clone().compress().to_bytes())).await.unwrap();
        send.send(Bytes::copy_from_slice(& R_A.clone().compress().to_bytes())).await.unwrap();  

        let (cipher,ciphertext) = AES_Enc(K, vec![c_A.clone(),z_A.clone(),s_A]);

        let recv_R_B = tokio::stream::StreamExt::next(&mut recv).await.unwrap().unwrap().freeze();

        println!("[+] recv R_B");
        let recv_ciphertext = tokio::stream::StreamExt::next(&mut recv).await.unwrap().unwrap().freeze();
        let recv_ciphertext_decrpted = cipher.decrypt(Nonce::from_slice(b"avow_key_exc"), recv_ciphertext.clone().to_vec().as_ref()).unwrap();
        let recv_c_B = StaticSecret(Scalar::from_bits( recv_ciphertext_decrpted[..32].try_into().unwrap()));
        let recv_z_B = StaticSecret(Scalar::from_bits( recv_ciphertext_decrpted[32..64].try_into().unwrap()));


        println!("[+] recv c_B and z_B");
        

        println!("[+] sending encrypted c_A, z_A, and s_A");

        send.send(Bytes::from(ciphertext.clone())).await.unwrap();

        println!("[+] generating avow proof");
        let mut avow_prof = prove_avow(c_A, recv_c_B, z_A, recv_z_B, R_A, 
           CompressedRistretto(recv_R_B.to_vec().try_into().unwrap()).decompress().unwrap(), pk_J);

        let z_alpha = Scalar::from_bits( avow_prof.c_AB) * secret_a.0 + r_A.0;
        
        send.send(Bytes::copy_from_slice( &z_alpha.to_bytes())).await.unwrap();
        let recv_z_beta = tokio::stream::StreamExt::next(&mut recv).await.unwrap().unwrap().freeze();


        let z_AB = z_alpha + Scalar::from_bits( recv_z_beta.to_vec().try_into().unwrap());
        avow_prof.z_AB = z_AB;
        avow_prof.AB = CompressedRistretto(recv_B.to_vec().try_into().unwrap()).decompress().unwrap() + A.0;
        

        let duration_2 = start.elapsed();
        println!("[+] Alice finished avow in {:?}",duration_2-duration);

        if Judge(pk_J, avow_prof){
            println!("[+] succeed avow");
        }
        else{
            println!("[+] avow denied");
        }
        println!("[+] Alice runs {:?}",duration_2);
        let total_size = 32 + size_of::<SigmaOr>()*2 + 32 + 32 + ciphertext.len() + 32;
        println!("Alice's Communication overhead:{}",total_size);




}
    else{
        //Bob
        let start = Instant::now();

        let  (secret_b ,B ,sk ,pk ) = init_key();

        let recv_A = tokio::stream::StreamExt::next(&mut recv).await.unwrap().unwrap().freeze();
        let signature_of_knowledge = sok(recv_A.clone().try_into().unwrap(),B,pk,secret_b.clone(),sk,Choice::from(1));
        println!("[+] recevied A:{:?}",recv_A);
        send.send(Bytes::copy_from_slice( &signature_of_knowledge[0].to_bytes())).await.unwrap();
        send.send(Bytes::copy_from_slice( &signature_of_knowledge[1].to_bytes())).await.unwrap();

        send.send(Bytes::copy_from_slice(& B.to_bytes())).await.unwrap();


        let sok_rec_0 = tokio::stream::StreamExt::next(&mut recv).await.unwrap().unwrap().freeze();
        let sok_rec_1 = tokio::stream::StreamExt::next(&mut recv).await.unwrap().unwrap().freeze();
        let sok_recv = vec![SigmaOr::from(&sok_rec_0.to_vec().try_into().unwrap()),SigmaOr::from(&sok_rec_1.to_vec().try_into().unwrap())];

        if sok_verify(sok_recv.clone(),Choice::from(0)){
        
            println!("[+] SoK_A recv verified");

        }
        else{
            panic!("SoK_A is not valid");
        }
        let (K,rho_B,beta) = derive_key(PublicKey::from(recv_A.clone()), B, secret_b.clone(), sok_recv.clone(), signature_of_knowledge,Choice::from(1));
        let duration = start.elapsed();
        println!("[+] Bob finished key exchange in {:?}",duration);
        println!("[+] key established:{:?}",K);

        println!("[+] Start Avow");

        let (c_B 
            , z_B 
            , _ 
            , r_B 
            , _
            , R_B) = notry::avow::Init();
        
        let recv_E_A = tokio::stream::StreamExt::next(&mut recv).await.unwrap().unwrap().freeze();
        let recv_R_A = tokio::stream::StreamExt::next(&mut recv).await.unwrap().unwrap().freeze();
        
        let (cipher,ciphertext) = AES_Enc(K, vec![c_B.clone(),z_B.clone()]);


        send.send(Bytes::copy_from_slice(&R_B.compress().to_bytes())).await.unwrap();
        send.send(Bytes::from(ciphertext.clone())).await.unwrap();
        println!("[+] sending R_B and encrypted c_B and z_B");

        let recv_enc_pack = tokio::stream::StreamExt::next(&mut recv).await.unwrap().unwrap().freeze();
        let recv_dec_pack = cipher.decrypt(Nonce::from_slice(b"avow_key_exc"), recv_enc_pack.to_vec().as_slice()).unwrap();
        
        let Recv_c_A:StaticSecret = StaticSecret(Scalar::from_bits( recv_dec_pack[..32].try_into().unwrap()));
        let Recv_z_A:StaticSecret = StaticSecret(Scalar::from_bits( recv_dec_pack[32..64].try_into().unwrap())); 
        let Recv_s_A:StaticSecret = StaticSecret(Scalar::from_bits( recv_dec_pack[64..96].try_into().unwrap()));
        
        assert_eq!(recv_E_A.to_vec(),   Bytes::copy_from_slice(&(Recv_c_A.0 * RISTRETTO_BASEPOINT2.decompress().unwrap() 
                                                + &Recv_z_A.0 * &RISTRETTO_BASEPOINT_TABLE 
                                                + Recv_s_A.0 * RISTRETTO_BASEPOINT_RANDOM.decompress().unwrap()).compress().to_bytes()));
    
        println!("[+] generating avow proof");
        
        let mut avow_prof = prove_avow(Recv_c_A, c_B, Recv_z_A, z_B, 
            CompressedRistretto( recv_R_A.to_vec().try_into().unwrap()).decompress().unwrap(), R_B, pk_J);
        
        let z_beta = Scalar::from_bits( avow_prof.c_AB) * secret_b.0 + r_B.0;
        
        let recv_z_alpha = tokio::stream::StreamExt::next(&mut recv).await.unwrap().unwrap().freeze();
        send.send(Bytes::copy_from_slice(&z_beta.to_bytes())).await.unwrap();
        
        

        let z_AB = z_beta + Scalar::from_bits( recv_z_alpha.to_vec().try_into().unwrap());
        avow_prof.z_AB = z_AB;
        avow_prof.AB = CompressedRistretto(recv_A.to_vec().try_into().unwrap()).decompress().unwrap() + B.0;
        
        let duration_2 = start.elapsed();
        println!("[+] Bob finished avow in {:?}",duration_2-duration);

        if Judge(pk_J, avow_prof){
            println!("[+] succeed avow");
        }
        else{
            println!("[+] avow denied");
        }
        println!("[+] Bob runs {:?}",duration_2);

        let total_size = size_of::<SigmaOr>()*2+ 32 + 32 + ciphertext.len() + 32;
        println!("Bob's Communication overhead:{}",total_size);
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