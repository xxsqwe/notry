use std::convert::TryInto;
use std::time::{Instant, Duration};
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
#[allow(unused_imports)]

use aes_gcm::{
    aead::{Aead, KeyInit, consts::U12},
    Aes256Gcm, Nonce};
#[allow(unused_imports)]

use aes_gcm::aead::generic_array::GenericArray;

use curve25519_dalek::{scalar::Scalar};

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

    ratchet(cfg.clone(),peer.clone(),initiate);
}

#[allow(non_snake_case,unused_variables,unused_assignments)]
#[tokio::main]
async fn ratchet(cfg: ClientConfig, peer: String, initiate: bool) {
    use std::io::{stderr, Write};
    println!("peer:{}",peer);
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
    // the rounds  variable indicates the number of session keys to be established
    let rounds=1000;

    if peer.contains("ob"){

        
        
        let  (_ ,_ ,sk ,pk ) = init_key();
        let mut session_material:Vec<(StaticSecret, PublicKey, PublicKey,Vec<SigmaOr>, Vec<SigmaOr>)> = Vec::new();
        let mut comm_size =0;
        let mut size_total = 0;
        let mut computation_time=Duration::new(0, 0);
        let mut start = Instant::now();
    for i in 0..rounds
    {
        //Alice
            start = Instant::now();
            let starttime =start.elapsed();
            let  (secret_a ,A ,_ ,_ ) = init_key();
            let signature_of_knowledge = 
            if i == 0{
                send.send(Bytes::copy_from_slice(& A.to_bytes())).await.unwrap();
                comm_size=size_of::<PublicKey>();
                vec![SigmaOr::new(),SigmaOr::new()]
            }
            else{
                let signature_of_knowledge = sok(A.clone().try_into().unwrap(),session_material[i-1].2.try_into().unwrap(),pk,secret_a.clone(),sk.clone(),Choice::from(0));

                send.send(Bytes::copy_from_slice(& A.to_bytes())).await.unwrap();

                send.send(Bytes::copy_from_slice( &signature_of_knowledge[0].to_bytes())).await.unwrap();
                send.send(Bytes::copy_from_slice( &signature_of_knowledge[1].to_bytes())).await.unwrap();
                comm_size=size_of::<PublicKey>()+signature_of_knowledge[0].size()*2;

                signature_of_knowledge

            };
        

        
            let sok_rec_0 = tokio::stream::StreamExt::next(&mut recv).await.unwrap().unwrap().freeze();
            let sok_rec_1 = tokio::stream::StreamExt::next(&mut recv).await.unwrap().unwrap().freeze();
            let sok_recv = vec![SigmaOr::from(&sok_rec_0.to_vec().try_into().unwrap()),SigmaOr::from(&sok_rec_1.to_vec().try_into().unwrap())];
        
            if sok_verify(sok_recv.clone(),Choice::from(1)){
        
                //println!("[+] SoK_B recv verified");

            }
            else{
                panic!("SoK_B is not valid");
            }

        
            let recv_B = tokio::stream::StreamExt::next(&mut recv).await.unwrap().unwrap().freeze();
            //println!("[+] Recevied B:{:?}",recv_B);
            
            session_material.push((secret_a.clone(),A,PublicKey::from(recv_B),signature_of_knowledge.clone(),sok_recv.clone()));
            
            
            let (K_alice,_,_) = 
                if i >0{
                
                 derive_key(A, session_material.clone()[i-1].2, secret_a.clone(), signature_of_knowledge.clone(), session_material[i-1].clone().4,  Choice::from(0))
                }
                else{
                    ([0u8;32],[0u8;32],Scalar::zero())
                };
            let (K_bob,_,_) = 
                if i >0{
                 derive_key(A, session_material[i].2, secret_a.clone(), signature_of_knowledge.clone(), sok_recv,  Choice::from(0))
                }
                else{
                    ([0u8;32],[0u8;32],Scalar::zero())
                };
            let duration = start.elapsed()-starttime;
            computation_time+=duration;
            //println!("[+] Alice finished key exchange in {:?}",duration/2);
            //println!("[+] alice key_{} established:{:?}",i,K_alice);
            //println!("[+] bob key_{} established:{:?}",i,K_bob);
            //println!("[x] Communication overhead per key:{}",comm_size/2);
            size_total+=comm_size;
        }
        println!("{} Bytes communication overhead,{:?} computation overhead for {} session keys",size_total,computation_time,rounds*2-1);
        println!("{} bytes {:?} per key",size_total/(rounds*2-1),computation_time/(rounds*2-1).try_into().unwrap());
    }

    else{
        //Bob
        let start = Instant::now();

        let  (_ ,_ ,sk ,pk ) = init_key();

        let mut session_material:Vec<(StaticSecret, PublicKey, PublicKey,Vec<SigmaOr>, Vec<SigmaOr>)> = Vec::new();

        let mut comm_size =0;
        let mut size_total = 0;
        let mut starttime= start.elapsed();

        for i in 0..rounds
        {
            starttime = start.elapsed();
            let  (secret_b ,B ,_ ,_ ) = init_key();

            let recv_A = tokio::stream::StreamExt::next(&mut recv).await.unwrap().unwrap().freeze();
            //println!("[+] recevied A:{:?}",recv_A);

            let sok_recv = 
            if i>0  
                {

                let sok_rec_0 = tokio::stream::StreamExt::next(&mut recv).await.unwrap().unwrap().freeze();
                let sok_rec_1 = tokio::stream::StreamExt::next(&mut recv).await.unwrap().unwrap().freeze();
                vec![SigmaOr::from(&sok_rec_0.to_vec().try_into().unwrap()),SigmaOr::from(&sok_rec_1.to_vec().try_into().unwrap())]
                
            }
            else{
                vec![SigmaOr::new(),SigmaOr::new()]
            };
            if i>0{
                if sok_verify(sok_recv.clone(),Choice::from(0)){
                
                    //println!("[+] SoK_A recv verified");

                }
                else{
                    panic!("SoK_A is not valid");
                }
            }
            else{

            }

            let signature_of_knowledge = sok(recv_A.clone().try_into().unwrap(),B,pk.clone(),secret_b.clone(),sk.clone(),Choice::from(1));
            send.send(Bytes::copy_from_slice( &signature_of_knowledge[0].to_bytes())).await.unwrap();
            send.send(Bytes::copy_from_slice( &signature_of_knowledge[1].to_bytes())).await.unwrap();

            send.send(Bytes::copy_from_slice(& B.to_bytes())).await.unwrap();

            comm_size=size_of::<PublicKey>()+signature_of_knowledge[0].size()*2;

            let (K_alice,_,_) =
                if i>0{
                    derive_key(PublicKey::from(recv_A.clone()), session_material[i-1].1, session_material[i-1].clone().0, sok_recv.clone(), session_material[i-1].clone().3,Choice::from(1))
                }
            
                else{
                    ([0u8;32],[08;32],Scalar::zero())
                };
            let (K_bob,_,_) =
                if i>0{
                    derive_key(PublicKey::from(recv_A.clone()), B, secret_b.clone(), sok_recv.clone(), signature_of_knowledge.clone(),Choice::from(1))
                }
            
                else{
                    ([0u8;32],[08;32],Scalar::zero())
                };
            
            let duration = start.elapsed()-starttime;
            session_material.push((secret_b.clone(),B,PublicKey::from(recv_A),signature_of_knowledge.clone(),sok_recv));

            //println!("[+] Bob finished key exchange in {:?}",duration);
            //println!("[+] alice k_{}:{:?}",i,K_alice);
            //println!("[+] bob k_{}:{:?}",i,K_bob);
            //println!("[x] Communication overhead for this round:{}",comm_size);
            size_total+=comm_size;

        }
    //println!("{} Bytes communication overhead for {} session keys",size_total,4);

}
}