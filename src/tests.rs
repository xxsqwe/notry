use crate::{
    utils::{hash,PublicKey,StaticSecret,xor,RISTRETTO_BASEPOINT2,get_cert_paths},
    sok::{sok,sok_verify,simulator},
    key_exchange::key_exchange,
    network::{Start_Client,Start_Judge,Comm_Channel},
    avow::{avow,Judge}


};
#[allow(unused_imports)]

use std::path::Path;
#[allow(unused_imports)]

use futures::{StreamExt, SinkExt, TryStreamExt, sink::Flush};

use bytes::Bytes;
#[allow(unused_imports)]
use curve25519_dalek::ristretto::{CompressedRistretto,RistrettoPoint};
#[allow(unused_imports)]
use curve25519_dalek::scalar::Scalar;
use subtle::Choice;
use rand::rngs::OsRng;
use hkdf::Hkdf;
#[allow(unused_imports)]

use sha2::{Sha256,Sha512};
#[allow(unused_imports)]

use tokio::{runtime, time};
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce // Or `Aes128Gcm`
};
#[test]
fn test_simulator() {
    println!("random:{:?}",RistrettoPoint::random( &mut OsRng).compress());

    let alice_secret = StaticSecret::new(&mut OsRng);
    let alice_public = PublicKey::from(&alice_secret);
    println!("Alice Public={:?}", alice_public);
    let s=simulator(alice_public,true);
    assert_eq!(&s.0.0*&(RISTRETTO_BASEPOINT2.decompress().unwrap()),s.2.0+alice_public.0*s.1.0);
}
#[test]
#[allow(non_snake_case)]
fn test_hash(){
    let message= String::from("dlog_{h}A or dlog_{h}B");
    let m2=String::from("holy shit");
    let alice_secret = StaticSecret::new(&mut OsRng);
    let alice_public = PublicKey::from(&alice_secret);
    println!("alice secret is {:?}", alice_secret.to_bytes());
    println!("linked array:{:?}",&alice_public.to_bytes().iter().chain(message.as_bytes()).chain(m2.as_bytes()).cloned().collect::<Vec<u8>>());
    let FS=hash(&alice_public.to_bytes().iter().chain(message.as_bytes()).cloned().collect::<Vec<u8>>());
    
    println!("hash of msg:{:?}",FS);
    println!("xored:{:?}",      FS.iter().zip(alice_secret.to_bytes()).map(|(x,y)| x^y).collect::<Vec<u8>>());

    let hf=Hkdf::<Sha256>::new(None,&alice_public.to_bytes().iter().chain(message.as_bytes()).cloned().collect::<Vec<u8>>());
    let mut okm = [0u8;32];
    hf.expand(&[] as &[u8;0], &mut okm).expect("HDKF expands failed");
    let rho=hash(&okm.iter().chain(String::from("avow").as_bytes()).cloned().collect::<Vec<u8>>());
    println!("rho:{:?}",rho.as_slice());
    println!("output key material:{:?}",rho.iter().zip(alice_secret.0.to_bytes()).map(|(x,y)| x^y).collect::<Vec<u8>>());
    println!("xor:{:?}",xor(rho[..32].try_into().unwrap(),alice_secret.to_bytes()));
    
    let _key = Aes256Gcm::generate_key(&mut aes_gcm::aead::OsRng);
    let cipher = Aes256Gcm::new(GenericArray::from_slice(& okm));
    let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message
    let ciphertext = cipher.encrypt(nonce, b"plaintext message".as_ref()).unwrap();
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
    assert_eq!(&plaintext, b"plaintext message");
    //assert_eq!(1,1)
}



#[test]
#[allow(non_snake_case)]
fn test_sok(){
    let secret_a = StaticSecret::new(&mut OsRng);
    let A = PublicKey::from(&secret_a);

    let secret_b = StaticSecret::new(&mut OsRng);
    let B = PublicKey::from(&secret_b);

    let sk = StaticSecret::new(&mut OsRng);
    let pk = &sk.0 * &RISTRETTO_BASEPOINT2.decompress().unwrap();
    //let Signature_of_Knowledge = sok(A,B,PublicKey(pk),secret_a,sk,Choice::from(0));
    assert_eq!(true, sok_verify( sok(A,B,PublicKey(pk),secret_a,sk,Choice::from(0)),Choice::from(0)));
}
#[allow(unused_mut,unused_variables)]
#[test]
fn test_network(){
    let (cpath,kpath) = get_cert_paths();
    let mut rt = runtime::Builder::new().basic_scheduler().enable_all().build().unwrap();
    rt.block_on(async move{
    
    let coord = Start_Judge(&cpath, &kpath).await;
    let port = coord.local_addr().port();
    let (mut client1,mut _inc1) =  Start_Client(&cpath, "client1".to_string(), port).await;
    

    let (_client2,mut inc2) = Start_Client(&cpath, "client2".to_string(), port).await;

    let (mut coordinator, incoord) = Start_Client(&cpath, "coordinator".to_string(), port).await;

    client1.new_channel("client2".to_string()).await.unwrap();
        let (mut s12, mut r21) = client1.new_direct_stream("client2".to_string()).await.unwrap();
        // receive stream at client2
        
        let (_, _, mut s21, mut r12) = inc2.next().await.unwrap();

        let to_send = Bytes::from("ping pong");
        s12.send(to_send.clone()).await.unwrap();
        println!("clinet 1 to client 2: {:?}",to_send);
        let rec = r12.try_next().await?.unwrap().freeze();
        println!("clinet 2 from client 1: {:?}",rec);
        s21.send(rec).await.unwrap();
        
        let rec = r21.try_next().await?.unwrap();
        println!("clinet 1 get back from client 2: {:?}",rec);
        s12.send(to_send.clone()).await.unwrap();
        let rec = r12.try_next().await?.unwrap().freeze();
        println!("round 2:{:?}",rec);
        

    let (mut send_coord2client1,mut recv_client2coord) =  coordinator.new_stream("client1".to_string()).await.unwrap();
    
    let (peer,strmid,mut send_client2coord, mut recv_coord2client1) = _inc1.next().await.unwrap();
    send_coord2client1.send(to_send.clone()).await.unwrap();
    
    let rec = recv_coord2client1.try_next().await?.unwrap().freeze();

    assert_eq!(to_send, rec);
        Ok(()) as Result<(), std::io::Error>
    })
    .unwrap();
    
}

#[allow(non_snake_case,unused_mut,unused_variables)]
fn test_sok_network(){
    let secret_a = StaticSecret::new(&mut OsRng);
    let A = PublicKey::from(&secret_a);

    let secret_b = StaticSecret::new(&mut OsRng);
    let B = PublicKey::from(&secret_b);

    let sk = StaticSecret::new(&mut OsRng);
    let pk = &sk.0 * &RISTRETTO_BASEPOINT2.decompress().unwrap();
    

    let signature_of_knowledge = sok(A,B,PublicKey(pk),secret_a,sk,Choice::from(0));
    //println!("signature of knowledge:{:?}",signature_of_knowledge[0].to_bytes());
    //println!("recovered:{:?}",SigmaOr::from(& signature_of_knowledge[0].to_bytes().try_into().unwrap()).to_bytes());
    let (cpath,kpath) = get_cert_paths();
    let mut rt = runtime::Builder::new().basic_scheduler().enable_all().build().unwrap();
    rt.block_on(async move{
        let coord = Start_Judge(&cpath, &kpath).await;
        let port = coord.local_addr().port();
        let (mut client1,_inc1) =  Start_Client(&cpath, "client1".to_string(), port).await;
    

        let (client2,mut inc2) = Start_Client(&cpath, "client2".to_string(), port).await;

        /*client1.new_channel("client2".to_string()).await.unwrap();
        let (mut s12, mut r21) = client1.new_direct_stream("client2".to_string()).await.unwrap();
        // receive stream at client2
        
        let (_, _, mut s21, mut r12) = inc2.next().await.unwrap();*/
        let P = RistrettoPoint::random(&mut OsRng);
        println!("P={:?}",P.compress().to_bytes());
        let to_send =Bytes::copy_from_slice(&signature_of_knowledge[0].to_bytes());
        //println!("clinet 1 to client 2: {:?}",to_send);
        let  (mut channel1,mut channel2)=Comm_Channel::new(client1, "client2".to_string(), inc2).await;
        channel1.send(to_send,Choice::from(0)).await;
        
        let sok_recv= channel1.recv(Choice::from(1)).await;
        
        
        
        let to_send = Bytes::copy_from_slice(&signature_of_knowledge[1].to_bytes());
        println!("clinet 1 to client 2: {:?}",to_send);
        
        channel1.send(to_send.clone(),Choice::from(0)).await;

        
        let rec =channel1.recv(Choice::from(0)).await;
        //let sok_recv = vec![SigmaOr::from(&rec.to_vec().try_into().unwrap()),SigmaOr::from(&rec1.to_vec().try_into().unwrap())];
        println!("clinet 2 from client 1: {:?}",rec);

        assert_eq!(rec.to_vec(),signature_of_knowledge[1].to_bytes());
        
        //assert_eq!(true,sok_verify(sok_recv, Choice::from(0)));
        Ok(()) as Result<(), std::io::Error>
    })
    .unwrap();
}
#[allow(non_snake_case,unused_variables,unused_mut)]
#[test]
fn test_key_exchange(){
    let mut rt = runtime::Builder::new().basic_scheduler().enable_all().build().unwrap();
    rt.block_on(async move{
    key_exchange().await;
    })
    /*
    let secret_a = StaticSecret::new(&mut OsRng);
    let A = PublicKey::from(&secret_a);

    let secret_b = StaticSecret::new(&mut OsRng);
    let B = PublicKey::from(&secret_b);

    let sk_a = StaticSecret::new(&mut OsRng);
    let pk_a = &sk_a.0 * &RISTRETTO_BASEPOINT2.decompress().unwrap();

    let sk_b = StaticSecret::new(&mut OsRng);
    let pk_b = &sk_b.0 * &RISTRETTO_BASEPOINT2.decompress().unwrap();

    let (cpath,kpath) = get_cert_paths();
    let mut rt = runtime::Builder::new().basic_scheduler().enable_all().build().unwrap();
    rt.block_on(async move{

        let Judge = Start_Judge(&cpath, &kpath).await;
        let port = Judge.local_addr().port();
        let (mut Alice, _incAlice) = Start_Client(&cpath, "Alice".to_string(), port).await;
        let (Bob,mut incBob) = Start_Client(&cpath, "Bob".to_string(), port).await;
        let (mut chal1,mut chal2) = Comm_Channel::new(Alice,"Bob".to_string(),incBob).await;

        let share_key = Alice_key_exchange(secret_a, sk_a, PublicKey( pk_a), PublicKey( pk_b), chal1).await;

        let Bob_kex = thread::spawn(move| |{
        block_on( Bob_key_exchange(secret_b, sk_b, PublicKey( pk_a), PublicKey( pk_b), chal2));
    }
        
    );
    Bob_kex.join().expect("bob kex failed");


}) */
}
#[allow(non_snake_case)]
#[test]
fn test_avow(){
    let mut rt = runtime::Builder::new().basic_scheduler().enable_all().build().unwrap();
    
    let secret_j = StaticSecret::new(&mut OsRng);
    let pk_J = PublicKey::from(&secret_j);
    rt.block_on(async move{
    let (pk_a,pk_b,AB,sk_a,sk_b,k_sess, alpha, beta) 
            = key_exchange().await;
            
    let mut avow_prof = 
        avow(pk_a,pk_b, pk_J,sk_a,sk_b,alpha,beta,true,k_sess.to_bytes()).await;
        
    avow_prof.AB = AB.0;
        //assert_eq!(avow_prof.c_AB * alpha + avow_prof.r_A + avow_prof.c_AB * beta+avow_prof.r_B, avow_prof.z_AB);
        assert_eq!(true,Judge(pk_J, avow_prof));
    });
    
}