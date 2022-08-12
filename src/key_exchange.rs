#[allow(unused_imports)]
use std::path::Path;
use std::thread;

use bytes::Bytes;
use curve25519_dalek::ristretto::CompressedRistretto;
use hkdf::Hkdf;
use sha2::Sha256;

use crate::utils::{PublicKey,StaticSecret,xor,hash,get_cert_paths, RISTRETTO_BASEPOINT2};
use crate::sok::{sok,sok_verify,SigmaOr};

#[allow(unused_imports)]
use tokio::{runtime, time};
use rand::rngs::OsRng;
use subtle::Choice;
use futures::executor::block_on;
use crate::network::{Start_Client, Comm_Channel,Start_Judge};
/// Role 0 for Alice, 1 for Bob
#[allow(non_snake_case,unused_variables)]
pub async fn Alice_key_exchange( secret:StaticSecret, Sk:StaticSecret, Alice_Pk:PublicKey, Bob_Pk: PublicKey, mut A2B_bi:Comm_Channel) -> PublicKey{
    
    
        let Gamma = StaticSecret::new(&mut OsRng);
        let A = PublicKey::from(&Gamma);
        //let (mut Alice, _inc1) = Start_Client(cpath, "alice".to_string(), coorder.local_addr().port()).await;
        //Alice.new_channel("Bob".to_string()).await;
        //let (mut s12, mut r21) = Alice.new_direct_stream("client2".to_string()).await.unwrap();
        //let (_, _, mut s21, mut r12) = incomingBob.next().await.unwrap();
        //let mut A2B_bi = Comm_Channel::new(Alice,"Bob")
        A2B_bi.send(Bytes::copy_from_slice(& A.to_bytes()),Choice::from(0)).await;
        
        let B = PublicKey::from( A2B_bi.recv(Choice::from(0)).await);
        let Sok_B_0 = A2B_bi.recv(Choice::from(0)).await;
        let Sok_B_1 = A2B_bi.recv(Choice::from(0)).await;
        let Sok_B = vec![SigmaOr::from(&Sok_B_0.to_vec().try_into().unwrap()),SigmaOr::from(&Sok_B_1.to_vec().try_into().unwrap())];
        let Sok_A = if sok_verify(Sok_B, Choice::from(1)){
            sok(A,B,Alice_Pk,secret,Sk,Choice::from(0))
        }
        else{
            panic!("Signature of Knowledge recv from Bob is invalid");
        };
        let to_send =Bytes::copy_from_slice( &Sok_A[0].to_bytes());
        A2B_bi.send(to_send.clone(), Choice::from(0)).await;
        let to_send_final = Bytes::copy_from_slice(&Sok_A[1].to_bytes());
        A2B_bi.send(to_send_final.clone(),Choice::from(0)).await;
        
       
        let K = Gamma.0 * B.0;
            // HKDF
            let KeyMatereial = A.to_bytes().iter()
                                                .chain(&B.to_bytes())
                                                .chain(&Sok_A[0].to_bytes())
                                                .chain(&Sok_A[1].to_bytes())
                                                .chain(&Sok_B_0.to_vec())
                                                .chain(&Sok_B_1.to_vec())
                                                .chain(&K.compress().to_bytes())
                                                .cloned()
                                                .collect::<Vec<_>>();
            let mut k_sess_A = [0u8;32];
            let hf = Hkdf::<Sha256>::new(None,&KeyMatereial);
            hf.expand(&[] as &[u8;0],  &mut k_sess_A).expect("HKDF expansion Failed"); //KDF(A || B || σ A || σ B || K)
            let rho_A = hash(&k_sess_A.iter().chain(String::from("avow").as_bytes()).cloned().collect::<Vec<u8>>());//H(k_sess|| “avow”)
            let _alpha = xor(rho_A,Gamma.0.to_bytes());
            PublicKey(CompressedRistretto(rho_A).decompress().unwrap())
        }
#[allow(non_snake_case)]
pub async fn Bob_key_exchange(secret:StaticSecret, Sk:StaticSecret, _Alice_Pk:PublicKey, Bob_Pk: PublicKey, mut A2B_bi:Comm_Channel) -> PublicKey{
        
        let Delta = StaticSecret::new(&mut OsRng);
        let B = PublicKey::from(&Delta);
        let A = PublicKey::from( A2B_bi.recv(Choice::from(1)).await);
        let Sok_B = sok(A,B,Bob_Pk,secret,Sk,Choice::from(1));
        A2B_bi.send(Bytes::copy_from_slice( &B.to_bytes()), Choice::from(1)).await;
        A2B_bi.send(Bytes::copy_from_slice( &Sok_B[0].to_bytes()), Choice::from(1)).await;

        A2B_bi.send(Bytes::copy_from_slice( &Sok_B[0].to_bytes()), Choice::from(1)).await;

        let Sok_A_0 = A2B_bi.recv(Choice::from(1)).await;
        let Sok_A_1 = A2B_bi.recv(Choice::from(1)).await;
        let Sok_A = vec![SigmaOr::from(&Sok_A_0.to_vec().try_into().unwrap()),SigmaOr::from(&Sok_A_1.to_vec().try_into().unwrap())];
        let K = if sok_verify(Sok_A,Choice::from(0)){
            A.0 * Delta.0
        }
        else{
            panic!("Signature of Knowledge recv from Alice is invalid");

        };

        let KeyMatereial = A.to_bytes().iter()
                                                .chain(&B.to_bytes())
                                                .chain(&Sok_A_0.to_vec())
                                                .chain(&Sok_A_1.to_vec())
                                                .chain(&Sok_B[0].to_bytes())
                                                .chain(&Sok_B[1].to_bytes())
                                                .chain(&K.compress().to_bytes())
                                                .cloned()
                                                .collect::<Vec<_>>();
        let mut k_sess_B = [0u8;32];
        let hf = Hkdf::<Sha256>::new(None,&KeyMatereial);
        hf.expand(&[] as &[u8;0],  &mut k_sess_B).expect("HKDF expansion failed"); //KDF(A || B || σ A || σ B || K)
        let rho_B = hash(&k_sess_B.iter().chain(String::from("avow").as_bytes()).cloned().collect::<Vec<u8>>());//H(k_sess|| “avow”)
        let _beta = xor(rho_B,Delta.0.to_bytes());
        PublicKey(CompressedRistretto(rho_B).decompress().unwrap())
        

}
        
#[test]
fn test_key_exchange(){
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
        let mut chal = Comm_Channel::new(Alice,"Bob".to_string(),incBob).await;

        let share_key = Alice_key_exchange(secret_a, sk_a, PublicKey( pk_a), PublicKey( pk_b), chal).await;

        let alice_kex = thread::spawn(move| |{
        block_on( Bob_key_exchange(secret_b, sk_b, PublicKey( pk_a), PublicKey( pk_b), chal));
    }
    );



})
}

