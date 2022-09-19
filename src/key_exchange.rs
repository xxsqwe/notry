#[allow(unused_imports)]
use std::path::Path;

use bytes::Bytes;
use curve25519_dalek::ristretto::{CompressedRistretto,RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use futures::{StreamExt, SinkExt, TryStreamExt};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::utils::{PublicKey,StaticSecret,xor,hash,get_cert_paths, RISTRETTO_BASEPOINT2};
use crate::sok::{sok,sok_verify,SigmaOr};

#[allow(unused_imports)]
use tokio::{runtime, time};
use rand::rngs::OsRng;
use subtle::Choice;
use crate::network::{Start_Client, Comm_Channel,Start_Judge};


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
            let _alpha = xor(rho_A[..32].try_into().unwrap(),Gamma.0.to_bytes());
            PublicKey(CompressedRistretto(rho_A[..32].try_into().unwrap()).decompress().unwrap())
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
        let _beta = xor(rho_B[..32].try_into().unwrap(),Delta.0.to_bytes());
        PublicKey(CompressedRistretto(rho_B[..32].try_into().unwrap()).decompress().unwrap())
        

}
#[allow(non_snake_case,unused_variables)]
pub async fn key_exchange() -> 
    (PublicKey, PublicKey,PublicKey,
     StaticSecret,StaticSecret,
     PublicKey,
    Scalar,Scalar,
    ){
    let secret_a = StaticSecret::new(&mut OsRng);
    let A = PublicKey::from(&secret_a);

    let secret_b = StaticSecret::new(&mut OsRng);
    let B = PublicKey::from(&secret_b);

    let sk_a = StaticSecret::new(&mut OsRng);
    let pk_a = &sk_a.0 * &RISTRETTO_BASEPOINT2.decompress().unwrap();

    let sk_b = StaticSecret::new(&mut OsRng);
    let pk_b = &sk_b.0 * &RISTRETTO_BASEPOINT2.decompress().unwrap();

    let (cpath,kpath) = get_cert_paths();
    let Judge = Start_Judge(&cpath, &kpath).await;
    let port = Judge.local_addr().port();
    
    let (mut Alice, _incAlice) = Start_Client(&cpath, "Alice".to_string(), port).await;
    let (Bob,mut IncBOB) =Start_Client(&cpath, "Bob".to_string(), port).await;

    Alice.new_channel("Bob".to_string()).await.unwrap();

    let (mut s12,mut r21) = Alice.new_direct_stream("Bob".to_string()).await.unwrap();
    let (_,_,mut s21, mut r12) = IncBOB.next().await.unwrap();

    // Alice sends A to Bob
    s12.send(Bytes::copy_from_slice(&A.to_bytes())).await.unwrap();
    
    // Bob Recvs A and prepare SoK
    let Recv_A =PublicKey::from( r12.try_next().await.unwrap().unwrap().freeze());
    let SoK_B = sok(Recv_A,B, PublicKey( pk_b), secret_b.clone(),sk_b.clone(),Choice::from(1));
    // Bob sends SoK_B and B to Alice
    //Alice recvs SoKB, unwraps it, then verify it
    s21.send(Bytes::copy_from_slice(&SoK_B[0].to_bytes())).await.unwrap();
    let recv_SoKB_0 = r21.try_next().await.unwrap().unwrap().freeze();

    s21.send(Bytes::copy_from_slice(&SoK_B[1].to_bytes())).await.unwrap();
    let recv_SoKB_1 = r21.try_next().await.unwrap().unwrap().freeze();

    s21.send(Bytes::copy_from_slice(&B.to_bytes())).await.unwrap();

    
    
    let recv_SoKB = vec![SigmaOr::from( &recv_SoKB_0.to_vec().try_into().unwrap()),
                                       SigmaOr::from( &recv_SoKB_1.to_vec().try_into().unwrap())];
    
    assert_eq!(true, sok_verify(recv_SoKB, Choice::from(1)));

    //Alice gets B and compute her sok_A, then sends her sok to Bob
    let Recv_B = PublicKey::from( r21.try_next().await.unwrap().unwrap().freeze());
    let SoK_A = sok(A,B,PublicKey( pk_a),secret_a.clone(),sk_a.clone(),Choice::from(0));

    //Bob recvs SoKA, unwraps it, then verify
    s12.send(Bytes::copy_from_slice(&SoK_A[0].to_bytes())).await.unwrap();
    let recv_SoKA_0 = r12.try_next().await.unwrap().unwrap().freeze();

    s12.send(Bytes::copy_from_slice(&SoK_A[1].to_bytes())).await.unwrap();
    let recv_SoKA_1 = r12.try_next().await.unwrap().unwrap().freeze();
    
    let recv_SoKA = vec![SigmaOr::from( &recv_SoKA_0.to_vec().try_into().unwrap()),
                                       SigmaOr::from( &recv_SoKA_1.to_vec().try_into().unwrap())];

    assert_eq!(true,sok_verify(recv_SoKA, Choice::from(0)));
    
    // Alice gets her DH key
    let Alice_K = Recv_B.0 * (secret_a.clone()).0;

    // Bob gets his DH key
    let Bob_K = Recv_A.0 * secret_b.clone().0;
    
    assert_eq!(Alice_K, Bob_K);
    
    let (k_sess_alice,alpha) =
    {
        // Alice run HKDF to produce session key k_sess
        let KeyMatereial = A.to_bytes().iter()
        .chain(&Recv_B.to_bytes())
        .chain(&SoK_A[0].to_bytes())
        .chain(&SoK_A[1].to_bytes())
        .chain(&recv_SoKB_0.to_vec())
        .chain(&recv_SoKB_1.to_vec())
        .chain(&Alice_K.compress().to_bytes())
        .cloned()
        .collect::<Vec<_>>();
        let mut k_sess_A = [0u8;32];
        let hf = Hkdf::<Sha256>::new(None,&KeyMatereial);
        hf.expand(&[] as &[u8;0],  &mut k_sess_A).expect("HKDF expansion Failed"); //KDF(A || B || σ A || σ B || K)
        let rho_A = hash(&mut k_sess_A.iter().chain(String::from("avow").as_bytes()).cloned().collect::<Vec<u8>>());//H(k_sess|| “avow”)
        let alpha =Scalar::from_bits( rho_A[..32].try_into().unwrap()) + Scalar::from_bits( secret_a.clone().0.to_bytes());
        //println!("k_sess_alice:{:?}",PublicKey::from(rho_A.to_vec().as_slice()));
        (PublicKey(RistrettoPoint::from_uniform_bytes(&rho_A)), alpha)
    };
    
    let (k_sess_bob,beta) =
    {
        // Alice run HKDF to produce session key k_sess
        let KeyMatereial = Recv_A.to_bytes().iter()
        .chain(&B.to_bytes())
        .chain(&recv_SoKA_0.to_vec())
        .chain(&recv_SoKA_1.to_vec())
        .chain(&SoK_B[0].to_bytes())
        .chain(&SoK_B[1].to_bytes())
        .chain(&Bob_K.compress().to_bytes())
        .cloned()
        .collect::<Vec<_>>();
        let mut k_sess_B = [0u8;32];
        let hf = Hkdf::<Sha256>::new(None,&KeyMatereial);
        hf.expand(&[] as &[u8;0],  &mut k_sess_B).expect("HKDF expansion Failed"); //KDF(A || B || σ A || σ B || K)
        let rho_B = hash(&mut k_sess_B.iter().chain(String::from("avow").as_bytes()).cloned().collect::<Vec<u8>>());//H(k_sess|| “avow”)
        let beta = Scalar::from_bits(secret_b.clone().0.to_bytes()) - Scalar::from_bits( rho_B[..32].try_into().unwrap());
        //println!("rho_A:{:?}",rho_B);

        (PublicKey(RistrettoPoint::from_uniform_bytes(&rho_B)), beta)
    };
    assert_eq!(k_sess_alice,k_sess_bob);
    assert_eq!(alpha+beta , secret_a.0+secret_b.0);
    //println!("alpha+beta:{:?}",alpha+beta );
    //println!("alpha+beta:{:?}",secret_a.0+secret_b.0);
    (PublicKey(pk_a),PublicKey(pk_b),PublicKey(A.0+B.0),sk_a, sk_b, k_sess_alice,alpha,beta)
    
    
}
pub fn init_key()-> (StaticSecret,PublicKey,StaticSecret,PublicKey){
    let secret_x = StaticSecret::new(&mut OsRng);
    let x = PublicKey::from(&secret_x);
    let sk = StaticSecret::new(&mut OsRng);
    let pk = PublicKey(&sk.0 * &RISTRETTO_BASEPOINT2.decompress().unwrap());
    (secret_x,x,sk,pk)
}
#[allow(non_snake_case)]
/// after exchanging DH like messages and verified SoK, both of the parties are now able to 
/// generate the shared key.
pub fn derive_key(A: PublicKey,B:PublicKey, secret_conponent:StaticSecret, SoK_A:Vec<SigmaOr>,SoK_B:Vec<SigmaOr>,role: Choice) -> ([u8;32],[u8;32],Scalar){
    let K = if role.unwrap_u8()==0u8{
        B.0 * secret_conponent.0
    }
    else{
        A.0 * secret_conponent.0
    };
    //println!("A={:?},B={:?}",A.0.compress().to_bytes(),B.0.compress().to_bytes());
    //println!("SokA={:?},\n SoKB={:?}",SoK_A[0].to_bytes(),SoK_B[0].to_bytes());
    //åprintln!("k_agree={:?}",K.compress().to_bytes());
    let KeyMatereial = A.to_bytes().iter()
                                                .chain(&B.to_bytes())
                                                .chain(&SoK_A[0].to_bytes())
                                                .chain(&SoK_A[1].to_bytes())
                                                .chain(&SoK_B[0].to_bytes())
                                                .chain(&SoK_B[1].to_bytes())
                                                .chain(&K.compress().to_bytes())
                                                .cloned()
                                                .collect::<Vec<_>>();
            let mut k_sess = [0u8;32];
            let hf = Hkdf::<Sha256>::new(None,&KeyMatereial);
            hf.expand(&[] as &[u8;0],  &mut k_sess).expect("HKDF expansion Failed"); //KDF(A || B || σ A || σ B || K)
            let rho = hash(&k_sess.iter().chain(String::from("avow").as_bytes()).cloned().collect::<Vec<u8>>());//H(k_sess|| “avow”)
            let alpha_beta = if role.unwrap_u8()==0u8{
                Scalar::from_bits( rho[..32].try_into().unwrap()) + Scalar::from_bits( secret_conponent.clone().0.to_bytes())
            }
            else{
                Scalar::from_bits( rho[..32].try_into().unwrap()) - Scalar::from_bits( secret_conponent.clone().0.to_bytes())

            };
            (k_sess,rho[..32].try_into().unwrap(),alpha_beta)

}

