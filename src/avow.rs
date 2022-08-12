use crate::utils::{PublicKey,StaticSecret,RISTRETTO_BASEPOINT2,RISTRETTO_BASEPOINT_RANDOM,xor, hash,get_cert_paths};
use crate::network::{Start_Client,Start_Judge};
//use crate::key_exchange::key_exchange;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce // Or `Aes128Gcm`
};
use bytes::Bytes;
use curve25519_dalek::constants::{RISTRETTO_BASEPOINT_TABLE};

use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::scalar::{Scalar};
use rand::rngs::OsRng;
#[allow(non_camel_case_types,dead_code,non_snake_case)]
#[derive(Debug)]
pub struct avow_proof{
    c_AB : StaticSecret,
    z_AB : Scalar,
    c_J  : Scalar,
    z_j  : Scalar,
}
use futures::{StreamExt, SinkExt, TryStreamExt};

/// role 1 for Bob and 0 for Alice
/// 
/// 
#[allow(unused_variables,non_snake_case,unused_mut)]
pub async fn avow(alice:PublicKey, bob: PublicKey, judge: PublicKey, sk: StaticSecret, secret_a: StaticSecret, secret_b:StaticSecret, role:bool){


        let c_A = StaticSecret::new(&mut OsRng);
        let z_A = StaticSecret::new(&mut OsRng);
        let s_A = StaticSecret::new(&mut OsRng);
        let r_A = StaticSecret::new(&mut OsRng);
        let E_A = c_A.0 * RISTRETTO_BASEPOINT2.decompress().unwrap() + &z_A.0 * &RISTRETTO_BASEPOINT_TABLE + s_A.0 * RISTRETTO_BASEPOINT_RANDOM.decompress().unwrap();
        let R_A = &r_A.0 * &RISTRETTO_BASEPOINT_TABLE;

        // setup communication channel
        let (cpath,kpath) = get_cert_paths();
        let Judge = Start_Judge(&cpath, &kpath).await;
        let port = Judge.local_addr().port();
    
        let (mut Alice, _incAlice) = Start_Client(&cpath, "Alice".to_string(), port).await;
        let (Bob,mut IncBob) =Start_Client(&cpath, "Bob".to_string(), port).await;

        Alice.new_channel("Bob".to_string()).await.unwrap();

        let (mut s12,mut r21) = Alice.new_direct_stream("Bob".to_string()).await.unwrap();
        let (_,_,mut s21, mut r12) = IncBob.next().await.unwrap();
        // Alice sends E_A and R_A to Bob
        s12.send(Bytes::copy_from_slice( &E_A.compress().to_bytes())).await.unwrap();
        s12.send(Bytes::copy_from_slice(&R_A.compress().to_bytes())).await.unwrap();


        //Recv E_A, R_A
        let RecvE_A = CompressedRistretto(r12.try_next().await.unwrap().unwrap().freeze().to_vec().try_into().unwrap()).decompress().unwrap();
        let RecvR_A = CompressedRistretto(r12.try_next().await.unwrap().unwrap().freeze().to_vec().try_into().unwrap()).decompress().unwrap();



        let c_B = StaticSecret::new(&mut OsRng);
        let z_B = StaticSecret::new(&mut OsRng);
        let r_B = StaticSecret::new(&mut OsRng);
        let R_B = &r_B.0 * & RISTRETTO_BASEPOINT_TABLE;
    
        let cipher = Aes256Gcm::new(GenericArray::from_slice( &Scalar::random(&mut OsRng).to_bytes()));
        let nonce = Nonce::from_slice(b"avow_key_exc"); // 96-bits; unique per message
        let ciphertext = cipher.encrypt(nonce, c_A.to_bytes().iter().chain(&z_A.to_bytes()).chain(&s_A.to_bytes()).cloned().collect::<Vec<_>>().as_ref());
        let c_AB = prove_avow(c_A, c_B, z_A, z_B, R_A, R_B, judge);

        let z_alpha = c_AB.0 * secret_a.0 + r_A.0;
        let z_beta = c_AB.0 * secret_b.0 + r_B.0;
        let a_AB = z_alpha + z_beta;

                                                                     
}
/// return c_{AB}
#[allow(unused_variables,non_snake_case)]

fn prove_avow(c_A:StaticSecret,c_B:StaticSecret,z_A:StaticSecret,z_B:StaticSecret, R_A: RistrettoPoint, R_B: RistrettoPoint, PK_J : PublicKey)-> StaticSecret{
    let c_J = Scalar::from_bits( xor(c_A.to_bytes(),c_B.to_bytes()));
    let z_J = z_A.0 + z_B.0;
    let R_J = z_J * RISTRETTO_BASEPOINT2.decompress().unwrap() - c_J * PK_J.0;
    let R_AB = R_A + R_B;
    let c = hash(&[R_AB.compress().to_bytes(),R_J.compress().to_bytes()].concat());
    StaticSecret( Scalar::from_bits( xor(c[..32].try_into().unwrap(),c_J.to_bytes())))
}
#[allow(unused_variables,non_snake_case)]

pub fn Judge(pk_J: PublicKey, AB: RistrettoPoint, pi: avow_proof ) -> bool{
    true
}