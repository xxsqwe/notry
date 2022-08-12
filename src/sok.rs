
#[allow(unused_imports)]
use aes_gcm::aead::generic_array::GenericArray;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::{RISTRETTO_BASEPOINT_COMPRESSED,RISTRETTO_BASEPOINT_TABLE};

use curve25519_dalek::ristretto::{RistrettoPoint,CompressedRistretto};
#[allow(unused_imports)]
use futures::channel::oneshot::channel;
#[allow(unused_imports)]
use sha2::{Sha256,Sha512};
#[allow(unused_imports)]
use hkdf::Hkdf;
//use core::ops::{Add, Sub};
#[allow(unused_imports)]
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce // Or `Aes128Gcm`
};
#[allow(unused_imports)]
use crate::utils::{hash,PublicKey,StaticSecret,xor,RISTRETTO_BASEPOINT2,get_cert_paths};

use subtle::Choice;
use rand::rngs::OsRng;

use zeroize::Zeroize;

#[allow(unused_imports)]
use crate::network::{Start_Client,Start_Judge,Send,Recv, Comm_Channel, };
#[allow(unused_imports)]
use std::{path::PathBuf};
#[allow(unused_imports)]
use futures::{future, prelude::*, stream};
#[allow(unused_imports)]
use tokio::{runtime, time};
#[allow(unused_imports)]
use bytes::{Bytes};

#[derive(Zeroize, Debug, Clone)]
pub struct SigmaOr{
    t_0: PublicKey,
    c_0: StaticSecret,
    z_0: StaticSecret,
    t_1: PublicKey,
    c_1: StaticSecret,
    z_1: StaticSecret,
    left: PublicKey,
    right: PublicKey,
}
impl SigmaOr{
    pub fn verify(&self,diff_base:bool) -> bool{
        let first = 
            if diff_base{
                &self.z_0.0*&RISTRETTO_BASEPOINT2.decompress().unwrap() == self.t_0.0+self.left.0*self.c_0.0
        }
            else{
                &self.z_0.0*&RISTRETTO_BASEPOINT_TABLE == self.t_0.0+self.left.0*self.c_0.0
            
        };
        let second = 
            if diff_base{
                &self.z_1.0*&RISTRETTO_BASEPOINT2.decompress().unwrap() == self.t_1.0+self.right.0*self.c_1.0
            }
            else{
                &self.z_1.0*&RISTRETTO_BASEPOINT_TABLE == self.t_1.0+self.right.0*self.c_1.0
            };
            println!("left={:?}, right = {:?}",first,second);
        first && second
    }
    pub fn new()-> Self{
        SigmaOr{
            t_0: PublicKey(RistrettoPoint::default()),
            c_0: StaticSecret(Scalar::zero()),
            z_0: StaticSecret(Scalar::zero()),
            t_1: PublicKey(RistrettoPoint::default()),
            c_1: StaticSecret(Scalar::zero()),
            z_1: StaticSecret(Scalar::zero()),
            left: PublicKey(RistrettoPoint::default()),
            right: PublicKey(RistrettoPoint::default()),
        }
    }
    pub fn to_bytes(&self)-> Vec<u8>{
        (&self.t_0.0.compress().to_bytes()).iter()
        .chain(&self.c_0.0.to_bytes())
        .chain(&self.z_0.0.to_bytes())
        .chain(&self.t_1.0.compress().to_bytes())
        .chain(&self.c_1.0.to_bytes())
        .chain(&self.z_1.0.to_bytes())
        .chain(&self.left.0.compress().to_bytes())
        .chain(&self.right.0.compress().to_bytes())
        .cloned()
        .collect::<Vec<u8>>()
    }
}
impl From<&[u8;256]> for SigmaOr {
    fn from(bytes: &[u8;256]) -> Self {
        SigmaOr { 
            t_0:PublicKey( CompressedRistretto(bytes[0..32].try_into().unwrap()).decompress().unwrap()), 
            c_0:StaticSecret( Scalar::from_bits(bytes[32..64].try_into().unwrap())), 
            z_0:StaticSecret( Scalar::from_bits(bytes[64..96].try_into().unwrap())), 
            t_1:PublicKey( CompressedRistretto(bytes[96..128].try_into().unwrap()).decompress().unwrap()), 
            c_1:StaticSecret( Scalar::from_bits(bytes[128..160].try_into().unwrap())), 
            z_1:StaticSecret( Scalar::from_bits(bytes[160..192].try_into().unwrap())), 
            left:PublicKey( CompressedRistretto(bytes[192..224].try_into().unwrap()).decompress().unwrap()), 
            right:PublicKey( CompressedRistretto(bytes[224..256].try_into().unwrap()).decompress().unwrap()) }
    }
    
}
/// SoK, which take two group points as a input,
/// produces a compund proof based on schnorr signature.
/// Let Choice 0 for proving left part, where 1 as the right part, of the formula
/// dlog{_h}A or dlog{_h}B proof:
/// (j\in {0,1} indicating which statement to prove, x\in {a,b} is the witness) for one of y_j \in {A,B}. d = 1-j
/// First P runs the simlator with Y_d to oatains (t_d,c_d,z_d). P runs the P_j(x,y_j) to get t_j, sends (t_0,t_1)
/// After that P recevies the random challenge c from the V and sets c_j= c_d ⊕ c 
/// P runs P_j(x, y_j) to get reponse z_j, sends (t_0,z_0,z_1) to V
/// V computes c_1 = c + c_0, then checks that (c_0,t_0,z_0) and (c_1,t_1,z_1) are both valid transcripts for statement y_0 and y_1
#[allow(non_snake_case)]
#[allow(dead_code)]
#[allow(unused_variables)]
pub fn sok(A: PublicKey, B:PublicKey, pk: PublicKey,  secret: StaticSecret, sk: StaticSecret,  j:Choice) -> Vec<SigmaOr> { 
    let Result: Vec<SigmaOr> = Vec::new();
    
    let first_part=
    if j.unwrap_u8()==0u8 { //prove dlog_{h}A, send (t_0,t_1) and (c_0,z_0,z_1) to Verifier. j=0,d=1
        let (z_d,c_d,t_d)=simulator(B, false);
        let t_j=StaticSecret::new(&mut OsRng);
        let u_j = PublicKey::from(&t_j);
        let message: String= String::from("dlog_{h}A or dlog_{h}B");
        let FS = Scalar::from_bits( hash(&RISTRETTO_BASEPOINT_COMPRESSED.to_bytes().iter()
                                            .chain(&A.to_bytes())
                                            .chain(&u_j.to_bytes())
                                            .chain(message.as_bytes())
                                            .cloned()               //H(g,pubkey,u,m)
                                            .collect::<Vec<u8>>())[..32].try_into().unwrap());// Array Catenation
        let c_j: Scalar = Scalar::from_bits(FS.to_bytes().iter().zip(c_d.to_bytes()).map(|(x,y)| x^y).collect::<Vec<u8>>().as_slice().try_into().unwrap()); // xor corresponding bytes in two Vectors
        let z_j = t_j.0 + c_j * secret.0; // trick. from Vec to array
    
        (u_j,t_d,StaticSecret(c_j),c_d,StaticSecret(z_j),z_d)
        
        

    }
       
    else{   //where j=1, d=0
        let (z_d,c_d,t_d)=simulator(A, false);
        let t_j = StaticSecret::new(&mut OsRng);
        let u_j = PublicKey::from(&t_j);
        let message: String= String::from("dlog_{h}A or dlog_{h}B");
        let FS = Scalar::from_bits(hash(&RISTRETTO_BASEPOINT_COMPRESSED.to_bytes().iter()
                                            .chain(&B.to_bytes())
                                            .chain(&u_j.to_bytes())
                                            .chain(message.as_bytes())
                                            .cloned()               //H(g,pubkey,u,m)
                                            .collect::<Vec<u8>>())[..32].try_into().unwrap());// Array Catenation
        let c_j: Scalar = Scalar::from_bits(FS.to_bytes().iter().zip(c_d.to_bytes()).map(|(x,y)| x^y).collect::<Vec<u8>>().as_slice().try_into().unwrap()); // xor corresponding bytes in two Vectors, trick. from Vec to array
        let z_j = t_j.0+c_j*secret.0; //
    
        (t_d,u_j,c_d,StaticSecret(c_j),z_d,StaticSecret(z_j))
    };
    let mut result=Vec::new();
    {
    let simga_proof = SigmaOr {
            t_0:first_part.0,
            t_1:first_part.1,
            c_0:first_part.2,
            c_1:first_part.3,
            z_0:first_part.4,
            z_1:first_part.5,
            left:A,
            right:B,
        }; 
    
    result.push(simga_proof);
    }
    let second_part=//by default the second part of the proof is to prove knowing the secret key of the corresponding public key pk.
        {
            let (z_d,c_d,t_d)=simulator(PublicKey(A.0+B.0), true);
            let t_j = StaticSecret::new(&mut OsRng);
            let u_j = PublicKey( &t_j.0 * &RISTRETTO_BASEPOINT2.decompress().unwrap());
            let message: String= String::from("dlog_{g}pk or dlog_{g}AB");

            let FS = Scalar::from_bits(hash(&RISTRETTO_BASEPOINT2.to_bytes().iter()
                                            .chain(&pk.to_bytes())
                                            .chain(&u_j.to_bytes())
                                            .chain(message.as_bytes())
                                            .cloned()               //H(g,pubkey,u,m)
                                            .collect::<Vec<u8>>())[..32].try_into().unwrap());
            let c_j: Scalar = Scalar::from_bits(FS.to_bytes().iter().zip(c_d.to_bytes()).map(|(x,y)| x^y).collect::<Vec<u8>>().as_slice().try_into().unwrap()); // xor corresponding bytes in two Vectors
            //println!("t={:?}\n c={:?}\n x = {:?}",t_j,c_j,sk);
            
            let z_j = t_j.0 + c_j * sk.0;
            
                //println!("left:{:?}",&z_j * &RISTRETTO_BASEPOINT2.decompress().unwrap());
                //println!("right:{:?}",u_j.0 + c_j * pk.0);
            
            (u_j,t_d,StaticSecret(c_j),c_d,StaticSecret(z_j),z_d)


        };
        
    {
        let simga_proof = SigmaOr {
            t_0:second_part.0,
            t_1:second_part.1,
            c_0:second_part.2,
            c_1:second_part.3,
            z_0:second_part.4,
            z_1:second_part.5,
            left:pk,
            right:PublicKey(A.0+B.0),
        }; 
        result.push(simga_proof);
    }
    
    result
    
}
#[allow(non_snake_case)]
pub fn sok_verify(mut proof: Vec<SigmaOr>, j: Choice) -> bool{
    let message1: String= String::from("dlog_{h}A or dlog_{h}B");
    let message2: String= String::from("dlog_{g}pk or dlog_{g}AB");
    //println!("Sigma Bytes Array:{:?}",proof[0].to_bytes());
    let FS = 
        if j.unwrap_u8()==0{
           Scalar::from_bits( hash(&RISTRETTO_BASEPOINT_COMPRESSED.to_bytes().iter()
                                            .chain(&proof[0].left.to_bytes())
                                            .chain(&proof[0].t_0.to_bytes())
                                            .chain(message1.as_bytes())
                                            .cloned()               //H(g,pubkey,u,m)
                                            .collect::<Vec<u8>>())[..32].try_into().unwrap())
        }
        else{
            Scalar::from_bits(hash(&RISTRETTO_BASEPOINT_COMPRESSED.to_bytes().iter()
                                            .chain(&proof[0].right.to_bytes())
                                            .chain(&proof[0].t_1.to_bytes())
                                            .chain(message1.as_bytes())
                                            .cloned()               //H(g,pubkey,u,m)
                                            .collect::<Vec<u8>>())[..32].try_into().unwrap())
        };
    proof[0].c_1 = StaticSecret(Scalar::from_bits( xor(FS.to_bytes(),proof[0].c_0.to_bytes())));
    let FS2 = Scalar::from_bits(hash(&RISTRETTO_BASEPOINT2.to_bytes().iter()
                                .chain(&proof[1].left.to_bytes())
                                .chain(&proof[1].t_0.to_bytes())
                                .chain(message2.as_bytes())
                                .cloned()               //H(g,pubkey,u,m)
                                .collect::<Vec<u8>>())[..32].try_into().unwrap());
    proof[1].c_1 = StaticSecret(Scalar::from_bits( xor(FS2.to_bytes(), proof[1].c_0.to_bytes())));

    if proof[0].verify(false) {
        if proof[1].verify(true){
         return   true;
    }
        else{
         return   false;
        }
    }
    else{
        println!("first part sigma:{:?}",proof[0]);
        return false;
    }
}


/// a simulator is need for Sigma-OR proof, which is a fundamental conponet in our Sok(Signature of Knowledge) protocol. 
/// let pubc be the A, B, AB, and pk
/// 
/// Following the tradition, we let t be the commit in a sigma protocol, c be the challenge value, and z be the response.
/// convert a DH style protocol into an ECC one: t=zG-acG, therefore the test g^z = t*A^c is zG=zG-acG+cA=zG-ac
/// Original base point of Edwards Curve is y=-5/4, According to another basepoint base2:x=16 
/// in the Montgomery form, we set base2 of Edwards according to the transform. (Transformations)Birational maps between the two are:
/// (u, v) = ((1+y)/(1-y), sqrt(-486664)*u/x)
/// (x, y) = (sqrt(-486664)*u/v, (u-1)/(u+1))
/// return z c t as the transcript of a schnorr proof
fn simulator(pubc: PublicKey,diff_base:bool) -> (StaticSecret,StaticSecret,PublicKey) {
    let z = StaticSecret::new(&mut OsRng);
    let c = StaticSecret::new(&mut OsRng);
    let t= 
        if diff_base{
            PublicKey(&z.0*&(RISTRETTO_BASEPOINT2.decompress().unwrap())-c.0*pubc.0)
        }
        
        else{
            PublicKey(PublicKey::from(&z).0-c.0*pubc.0)//pubc = aG
        };
    //println!("zG={:?}",t);
    //println!{"z={:?}\nc={:?}\nt={:?}",z.to_bytes(),c.to_bytes(),t};
    (z,c,t)
}

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
#[test]
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
        
        /*s12.send(to_send.clone()).await.unwrap();
        
        let to_send = Bytes::copy_from_slice(&signature_of_knowledge[1].to_bytes());
        println!("clinet 1 to client 2: {:?}",to_send);
        s12.send(to_send.clone()).await.unwrap();

        let rec = r12.try_next().await?.unwrap().freeze();
        let rec1 =r12.try_next().await?.unwrap().freeze();
        let sok_recv = vec![SigmaOr::from(&rec.to_vec().try_into().unwrap()),SigmaOr::from(&rec1.to_vec().try_into().unwrap())];*/
        println!("clinet 2 from client 1: {:?}",sok_recv);

        assert_eq!(sok_recv.to_vec(),signature_of_knowledge[0].to_bytes());
        
        //assert_eq!(true,sok_verify(sok_recv, Choice::from(0)));
        Ok(()) as Result<(), std::io::Error>
    })
    .unwrap();
}



