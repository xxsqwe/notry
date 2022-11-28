#[allow(unused_imports)]
use std::time::Instant;
#[allow(unused_imports)]
use futures::{future, prelude::*};
#[allow(unused_imports)]

use std::{env::args, path::PathBuf};
use std::mem::size_of;
use rand_core::OsRng;
#[allow(unused_imports)]

use curve25519_dalek::{scalar::Scalar,ristretto::{CompressedRistretto,RistrettoPoint},constants::RISTRETTO_BASEPOINT_TABLE};
#[allow(unused_imports)]

use tokio::{runtime, time};
#[allow(unused_imports)]

use notry::utils::{PublicKey,StaticSecret,xor,AES_Dec,AES_Enc,RISTRETTO_BASEPOINT2,RISTRETTO_BASEPOINT_RANDOM,RISTRETTO_JUDGE_PUBK};
use notry::key_exchange::{key_exchange};
#[allow(unused_imports)]
use notry::avow::{Judge,avow_proof, prove_avow,avow};

#[allow(non_snake_case)]
fn main(){
    let mut args: Vec<String> = args().skip(1).collect();
    if args.len()<1{
        println!("./avow <number of scripts>");
        std::process::exit(1);

    }
    let rounds:i32 =  args.pop().unwrap().parse().unwrap();
    let mut rt = runtime::Builder::new().basic_scheduler().enable_all().build().unwrap();
    
    let secret_j = StaticSecret::new(&mut OsRng);
    let pk_J = PublicKey::from(&secret_j);
    let mut ABs = Vec::<CompressedRistretto>::new();
    let mut alphas = Vec::<Scalar>::new();
    let mut betas = Vec::<Scalar>::new();

    let mut comm_size_judge=0;
    rt.block_on(async move{

        let (pk_a,pk_b,_,sk_a,sk_b,k_sess, _, _) 
         = key_exchange().await;

        for _i in 0..rounds{
            
            let (_,_,AB,_,_,_, alpha, beta) 
                = key_exchange().await;

            alphas.push(alpha);

            betas.push(beta);
            let temp = AB.0.compress();
            ABs.push(temp);
            comm_size_judge += size_of::<CompressedRistretto>();
            
            }
        let start = Instant::now();
        let (mut avow_prof,comm_size) = avow(pk_a,pk_b, pk_J,sk_a,sk_b,alphas,betas,true,k_sess.to_bytes()).await;
        let time_avow_gen= start.elapsed();
        
        avow_prof.AB = ABs;

        assert_eq!(true,Judge(pk_J, avow_prof));
        let time_verify = start.elapsed()-time_avow_gen;

        println!("[+] avow {} scripts",rounds);
        println!("[+] overall communication of  one party:{}",comm_size);
        println!("[+] overall computation of  one party:{:?}ms",time_avow_gen.as_millis());
        //println!("comm judge:{}",comm_size_judge);
        println!("[+] communication of the Judge:{:?}", size_of::<CompressedRistretto>()+comm_size_judge+32*4);
        println!("[+] computation overhead of the Judge:{:?}",time_verify);
        }
);
    //assert_eq!(avow_prof.c_AB * alpha + avow_prof.r_A + avow_prof.c_AB * beta+avow_prof.r_B, avow_prof.z_AB);

}
