use hkdf::Hkdf;
use sha2::Sha256;

use crate::utils::{PublicKey,SharedSecret,StaticSecret,xor};
use crate::sok::{sok,sok_verify,SigmaOr};

use rand::rngs::OsRng;
use subtle::Choice;
/// Role 0 for Alice, 1 for Bob
/// 
pub fn key_exchange(Role:bool, Sk:StaticSecret, MyPk:PublicKey, OtherPK: PublicKey){
    
    if Role{
        
    }
    else{
        let Gamma = StaticSecret::new(&mut OsRng);
        let A = PublicKey::from(&Gamma);
        Send(A);
        let SoK_b: Vec<SigmaOr> = Recv();
        let B: PublicKey = Recv();
        if sok_verify(SoK_b,Choice::from(0)) {
            let SoK_a = sok(A,B,MyPk,Gamma,Sk,Choice::from(0));
            Send(SoK_a);
            let K = Gamma.0 * B.0;

            let KeyMatereial = A.to_bytes().iter()
                                                                .chain(&B.to_bytes())
                                                                .chain(&SoK_a[0].0.to_bytes())
                                                                .chain(&SoK_a[0].1.to_bytes())
                                                                .chain(&SoK_a[0].2.to_bytes())
                                                                .chain(&SoK_a[0].3.to_bytes())
                                                                .chain(&SoK_a[0].4.to_bytes())
                                                                .chain(&K.compress().to_bytes());
            let mut k_sess = [0u8;32];
            let hf = Hkdf::<Sha256>::new(None,&KeyMatereial);
            hf.expand(&[] as &[u8;0], &mut k_sess); //KDF(A || B || σ A || σ B || K)
            let rho = hash(&okm.iter().chain(String::from("avow").as_bytes()).cloned().collect::<Vec<u8>>());//H(k_sess|| “avow”)
            let alpha = xor(rho,Gamma.0.to_bytes());
            
        }
        else{
            panic!("SoK verified failed");
        }
    }
}
fn Send(Component: PublicKey){

}
fn Recv() -> Box<Vec<T>>{

}