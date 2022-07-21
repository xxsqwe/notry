

extern crate hkdf;
extern crate sha2;
use sha2::{Sha256,Digest};
use hex_literal::Hex;
use curve25519_dalek::constants::{ED25519_BASEPOINT_TABLE};
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::edwards::{EdwardsPoint,CompressedEdwardsY};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{IsIdentity};

use rand_core::CryptoRng;
use rand_core::RngCore;
use rand::rngs::OsRng;

use subtle::Choice;

use zeroize::Zeroize;
//use sha2::{Digest, Sha256};
//use core::ops::{Add, Sub};

pub const EDWARDS_BASE2: CompressedEdwardsY=
   CompressedEdwardsY( [0x31,0x1d,0xdd,0xd2,0x2e,0xe8,0x8d,0xd6,
                        0x60,0x06,0x6d,0xd6,0x67,0x7e,0xec,0xc4,
                        0x44,0x48,0x87,0x73,0x3b,0xb7,0x74,0x49,
                        0x99,0x93,0x3b,0xb0,0x08,0x8b,0xb0,0x0a]);



#[derive(PartialEq, Eq, Copy, Clone, Debug, Zeroize)]
pub struct PublicKey(pub(crate) EdwardsPoint);

impl From<&[u8]> for PublicKey{

    /// Given a byte array, construct a x25519 `PublicKey`.
  
    fn from(bytes: &[u8]) -> PublicKey{
        PublicKey(CompressedEdwardsY::from_slice(bytes).decompress().unwrap())

    }
}


/// A Diffie-Hellman secret key that can be used to compute multiple [`SharedSecret`]s.
///
/// This type is identical to the [`EphemeralSecret`] type, except that the
/// [`StaticSecret::diffie_hellman`] method does not consume the secret key, and the type provides
/// serialization methods to save and load key material.  This means that the secret may be used
/// multiple times (but does not *have to be*).
///
/// # Warning
///
/// If you're uncertain about whether you should use this, then you likely
/// should not be using this.  Our strongly recommended advice is to use
/// [`EphemeralSecret`] at all times, as that type enforces at compile-time that
/// secret keys are never reused, which can have very serious security
/// implications for many protocols.
#[cfg_attr(feature = "serde", serde(crate = "our_serde"))]
#[cfg_attr(
    feature = "serde",
    derive(our_serde::Serialize, our_serde::Deserialize)
)]
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct StaticSecret(
    #[cfg_attr(feature = "serde", serde(with = "AllowUnreducedScalarBytes"))] pub(crate) Scalar,
);

impl StaticSecret {
    /// Perform a Diffie-Hellman key agreement between `self` and
    /// `their_public` key to produce a `SharedSecret`.
    

    /// Generate an x25519 key.
    pub fn new<T: RngCore + CryptoRng>(mut csprng: T) -> Self {
        let mut bytes = [0u8; 32];

        csprng.fill_bytes(&mut bytes);

        StaticSecret(clamp_scalar(bytes))
    }

    /// Extract this key's bytes for serialization.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl From<[u8; 32]> for StaticSecret {
    /// Load a secret key from a byte array.
    fn from(bytes: [u8; 32]) -> StaticSecret {
        StaticSecret(clamp_scalar(bytes))
    }
}

impl<'a> From<&'a StaticSecret> for PublicKey {
    /// Given an x25519 [`StaticSecret`] key, compute its corresponding [`PublicKey`].
    fn from(secret: &'a StaticSecret) -> PublicKey {
        PublicKey(&ED25519_BASEPOINT_TABLE * &secret.0)
    }
}

/// "Decode" a scalar from a 32-byte array.
///
/// By "decode" here, what is really meant is applying key clamping by twiddling
/// some bits.
///
/// # Returns
///
/// A `Scalar`.
fn clamp_scalar(mut scalar: [u8; 32]) -> Scalar {
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;

    Scalar::from_bits(scalar)
}

/// The result of a Diffie-Hellman key exchange.
///
/// Each party computes this using their [`EphemeralSecret`] or [`StaticSecret`] and their
/// counterparty's [`PublicKey`].
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SharedSecret(pub(crate) EdwardsPoint);

impl SharedSecret {
    /// Convert this shared secret to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }
  
    
}
/// SoK, which take two group points as a input,
/// produces a compund proof based on schnorr signature.
/// Let Choice 0 for proving left part, where 1 as the right part, of the formula
#[allow(non_snake_case)]
#[allow(dead_code)]
#[allow(unused_variables)]
pub fn sok(A: PublicKey, B:PublicKey, pk: PublicKey, AB:PublicKey, first_secret: StaticSecret, second_secret: StaticSecret, b:Vec<Choice> ){
    /// dlog{_h}A or dlog{_h}B proof:
    /// (j\in {0,1} indicating which statement to prove, x\in {a,b} is the witness) for one of y_j \in {A,B}. d = 1-j
    ///  First P runs the simlator with Y_d to oatains (t_d,c_d,z_d). P runs the P_j(x,y_j) to get t_j, sends (t_0,t_1)
    /// After that P recevies the random challenge c from the V and sets c_j= c_d ⊕ c 
    /// P runs P_j(x, y_j) to get reponse z_j, sends (t_0,z_0,z_1) to V
    /// V computes c_1 = c + c_0, then checks that (c_0,t_0,z_0) and (c_1,t_1,z_1) are both valid transcripts for statement y_0 and y_1
    if b[0].unwrap_u8()==0u8 { //prove dlog_{h}A
        let (c_d,z_d,t_d)=simulator(B, false);
        let t_j= StaticSecret::new(&mut OsRng);
        
        let mut hasher = Sha256::new();
        
        hasher.update(A.0.compress().to_bytes());
        let result = hasher.finalize();
        
        

    }
    else{

    }
    let left = 1;

}
fn hash( words:Scalar){
    
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
pub fn simulator(pubc: PublicKey,diff_base:bool) -> (StaticSecret,StaticSecret,PublicKey) {
    let z = StaticSecret::new(&mut OsRng);
    let c = StaticSecret::new(&mut OsRng);
    let t= 
        if diff_base{
            PublicKey(&z.0*&(EDWARDS_BASE2.decompress().unwrap())-c.0*pubc.0)
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
    let alice_secret = StaticSecret::new(&mut OsRng);
    let alice_public = PublicKey::from(&alice_secret);
    println!("Alice Public={:?}", alice_public);
    let s=simulator(alice_public,true);
    assert_eq!(&s.0.0*&(EDWARDS_BASE2.decompress().unwrap()),s.2.0+alice_public.0*s.1.0);
}


