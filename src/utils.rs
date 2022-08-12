use std::fmt::Debug;

use bytes::Bytes;
use sha2::{Sha256,Digest};
use curve25519_dalek::constants::{ED25519_BASEPOINT_TABLE,ED25519_BASEPOINT_COMPRESSED,RISTRETTO_BASEPOINT_TABLE};
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::edwards::{EdwardsPoint,CompressedEdwardsY};
use curve25519_dalek::ristretto::{RistrettoPoint,CompressedRistretto};
use curve25519_dalek::scalar::Scalar;

use std::{path::PathBuf};

use rand_core::CryptoRng;
use rand_core::RngCore;

use zeroize::Zeroize;

pub const EDWARDS_BASE2: CompressedEdwardsY=
   CompressedEdwardsY( [0x31,0x1d,0xdd,0xd2,0x2e,0xe8,0x8d,0xd6,
                        0x60,0x06,0x6d,0xd6,0x67,0x7e,0xec,0xc4,
                        0x44,0x48,0x87,0x73,0x3b,0xb7,0x74,0x49,
                        0x99,0x93,0x3b,0xb0,0x08,0x8b,0xb0,0x0a]);
pub const RISTRETTO_BASEPOINT2: CompressedRistretto = CompressedRistretto(
    [0x7a ,0x1e ,0xba ,0xb2 ,0xbc ,0xea ,0x96 ,0x5c ,
     0x49 ,0x4e ,0x43 ,0x78 ,0xd5 ,0x4e ,0xe0 ,0x8c ,
     0x3e ,0x6d ,0xe6 ,0x9d ,0x49 ,0xaa ,0x73 ,0xe7 ,
     0x85 ,0x04 ,0x13 ,0x1b ,0xcb ,0x33 ,0x50 ,0x6d]);

pub const RISTRETTO_BASEPOINT_RANDOM: CompressedRistretto = CompressedRistretto(
    [0xda,0xc7,0xdf,0xb3,0x0e,0xc0,0x49,0xa2,
     0x66,0x98,0x60,0xea,0x06,0xde,0x15,0x2c,
     0xba,0xf7,0xdf,0x9d,0x4d,0x26,0x06,0xea,
     0xf3,0x00,0x68,0x19,0x1c,0x0a,0x5b,0x16]
);
pub fn hash( msg: &[u8] ) -> [u8;32] {

    let mut hasher = Sha256::new();
    hasher.update(msg);
    let res = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(res.as_slice());
   // println!("hash:{:?}",output);
    output
}

pub fn xor(left:[u8;32],right:[u8;32]) -> [u8;32]{
    left.iter().zip(right).map(|(x,y)| x^y).collect::<Vec<u8>>().try_into().unwrap()
}

#[derive(PartialEq, Eq, Copy, Clone, Debug, Zeroize)]
pub struct PublicKey(pub(crate) RistrettoPoint);

impl From<&[u8]> for PublicKey{

    /// Given a byte array, construct a x25519 `PublicKey`.
  
    fn from(bytes: &[u8]) -> PublicKey{
        PublicKey(CompressedRistretto::from_slice(bytes).decompress().unwrap())

    }
}
impl PublicKey{
    pub fn to_bytes(&self) -> [u8;32]{
        self.0.compress().to_bytes()
    }
}
impl From<Bytes> for PublicKey{
    fn from(bytes:Bytes) -> PublicKey{
        PublicKey::from(bytes.to_vec().as_slice())
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
#[derive(Clone, Zeroize, Debug)]
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
        //PublicKey(&ED25519_BASEPOINT_TABLE * &secret.0)
        PublicKey(&RISTRETTO_BASEPOINT_TABLE * &secret.0)
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
pub struct SharedSecret(pub(crate) RistrettoPoint);

impl SharedSecret {
    /// Convert this shared secret to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }
  
    
}
pub fn get_cert_paths() -> (PathBuf, PathBuf) {
    let dir = directories_next::ProjectDirs::from("am.kwant", "conec", "conec-tests").unwrap();
    let path = dir.data_local_dir();
    let cert_path = path.join("cert.der");
    let key_path = path.join("key.der");
    match std::fs::read(&cert_path) {
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("generating self-signed cert");
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let key = cert.serialize_private_key_der();
            let cert = cert.serialize_der().unwrap();
            std::fs::create_dir_all(&path).unwrap();
            std::fs::write(&cert_path, &cert).unwrap();
            std::fs::write(&key_path, &key).unwrap();
        }
        Ok(_) => (),
        _ => panic!("could not stat file {:?}", cert_path),
    }
    (cert_path, key_path)
}