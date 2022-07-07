

extern crate hkdf;

use curve25519_dalek::constants::{ED25519_BASEPOINT_TABLE};
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::edwards::{EdwardsPoint,CompressedEdwardsY};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{IsIdentity};

use rand_core::CryptoRng;
use rand_core::RngCore;
use rand::rngs::OsRng;

use zeroize::Zeroize;
//use sha2::{Digest, Sha256};
use core::ops::{Add, Sub};





#[derive(PartialEq, Eq, Copy, Clone, Debug, Zeroize)]
pub struct PublicKey(pub(crate) EdwardsPoint);

impl From<&[u8]> for PublicKey{

    /// Given a byte array, construct a x25519 `PublicKey`.
  
    fn from(bytes: &[u8]) -> PublicKey{
        PublicKey(CompressedEdwardsY::from_slice(bytes).decompress().unwrap())

    }
}
impl PublicKey {

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
        PublicKey((&ED25519_BASEPOINT_TABLE * &secret.0))
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
pub struct SharedSecret(pub(crate) MontgomeryPoint);

impl SharedSecret {
    /// Convert this shared secret to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// View this shared secret key as a byte array.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }    #[must_use]
    pub fn was_contributory(&self) -> bool {
        !self.0.is_identity()
    }
}

pub fn sok(){

}

/// a simulator is need for Sigma-OR proof, which is a fundamental conponet in our Sok(Signature of Knowledge) protocol. 
/// let pubc be the A, B, AB, and pk
/// 
/// Following the tradition, we let t be the commit in a sigma protocol, c be the challenge value, and z be the response.
/// convert a DH style protocol into an ECC one: t=zG-acG, therefore the test g^z = t*A^c is zG=zG-acG+cA=zG-ac
pub fn simulator(pubc: PublicKey) -> (StaticSecret,StaticSecret,PublicKey) {
    let z = StaticSecret::new(&mut OsRng);
    let c = StaticSecret::new(&mut OsRng);
    let t = PublicKey(PublicKey::from(&z).0-c.0*pubc.0);//pubc = aG

    println!("scalar:{:?}",PublicKey::from(&z).0-c.0*pubc.0);
    println!("zG={:?}",PublicKey::from(&z));
    println!{"z={:?}\nc={:?}\nt={:?}",z.to_bytes(),c.to_bytes(),t};
    (z,c,t)
}

