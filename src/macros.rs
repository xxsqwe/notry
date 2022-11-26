// -*- mode: rust; -*-
//
// This file is part of curve25519-dalek.
// Copyright (c) 2016-2021 isis agora lovecruft
// Copyright (c) 2016-2019 Henry de Valence
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>
// - Henry de Valence <hdevalence@hdevalence.ca>

//! Internal macros.

/// Define borrow and non-borrow variants of `Add`.
macro_rules! define_add_variants {
    (LHS = $lhs:ty, RHS = $rhs:ty, Output = $out:ty) => {
        impl<'b> Add<&'b $rhs> for $lhs {
            type Output = $out;
            fn add(self, rhs: &'b $rhs) -> $out {
                &self + rhs
            }
        }

        impl<'a> Add<$rhs> for &'a $lhs {
            type Output = $out;
            fn add(self, rhs: $rhs) -> $out {
                self + &rhs
            }
        }

        impl Add<$rhs> for $lhs {
            type Output = $out;
            fn add(self, rhs: $rhs) -> $out {
                &self + &rhs
            }
        }
    }
}

/// Define borrow and non-borrow variants of `Sub`.
#[macro_export]
macro_rules! define_sub_variants {
    (LHS = $lhs:ty, RHS = $rhs:ty, Output = $out:ty) => {
        impl<'b> Sub<&'b $rhs> for $lhs {
            type Output = $out;
            fn sub(self, rhs: &'b $rhs) -> $out {
                &self - rhs
            }
        }

        impl<'a> Sub<$rhs> for &'a $lhs {
            type Output = $out;
            fn sub(self, rhs: $rhs) -> $out {
                self - &rhs
            }
        }

        impl Sub<$rhs> for $lhs {
            type Output = $out;
            fn sub(self, rhs: $rhs) -> $out {
                &self - &rhs
            }
        }
    }
}


/*

let gamma = StaticSecret::new(&mut OsRng);
let delta=StaticSecret::new(&mut OsRng);
let A= PublicKey::from(&gamma); 
let B=PublicKey::from(&delta.clone());
let AB= A.0+B.0;
let SoK_A=sok(A, B, pk_a, gamma.clone(), sk_a.clone(), Choice::from(0));
let SoK_B=sok(A,B,pk_b,delta.clone(),sk_b.clone(),Choice::from(1));
let K=A.0*delta.0;
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
hf.expand(&[] as &[u8;0],  &mut k_sess).expect("HKDF expansion Failed"); //KDF(A || B || σ A || σ B
let rho = hash(&k_sess.iter().chain(String::from("avow").as_bytes()).cloned().collect::<Vec<u8>>());
let alpha=Scalar::from_bits( rho[..32].try_into().unwrap()) + Scalar::from_bits( gamma.clone().0.to_bytes());
let beta =Scalar::from_bits( rho[..32].try_into().unwrap()) - Scalar::from_bits( delta.clone().0.to_bytes());
alphas.push(alpha);

betas.push(beta);
 
ABs.push(AB.compress());
comm_size_judge += size_of::<CompressedRistretto>();
 */