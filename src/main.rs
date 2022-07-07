pub mod sok;
use crate::sok::{simulator,StaticSecret,PublicKey};

use rand::rngs::OsRng;

#[macro_use]
pub mod macros;

#[test]
fn test_simulator() {
    let alice_secret = StaticSecret::new(&mut OsRng);
    let alice_public = PublicKey::from(&alice_secret);
    println!("Alice Public={:?}", alice_public);
    let s=simulator(alice_public);
    assert_eq!(PublicKey::from(&s.0),PublicKey(s.2.0+alice_public.0*s.1.0));
}
fn main(){

}