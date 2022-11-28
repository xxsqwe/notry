
use libsignal_protocol::*;
use std::time::Instant;
use rand::rngs::OsRng;
use std::time::Duration;
use std::mem::size_of;
fn main(){
    let rounds =1000;
    let mut time_keygen=Duration::new(0,0);
    let mut time_com=Duration::new(0,0);
    
    for _i in 0..rounds{
    let bob_ephemeral_public =
        hex::decode("052cb49776b8770205745a3a6e24f579cdb4ba7a89041005928ebbadc9c05ad458")
            .expect("valid hex");

    let bob_identity_public =
        hex::decode("05f1f43874f6966956c2dd473f8fa15adeb71d1cb991b2341692324cefb1c5e626")
            .expect("valid hex");

    let alice_base_public =
        hex::decode("05472d1fb1a9862c3af6beaca8920277e2b26f4a79213ec7c906aeb35e03cf8950")
            .expect("valid hex");

    let alice_base_private =
        hex::decode("11ae7c64d1e61cd596b76a0db5012673391cae66edbfcf073b4da80516a47449")
            .expect("valid hex");

    let bob_signed_prekey_public =
        hex::decode("05ac248a8f263be6863576eb0362e28c828f0107a3379d34bab1586bf8c770cd67")
            .expect("valid hex");

    let alice_identity_public =
        hex::decode("05b4a8455660ada65b401007f615e654041746432e3339c6875149bceefcb42b4a")
            .expect("valid hex");

    let alice_identity_private =
        hex::decode("9040f0d4e09cf38f6dc7c13779c908c015a1da4fa78737a080eb0a6f4f5f8f58")
            .expect("valid hex");

    // This differs from the Java test and needs investigation
    let expected_receiver_chain =
    //ab9be50e5cb22a925446ab90ee5670545f4fd32902459ec274b6ad0ae5d6031a
        "ab9be50e5cb22a925446ab90ee5670545f4fd32902459ec274b6ad0ae5d6031a";
    
    
        let start = Instant::now();
    let _idpair = IdentityKeyPair::generate(&mut OsRng);
    time_keygen+=start.elapsed();
    let alice_identity_key_public = IdentityKey::decode(&alice_identity_public).unwrap();

    let bob_ephemeral_public = PublicKey::deserialize(&bob_ephemeral_public).unwrap();

    let alice_identity_key_private = PrivateKey::deserialize(&alice_identity_private).unwrap();

    let bob_signed_prekey_public = PublicKey::deserialize(&bob_signed_prekey_public).unwrap();
    
    //println!("size of prekeybundle:{}",size_of::<PreKeyBundle>());
    //println!("size of PublicKey for communication to get a message key:{}",size_of::<PublicKey>());
    let alice_identity_key_pair =
        IdentityKeyPair::new(alice_identity_key_public, alice_identity_key_private);

    let alice_base_key = KeyPair::from_public_and_private(&alice_base_public, &alice_base_private).unwrap();

    let alice_parameters = AliceSignalProtocolParameters::new(
        alice_identity_key_pair,
        alice_base_key,
        IdentityKey::decode(&bob_identity_public).unwrap(),
        bob_signed_prekey_public,
        None, // one-time prekey
        bob_ephemeral_public,
    );

    let mut csprng = rand::rngs::OsRng;
    let alice_record = initialize_alice_session_record(&alice_parameters, &mut csprng).unwrap();
    let period = start.elapsed();
    time_com+=period;
    assert_eq!(
        hex::encode(alice_record.local_identity_key_bytes().unwrap()),
        hex::encode(alice_identity_public),
    );
    assert_eq!(
        hex::encode(
            alice_record
                .remote_identity_key_bytes().unwrap()
                .expect("value exists")
        ),
        hex::encode(bob_identity_public)
    );

    assert_eq!(
        hex::encode(
            alice_record
                .get_receiver_chain_key_bytes(&bob_ephemeral_public).unwrap()
                .expect("value exists")
        ),
        expected_receiver_chain
    );
}
    println!("tests in {} rounds",rounds);
    println!("{:?} per key generation",time_keygen/rounds);
    println!("{:?} per x3dh",time_com/rounds);
}