use k256::elliptic_curve::Field;
use k256::*;
use std::{
    io::{stdout, Write},
    time::SystemTime,
};
use hd_keys_curves::HdKeyDeriver;

fn main() {
    const START: usize = 1000;
    const STOP: usize = 100000;
    const STEP: usize = 1000;
    let deriver = HdKeyDeriver::<Secp256k1>::new(
        b"cait-sith-id",
        b"LIT_HD_KEY_ID_K256_XMD:SHA-256_SSWU_RO_NUL_",
    )
    .unwrap();
    print!("Creating root keys...");
    stdout().flush().unwrap();
    let root_secret_keys = (0..STOP)
        .map(|_| Scalar::random(&mut rand::thread_rng()))
        .collect::<Vec<_>>();
    let root_public_keys = root_secret_keys
        .iter()
        .map(|s| ProjectivePoint::GENERATOR * s)
        .collect::<Vec<_>>();
    println!("done");

    for i in (START..=STOP).step_by(STEP) {
        print!("Derive secret key with root key size {} - ", i);
        stdout().flush().unwrap();
        let before = SystemTime::now();
        let secret = deriver.compute_secret_key(&root_secret_keys[..i]);
        let after = SystemTime::now();
        println!("{:?}", after.duration_since(before));

        print!("Derive public key with root key size {} - ", i);
        stdout().flush().unwrap();
        let before = SystemTime::now();
        let public = deriver.compute_public_key(&root_public_keys[..i]);
        let after = SystemTime::now();
        println!("{:?}", after.duration_since(before));

        assert_eq!(public, ProjectivePoint::GENERATOR * secret);
    }
}
