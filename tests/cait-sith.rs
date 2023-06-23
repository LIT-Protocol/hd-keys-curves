use k256::{Scalar, elliptic_curve::Field, ProjectivePoint, ecdsa::{Signature, signature::{Signer, Verifier}}};
use vsss_rs::Share;

#[test]
fn apply_hd_key_signing() {
    // Setup
    const ID: &[u8] = b"cait-sith-id";
    const CXT: &[u8] = b"LIT_HD_KEY_ID_K256_XMD:SHA-256_SSWU_RO_NUL_";

    let mut rng = rand::thread_rng();
    let original_secrets = (0..2).map(|_| Scalar::random(&mut rng)).collect::<Vec<_>>();
    let public_keys = original_secrets
        .iter()
        .map(|secret| k256::ProjectivePoint::GENERATOR * secret)
        .collect::<Vec<_>>();

    let secret_shares = original_secrets
        .iter()
        .map(|secret| {
            vsss_rs::shamir::split_secret::<Scalar, u8, Vec<u8>>(2, 3, *secret, &mut rng).unwrap()
        })
        .collect::<Vec<_>>();

    let participants = [
        cait_sith::protocol::Participant::from(1),
        cait_sith::protocol::Participant::from(2),
        cait_sith::protocol::Participant::from(3),
    ];

    // Cait-Sith has KeygenOutputs so convert the secret shares to KeygenOutputs
    let mut participant_shares: Vec<Vec<cait_sith::KeygenOutput<k256::Secp256k1>>> = Vec::with_capacity(participants.len());
    for i in 0..participants.len() {
        let mut participant_share = Vec::with_capacity(participants.len());

        for (j, secret_share) in secret_shares.iter().enumerate() {
            let private_share = secret_share[i].as_field_element::<Scalar>().unwrap();
            participant_share.push(cait_sith::KeygenOutput::<k256::Secp256k1> {
                private_share,
                public_key: public_keys[j].to_affine(),
            });
        }

        participant_shares.push(participant_share);
    }

    // Test key derivation
    let deriver = hd_keys_ecdsa::HdKeyDeriverType::K256.create_deriver::<k256::Secp256k1>(ID, CXT).unwrap();
    let mut participant_derived_keys = Vec::with_capacity(participants.len());
    for i in 0..participants.len() {
        let derived_key = deriver.compute_secret_key_share_cait_sith(&participant_shares[i]);
        assert!(derived_key.is_ok());
        let derived_key = derived_key.unwrap();
        participant_derived_keys.push(derived_key);
    }

    // Test recombine
    let private_shares = participant_derived_keys
        .iter()
        .enumerate()
        .map(|(i, derived_key)| {
            <Vec<u8> as Share>::from_field_element((i + 1) as u8, derived_key.private_share).unwrap()
        })
        .collect::<Vec<_>>();
    let public_shares = participant_derived_keys
        .iter()
        .enumerate()
        .map(|(i, d)| {
            <Vec<u8> as Share>::from_group_element((i + 1) as u8, d.public_key).unwrap()
        })
        .collect::<Vec<_>>();
    let expected_signing_key = deriver.compute_secret_key(&original_secrets);

    let signing_key = vsss_rs::combine_shares::<Scalar, u8, Vec<u8>>(&private_shares).unwrap();
    assert_eq!(signing_key, expected_signing_key);
    let tweak = deriver.to_inner();
    assert_eq!(signing_key, original_secrets[0] + original_secrets[1] * tweak);


    let expected_verification_key = deriver.compute_public_key(&public_keys);
    let actual_verification_key = public_keys[0] + public_keys[1] * tweak;
    assert_eq!(expected_verification_key, actual_verification_key);
    assert_eq!(expected_verification_key, ProjectivePoint::GENERATOR * (original_secrets[0] + original_secrets[1] * tweak));

    let sk = k256::ecdsa::SigningKey::from_bytes(&signing_key.to_bytes()).unwrap();
    let signature: Signature = <k256::ecdsa::SigningKey as Signer<Signature>>::try_sign(&sk, &[0u8; 32]).unwrap();
    let vk = k256::ecdsa::VerifyingKey::from_affine(expected_verification_key.to_affine()).unwrap();
    assert!(vk.verify(&[0u8; 32], &signature).is_ok());

    // Test presign
}