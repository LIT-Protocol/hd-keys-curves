mod deriver;
mod error;

pub use error::*;

#[cfg(feature = "cait-sith")]
use cait_sith::{CSCurve, KeygenOutput};
use std::fmt::{self, Debug, Display, Formatter, LowerHex, UpperHex};

use crate::deriver::*;
use elliptic_curve::hash2curve::{ExpandMsg, ExpandMsgXmd, ExpandMsgXof, Expander};
use elliptic_curve::{
    group::cofactor::CofactorGroup,
    hash2curve::{FromOkm, GroupDigest},
    CurveArithmetic, Field, Group, PrimeField, ScalarPrimitive,
};
use serde::{Deserialize, Serialize};

pub use crate::deriver::compute_rerandomizer;
#[cfg(feature = "cait-sith")]
pub use crate::deriver::update_cait_sith_presig;

pub trait HDDeriver: PrimeField {
    fn create(msg: &[u8], dst: &[u8]) -> Self;

    fn hd_derive_secret_key(&self, secret_keys: &[Self]) -> Self {
        let mut result = Self::ZERO;
        for v in secret_keys.iter().rev() {
            result *= *self;
            result += v;
        }
        result
    }

    fn hd_derive_public_key<D: HDDerivable<Scalar = Self>>(&self, public_keys: &[D]) -> D {
        if public_keys.is_empty() {
            return D::identity();
        }
        if public_keys.len() == 1 {
            return public_keys[0] * *self;
        }
        let powers = get_poly_powers(*self, public_keys.len());
        D::sum_of_products(public_keys, powers.as_slice())
    }
}

pub trait HDDerivable: Group {
    fn sum_of_products(points: &[Self], scalars: &[Self::Scalar]) -> Self;
}

impl HDDeriver for k256::Scalar {
    fn create(msg: &[u8], dst: &[u8]) -> Self {
        let msg = [msg];
        let dst = [dst];
        k256::Secp256k1::hash_to_scalar::<ExpandMsgXmd<sha2::Sha256>>(&msg, &dst)
            .expect("hash_to_scalar failed")
    }
}

impl HDDerivable for k256::ProjectivePoint {
    fn sum_of_products(points: &[Self], scalars: &[Self::Scalar]) -> Self {
        sum_of_products_pippenger::<k256::Secp256k1>(points, scalars)
    }
}

impl HDDeriver for p256::Scalar {
    fn create(msg: &[u8], dst: &[u8]) -> Self {
        let msg = [msg];
        let dst = [dst];
        p256::NistP256::hash_to_scalar::<ExpandMsgXmd<sha2::Sha256>>(&msg, &dst)
            .expect("hash_to_scalar failed")
    }
}

impl HDDerivable for p256::ProjectivePoint {
    fn sum_of_products(points: &[Self], scalars: &[Self::Scalar]) -> Self {
        sum_of_products_pippenger::<p256::NistP256>(points, scalars)
    }
}

impl HDDeriver for p384::Scalar {
    fn create(msg: &[u8], dst: &[u8]) -> Self {
        let msg = [msg];
        let dst = [dst];
        p384::NistP384::hash_to_scalar::<ExpandMsgXmd<sha2::Sha384>>(&msg, &dst)
            .expect("hash_to_scalar failed")
    }
}

impl HDDerivable for p384::ProjectivePoint {
    fn sum_of_products(points: &[Self], scalars: &[Self::Scalar]) -> Self {
        points
            .iter()
            .zip(scalars.iter())
            .fold(p384::ProjectivePoint::IDENTITY, |acc, (pt, sc)| {
                acc + *pt * *sc
            })
    }
}

impl HDDeriver for ed448_goldilocks_plus::Scalar {
    fn create(msg: &[u8], dst: &[u8]) -> Self {
        ed448_goldilocks_plus::Scalar::hash::<ExpandMsgXof<sha3::Shake256>>(msg, dst)
    }
}

impl HDDerivable for ed448_goldilocks_plus::EdwardsPoint {
    fn sum_of_products(points: &[Self], scalars: &[Self::Scalar]) -> Self {
        points.iter().zip(scalars.iter()).fold(
            ed448_goldilocks_plus::EdwardsPoint::default(),
            |acc, (pt, sc)| acc + *pt * *sc,
        )
    }
}

impl HDDeriver for vsss_rs::curve25519::WrappedScalar {
    fn create(msg: &[u8], dst: &[u8]) -> Self {
        let msg = [msg];
        let dst = [dst];
        let mut expander = ExpandMsgXmd::<sha2::Sha512>::expand_message(&msg, &dst, 64)
            .expect("expand_message failed");
        let mut okm = [0u8; 64];
        expander.fill_bytes(&mut okm);
        vsss_rs::curve25519::WrappedScalar(
            vsss_rs::curve25519_dalek::Scalar::from_bytes_mod_order_wide(&okm),
        )
    }
}

impl HDDerivable for vsss_rs::curve25519::WrappedEdwards {
    fn sum_of_products(points: &[Self], scalars: &[Self::Scalar]) -> Self {
        points.iter().zip(scalars.iter()).fold(
            vsss_rs::curve25519::WrappedEdwards::default(),
            |acc, (pt, sc)| acc + *pt * *sc,
        )
    }
}

impl HDDerivable for vsss_rs::curve25519::WrappedRistretto {
    fn sum_of_products(points: &[Self], scalars: &[Self::Scalar]) -> Self {
        points.iter().zip(scalars.iter()).fold(
            vsss_rs::curve25519::WrappedRistretto::default(),
            |acc, (pt, sc)| acc + *pt * *sc,
        )
    }
}

impl HDDeriver for jubjub::Scalar {
    fn create(msg: &[u8], dst: &[u8]) -> Self {
        jubjub::Scalar::hash::<ExpandMsgXmd<blake2::Blake2b512>>(msg, dst)
    }
}

impl HDDerivable for jubjub::ExtendedPoint {
    fn sum_of_products(points: &[Self], scalars: &[Self::Scalar]) -> Self {
        points
            .iter()
            .zip(scalars.iter())
            .fold(jubjub::ExtendedPoint::default(), |acc, (pt, sc)| {
                acc + *pt * *sc
            })
    }
}

impl HDDerivable for jubjub::SubgroupPoint {
    fn sum_of_products(points: &[Self], scalars: &[Self::Scalar]) -> Self {
        points
            .iter()
            .zip(scalars.iter())
            .fold(jubjub::SubgroupPoint::default(), |acc, (pt, sc)| {
                acc + *pt * *sc
            })
    }
}

impl HDDeriver for blsful::inner_types::Scalar {
    fn create(msg: &[u8], dst: &[u8]) -> Self {
        blsful::inner_types::Scalar::hash::<ExpandMsgXmd<sha2::Sha256>>(msg, dst)
    }
}

impl HDDerivable for blsful::inner_types::G1Projective {
    fn sum_of_products(points: &[Self], scalars: &[Self::Scalar]) -> Self {
        blsful::inner_types::G1Projective::sum_of_products(points, scalars)
    }
}

impl HDDerivable for blsful::inner_types::G2Projective {
    fn sum_of_products(points: &[Self], scalars: &[Self::Scalar]) -> Self {
        blsful::inner_types::G2Projective::sum_of_products(points, scalars)
    }
}

fn get_poly_powers<D: HDDeriver>(scalar: D, count: usize) -> Vec<D> {
    let mut powers = vec![<D as Field>::ONE; count];
    powers[1] = scalar;
    for i in 2..powers.len() {
        powers[i] = powers[i - 1] * scalar;
    }
    powers
}

#[deprecated(since = "0.2.0", note = "Please use HDDeriver trait instead")]
#[derive(Debug, Clone, Copy, Hash, Ord, PartialOrd, Eq, PartialEq, Deserialize, Serialize)]
pub struct HdKeyDeriver<C>(C::Scalar)
where
    C: GroupDigest,
    <C as CurveArithmetic>::ProjectivePoint: CofactorGroup,
    <C as CurveArithmetic>::Scalar: FromOkm;

impl<C> Display for HdKeyDeriver<C>
where
    C: GroupDigest,
    <C as CurveArithmetic>::ProjectivePoint: CofactorGroup,
    <C as CurveArithmetic>::Scalar: FromOkm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self)
    }
}

impl<C> LowerHex for HdKeyDeriver<C>
where
    C: GroupDigest,
    <C as CurveArithmetic>::ProjectivePoint: CofactorGroup,
    <C as CurveArithmetic>::Scalar: FromOkm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for b in self.0.to_repr().as_ref() {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl<C> UpperHex for HdKeyDeriver<C>
where
    C: GroupDigest,
    <C as CurveArithmetic>::ProjectivePoint: CofactorGroup,
    <C as CurveArithmetic>::Scalar: FromOkm,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for b in self.0.to_repr().as_ref() {
            write!(f, "{:02X}", b)?;
        }
        Ok(())
    }
}

impl<C> HdKeyDeriver<C>
where
    C: GroupDigest,
    <C as CurveArithmetic>::ProjectivePoint: CofactorGroup,
    <C as CurveArithmetic>::Scalar: FromOkm,
{
    pub fn new(id: &[u8], cxt: &[u8]) -> Result<Self, Error> {
        Ok(Self(hash_to_scalar::<C>(id, cxt)?))
    }

    #[cfg(feature = "cait-sith")]
    pub fn compute_secret_key_share_cait_sith<S: CSCurve>(
        &self,
        shares: &[KeygenOutput<S>],
    ) -> Result<KeygenOutput<S>, Error> {
        use k256::elliptic_curve::group::Curve;

        let secrets = shares
            .iter()
            .map(|s| {
                let s = s.private_share.to_repr();
                let mut repr = <C::Scalar as Field>::ONE.to_repr();
                repr.as_mut().copy_from_slice(s.as_ref());
                C::Scalar::from_repr(repr)
            })
            .collect::<Vec<_>>();
        if secrets.iter().any(|s| s.is_none().into()) {
            return Err(Error::CurveMismatchOrInvalidShare);
        }
        let mut secrets = secrets.into_iter().map(|s| s.unwrap()).collect::<Vec<_>>();
        let share = self.compute_secret_key(&secrets);
        // NOTE: it would be better to call zeroize on the secrets but that would require
        // updating Cait-Sith to specify Scalar implements the Zeroize trait.
        // TODO: check if this is optimized away by the compiler.
        secrets.iter_mut().for_each(|s| *s = C::Scalar::ZERO);

        let mut repr = <S::Scalar as Field>::ONE.to_repr();
        repr.as_mut().copy_from_slice(share.to_repr().as_ref());
        let private_share = Option::<S::Scalar>::from(S::Scalar::from_repr(repr))
            .ok_or(Error::CurveMismatchOrInvalidShare)?;
        let public_key = S::ProjectivePoint::generator() * private_share;
        Ok(KeygenOutput {
            private_share,
            public_key: public_key.to_affine(),
        })
    }

    pub fn compute_secret_key(&self, shares: &[C::Scalar]) -> C::Scalar {
        let mut result = C::Scalar::ZERO;

        // Compute the polynomial value using Horner's Method
        for share in shares.iter().rev() {
            // b_{n-1} = a_{n-1} + b_n*x
            result *= self.0;
            result += share;
        }
        result
    }

    pub fn compute_public_key(&self, public_keys: &[C::ProjectivePoint]) -> C::ProjectivePoint {
        let mut powers = vec![<C::Scalar as Field>::ONE; public_keys.len()];
        powers[1] = self.0;
        for i in 2..powers.len() {
            powers[i] = powers[i - 1] * self.0;
        }
        sum_of_products_pippenger::<C>(public_keys, &powers)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.0.to_repr().as_ref());
        out
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        let mut repr = <C::Scalar as Field>::ONE.to_repr();
        repr.as_mut().copy_from_slice(bytes);
        let inner = Option::<C::Scalar>::from(C::Scalar::from_repr(repr))
            .ok_or(Error::CurveMismatchOrInvalidShare)?;
        Ok(HdKeyDeriver(inner))
    }

    pub fn to_inner(self) -> C::Scalar {
        self.0
    }

    pub fn from_inner(inner: C::Scalar) -> Self {
        Self(inner)
    }
}

fn sum_of_products_pippenger<C: CurveArithmetic>(
    points: &[C::ProjectivePoint],
    scalars: &[C::Scalar],
) -> C::ProjectivePoint {
    const WINDOW: usize = 4;
    const NUM_BUCKETS: usize = 1 << WINDOW;
    const EDGE: usize = WINDOW - 1;
    const MASK: u64 = (NUM_BUCKETS - 1) as u64;

    let scalars = convert_scalars::<C>(scalars);
    let num_components = std::cmp::min(points.len(), scalars.len());
    let mut buckets = [<C::ProjectivePoint as Group>::identity(); NUM_BUCKETS];
    let mut res = C::ProjectivePoint::identity();
    let mut num_doubles = 0;
    let mut bit_sequence_index = 255usize;

    loop {
        for _ in 0..num_doubles {
            res = res.double();
        }

        let mut max_bucket = 0;
        let word_index = bit_sequence_index >> 6;
        let bit_index = bit_sequence_index & 63;

        if bit_index < EDGE {
            // we are on the edge of a word; have to look at the previous word, if it exists
            if word_index == 0 {
                // there is no word before
                let smaller_mask = ((1 << (bit_index + 1)) - 1) as u64;
                for i in 0..num_components {
                    let bucket_index: usize = (scalars[i][word_index] & smaller_mask) as usize;
                    if bucket_index > 0 {
                        buckets[bucket_index] += points[i];
                        if bucket_index > max_bucket {
                            max_bucket = bucket_index;
                        }
                    }
                }
            } else {
                // there is a word before
                let high_order_mask = ((1 << (bit_index + 1)) - 1) as u64;
                let high_order_shift = EDGE - bit_index;
                let low_order_mask = ((1 << high_order_shift) - 1) as u64;
                let low_order_shift = 64 - high_order_shift;
                let prev_word_index = word_index - 1;
                for i in 0..num_components {
                    let mut bucket_index =
                        ((scalars[i][word_index] & high_order_mask) << high_order_shift) as usize;
                    bucket_index |= ((scalars[i][prev_word_index] >> low_order_shift)
                        & low_order_mask) as usize;
                    if bucket_index > 0 {
                        buckets[bucket_index] += points[i];
                        if bucket_index > max_bucket {
                            max_bucket = bucket_index;
                        }
                    }
                }
            }
        } else {
            let shift = bit_index - EDGE;
            for i in 0..num_components {
                let bucket_index: usize = ((scalars[i][word_index] >> shift) & MASK) as usize;
                if bucket_index > 0 {
                    buckets[bucket_index] += points[i];
                    if bucket_index > max_bucket {
                        max_bucket = bucket_index;
                    }
                }
            }
        }
        res += &buckets[max_bucket];
        for i in (1..max_bucket).rev() {
            buckets[i] += buckets[i + 1];
            res += buckets[i];
            buckets[i + 1] = C::ProjectivePoint::identity();
        }
        buckets[1] = C::ProjectivePoint::identity();
        if bit_sequence_index < WINDOW {
            break;
        }
        bit_sequence_index -= WINDOW;
        num_doubles = {
            if bit_sequence_index < EDGE {
                bit_sequence_index + 1
            } else {
                WINDOW
            }
        };
    }
    res
}

#[cfg(target_pointer_width = "32")]
fn convert_scalars<C: CurveArithmetic>(scalars: &[C::Scalar]) -> Vec<Vec<u64>> {
    scalars
        .iter()
        .map(|s| {
            let mut out = [0u64; 4];
            let primitive: ScalarPrimitive<C> = (*s).into();
            let small_limbs = primitive
                .as_limbs()
                .iter()
                .map(|l| l.0 as u64)
                .collect::<Vec<_>>();
            let mut i = 0;
            let mut j = 0;
            while i < small_limbs.len() && j < out.len() {
                out[j] = small_limbs[i + 1] << 32 | small_limbs[i];
                i += 2;
                j += 1;
            }
            out
        })
        .collect::<Vec<_>>()
}

#[cfg(target_pointer_width = "64")]
fn convert_scalars<C: CurveArithmetic>(scalars: &[C::Scalar]) -> Vec<[u64; 4]> {
    scalars
        .iter()
        .map(|s| {
            let mut out = [0u64; 4];
            let primitive: ScalarPrimitive<C> = (*s).into();
            out.copy_from_slice(
                primitive
                    .as_limbs()
                    .iter()
                    .map(|l| l.0 as u64)
                    .collect::<Vec<_>>()
                    .as_slice(),
            );
            out
        })
        .collect::<Vec<_>>()
}

#[test]
fn pippinger_k256_known() {
    let points = [k256::ProjectivePoint::GENERATOR; 3];
    let scalars = [
        k256::Scalar::from(1u64),
        k256::Scalar::from(2u64),
        k256::Scalar::from(3u64),
    ];
    let expected = points[0] * scalars[0] + points[1] * scalars[1] + points[2] * scalars[2];

    let actual = sum_of_products_pippenger::<k256::Secp256k1>(&points, &scalars);

    assert_eq!(expected, actual);
}

#[test]
fn pippinger_schnorr_proof() {
    let mut rng = rand::thread_rng();

    for _ in 0..25 {
        let h0 = k256::ProjectivePoint::random(&mut rng);
        let s = k256::Scalar::random(&mut rng);
        let s_tilde = k256::Scalar::random(&mut rng);
        let c = k256::Scalar::random(&mut rng);

        assert_eq!(
            h0 * s,
            sum_of_products_pippenger::<k256::Secp256k1>(&[h0], &[s])
        );

        assert_eq!(
            h0 * s_tilde,
            sum_of_products_pippenger::<k256::Secp256k1>(&[h0], &[s_tilde])
        );

        let u = h0 * s;
        let u_tilde = h0 * s_tilde;
        let s_hat = s_tilde - c * s;
        assert_eq!(u_tilde, u * c + h0 * s_hat);
        assert_eq!(
            u_tilde,
            sum_of_products_pippenger::<k256::Secp256k1>(&[u, h0], &[c, s_hat])
        )
    }
}

#[test]
fn pippinger_p256_known() {
    let points = [p256::ProjectivePoint::generator(); 3];
    let scalars = [
        p256::Scalar::from(1u64),
        p256::Scalar::from(2u64),
        p256::Scalar::from(3u64),
    ];
    let expected = points[0] * scalars[0] + points[1] * scalars[1] + points[2] * scalars[2];

    let actual = sum_of_products_pippenger::<p256::NistP256>(&points, &scalars);

    assert_eq!(expected, actual);
}

#[test]
fn compute_secret_key_test() {
    let mut rng = rand::thread_rng();
    let d0 = k256::Scalar::random(&mut rng);
    let d1 = k256::Scalar::random(&mut rng);

    let d0_shares = vsss_rs::shamir::split_secret::<k256::Scalar, u8, Vec<u8>>(2, 3, d0, &mut rng)
        .unwrap()
        .iter()
        .map(|s| <Vec<u8> as vsss_rs::Share>::as_field_element::<k256::Scalar>(s).unwrap())
        .collect::<Vec<_>>();
    let d1_shares = vsss_rs::shamir::split_secret::<k256::Scalar, u8, Vec<u8>>(2, 3, d1, &mut rng)
        .unwrap()
        .iter()
        .map(|s| <Vec<u8> as vsss_rs::Share>::as_field_element::<k256::Scalar>(s).unwrap())
        .collect::<Vec<_>>();

    let deriver =
        HdKeyDeriver::<k256::Secp256k1>::new(b"id", b"LIT_HD_KEY_ID_K256_XMD:SHA-256_SSWU_RO_NUL_")
            .unwrap();
    let p0 = deriver.compute_secret_key(&[d0_shares[0], d1_shares[0]]);
    let p1 = deriver.compute_secret_key(&[d0_shares[1], d1_shares[1]]);

    let shares = [p0, p1]
        .iter()
        .enumerate()
        .map(|(i, p)| <Vec<u8> as vsss_rs::Share>::from_field_element((i + 1) as u8, *p).unwrap())
        .collect::<Vec<_>>();
    let p = vsss_rs::combine_shares::<k256::Scalar, u8, Vec<u8>>(&shares).unwrap();

    assert_eq!(p, d0 + d1 * deriver.to_inner());
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    #[rstest]
    #[case::k256(k256::Scalar::default(), k256::ProjectivePoint::default())]
    #[case::p256(p256::Scalar::default(), p256::ProjectivePoint::default())]
    #[case::p384(p384::Scalar::default(), p384::ProjectivePoint::default())]
    #[case::ed25519(
        vsss_rs::curve25519::WrappedScalar::default(),
        vsss_rs::curve25519::WrappedEdwards::default()
    )]
    #[case::ristretto25519(
        vsss_rs::curve25519::WrappedScalar::default(),
        vsss_rs::curve25519::WrappedRistretto::default()
    )]
    #[case::jubjub(jubjub::Scalar::default(), jubjub::SubgroupPoint::default())]
    #[case::ed448(
        ed448_goldilocks_plus::Scalar::default(),
        ed448_goldilocks_plus::EdwardsPoint::default()
    )]
    #[case::bls12_381_g1(
        blsful::inner_types::Scalar::default(),
        blsful::inner_types::G1Projective::default()
    )]
    #[case::bls12_381_g2(
        blsful::inner_types::Scalar::default(),
        blsful::inner_types::G2Projective::default()
    )]
    fn derive_test<D: HDDeriver, B: HDDerivable<Scalar = D>>(#[case] _d: D, #[case] _b: B) {
        use rand::SeedableRng;

        const DST: &[u8] = b"LIT_HD_KEY_ID_TEST_XMD_OR_XOF_RO_";

        let mut rng = rand_xorshift::XorShiftRng::from_seed([6u8; 16]);
        let deriver = D::create(b"id", DST);

        let sks = [
            D::random(&mut rng),
            D::random(&mut rng),
            D::random(&mut rng),
        ];

        let pks = [
            B::generator() * sks[0],
            B::generator() * sks[1],
            B::generator() * sks[2],
        ];

        let new_sk = deriver.hd_derive_secret_key(&sks);
        let expected_pk = B::generator() * new_sk;
        let new_pk = deriver.hd_derive_public_key(&pks);
        assert_eq!(expected_pk, new_pk);
    }
}
