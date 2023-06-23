mod error;

pub use error::*;

use byteorder::{BigEndian, ReadBytesExt};
use cait_sith::{CSCurve, KeygenOutput};
use std::{
    convert::Infallible,
    fmt::{self, Debug, Display, Formatter, LowerHex, UpperHex},
    str::FromStr,
};

use k256::{
    ecdsa::hazmat::DigestPrimitive,
    elliptic_curve::{
        group::Curve,
        hash2curve::{ExpandMsgXmd, GroupDigest},
        CurveArithmetic, Field, Group, PrimeField,
    },
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, Copy, Hash, Ord, PartialOrd, Eq, PartialEq)]
#[repr(u8)]
pub enum HdKeyDeriverType {
    Unknown = 0,
    K256 = 1,
    P256 = 2,
}

impl Display for HdKeyDeriverType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::K256 => write!(f, "K256"),
            Self::P256 => write!(f, "P256"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

impl From<u8> for HdKeyDeriverType {
    fn from(v: u8) -> Self {
        match v {
            1 => Self::K256,
            2 => Self::P256,
            _ => Self::Unknown,
        }
    }
}

impl FromStr for HdKeyDeriverType {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "K256" => Ok(Self::K256),
            "P256" => Ok(Self::P256),
            _ => Ok(Self::Unknown),
        }
    }
}

impl LowerHex for HdKeyDeriverType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", *self as u8)
    }
}

impl UpperHex for HdKeyDeriverType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:X}", *self as u8)
    }
}

impl Serialize for HdKeyDeriverType {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if s.is_human_readable() {
            s.serialize_str(&self.to_string())
        } else {
            s.serialize_u8(*self as u8)
        }
    }
}

impl<'de> Deserialize<'de> for HdKeyDeriverType {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            Self::from_str(&s).map_err(serde::de::Error::custom)
        } else {
            let v = u8::deserialize(d)?;
            Ok(Self::from(v))
        }
    }
}

impl HdKeyDeriverType {
    pub fn create_deriver<C: CurveArithmetic>(
        &self,
        id: &[u8],
        cxt: &[u8],
    ) -> Result<HdKeyDeriver<C>, Error> {
        let mut repr = C::Scalar::ONE.to_repr();
        match self {
            Self::K256 => {
                let scalar = k256::Secp256k1::hash_to_scalar::<
                    ExpandMsgXmd<<k256::Secp256k1 as DigestPrimitive>::Digest>,
                >(&[id], &[cxt])?;
                repr.as_mut().copy_from_slice(scalar.to_repr().as_ref());
            }
            Self::P256 => {
                let scalar = p256::NistP256::hash_to_scalar::<
                    ExpandMsgXmd<<p256::NistP256 as DigestPrimitive>::Digest>,
                >(&[id], &[cxt])?;
                repr.as_mut().copy_from_slice(scalar.to_repr().as_ref());
            }
            Self::Unknown => return Err(Error::InvalidKeyDeriveType(*self as u8)),
        };

        let inner = Option::<C::Scalar>::from(C::Scalar::from_repr(repr))
            .ok_or(Error::CurveMismatchOrInvalidShare)?;
        Ok(HdKeyDeriver(inner))
    }

    pub fn from_hex(s: &str) -> Result<Self, Error> {
        // only two types so from_str is okay since it's infallible to be less than 10.
        let v = u8::from_str(s)?;
        Ok(Self::from(v))
    }
}

#[derive(Debug, Clone, Copy, Hash, Ord, PartialOrd, Eq, PartialEq, Deserialize, Serialize)]
pub struct HdKeyDeriver<C: CurveArithmetic>(C::Scalar);

impl<C: CurveArithmetic> Display for HdKeyDeriver<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self)
    }
}

impl<C: CurveArithmetic> LowerHex for HdKeyDeriver<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for b in self.0.to_repr().as_ref() {
            write!(f, "{:x}", b)?;
        }
        Ok(())
    }
}

impl<C: CurveArithmetic> UpperHex for HdKeyDeriver<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for b in self.0.to_repr().as_ref() {
            write!(f, "{:X}", b)?;
        }
        Ok(())
    }
}

impl<C: CurveArithmetic> HdKeyDeriver<C> {
    pub fn compute_secret_key_share_cait_sith<S: CSCurve>(
        &self,
        shares: &[KeygenOutput<S>],
    ) -> Result<KeygenOutput<S>, Error> {
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
        let mut result = C::Scalar::ONE;

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
        sum_of_products_pippenger::<C>(&public_keys, &powers)
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

    let scalars = scalars.iter().map(|s| {
        let repr = s.to_repr();
        let mut out = [0u64; 4];
        let mut cursor = std::io::Cursor::new(repr.as_ref());
        out[3] = cursor.read_u64::<BigEndian>().unwrap();
        out[2] = cursor.read_u64::<BigEndian>().unwrap();
        out[1] = cursor.read_u64::<BigEndian>().unwrap();
        out[0] = cursor.read_u64::<BigEndian>().unwrap();
        out
    }).collect::<Vec<_>>();
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
                    let bucket_index: usize =
                        (scalars[i][word_index] & smaller_mask) as usize;
                    if bucket_index > 0 {
                        buckets[bucket_index] += points[i];
                        if bucket_index > max_bucket {
                            max_bucket = bucket_index;
                        }
                    }
                }
            }
            else {
                // there is a word before
                let high_order_mask = ((1 << (bit_index + 1)) - 1) as u64;
                let high_order_shift = EDGE - bit_index;
                let low_order_mask = ((1 << high_order_shift) - 1) as u64;
                let low_order_shift = 64 - high_order_shift;
                let prev_word_index = word_index - 1;
                for i in 0..num_components {
                    let mut bucket_index = ((scalars[i][word_index] & high_order_mask)
                        << high_order_shift)
                        as usize;
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
                let bucket_index: usize =
                    ((scalars[i][word_index] >> shift) & MASK) as usize;
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

#[test]
fn pippinger_k256_known() {
    let points = [k256::ProjectivePoint::GENERATOR; 3];
    let scalars = [
        k256::Scalar::from(1u64),
        k256::Scalar::from(2u64),
        k256::Scalar::from(3u64),
    ];
    let expected = points[0]*scalars[0] + points[1]*scalars[1] + points[2]*scalars[2];

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
    let expected = points[0]*scalars[0] + points[1]*scalars[1] + points[2]*scalars[2];

    let actual = sum_of_products_pippenger::<p256::NistP256>(&points, &scalars);

    assert_eq!(expected, actual);
}

#[test]
fn compute_secret_key() {
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

    let deriver = HdKeyDeriverType::K256.create_deriver::<k256::Secp256k1>(b"id", b"LIT_HD_KEY_ID_K256_XMD:SHA-256_SSWU_RO_NUL_").unwrap();
    let p0 = deriver.compute_secret_key(&[d0_shares[0], d1_shares[0]]);
    let p1 = deriver.compute_secret_key(&[d0_shares[1], d1_shares[1]]);
    // let p2 = deriver.compute_secret_key(&[d0_shares[2], d1_shares[2]]);

    let shares = [p0, p1]
        .iter()
        .enumerate()
        .map(|(i, p)| <Vec<u8> as vsss_rs::Share>::from_field_element((i + 1) as u8, *p).unwrap())
        .collect::<Vec<_>>();
    let p = vsss_rs::combine_shares::<k256::Scalar, u8, Vec<u8>>(&shares).unwrap();

    assert_eq!(p, d0 + d1 * deriver.to_inner());
}