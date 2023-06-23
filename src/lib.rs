mod error;

pub use error::*;

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

    pub fn compute_public_key(&self, public_keys: &[C::AffinePoint]) -> C::AffinePoint {
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
    points: &[C::AffinePoint],
    scalars: &[C::Scalar],
) -> C::AffinePoint {
    const UPPER: usize = 256;
    const W: usize = 4;
    const WINDOWS: usize = UPPER / W; // careful--use ceiling division in case this doesn't divide evenly
    const BUCKET_SIZE: usize = 1 << W;

    if points.len() != scalars.len() {
        panic!("points and scalars must have the same length");
    }

    let mut windows = vec![<C::ProjectivePoint as Group>::identity(); WINDOWS];
    let mut bytes = vec![[0u8; 32]; scalars.len()];
    let mut buckets = vec![<C::ProjectivePoint as Group>::identity(); BUCKET_SIZE];

    for i in 0..scalars.len() {
        let mut repr = [0u8; 32];
        repr.copy_from_slice(<C::Scalar as PrimeField>::to_repr(&scalars[i]).as_ref());
        bytes[i] = repr;
    }
    let points = points
        .iter()
        .map(|p| C::ProjectivePoint::from(*p))
        .collect::<Vec<_>>();

    let mut sum;

    for (j, window) in windows.iter_mut().enumerate() {
        for bucket in buckets.iter_mut() {
            *bucket = <C::ProjectivePoint as Group>::identity();
        }

        for i in 0..scalars.len() {
            // j*W to get the nibble
            // >> 3 to convert to byte, / 8
            // (W * j & W) gets the nibble, mod W
            // 1 << W - 1 to get the offset
            let index = bytes[i][(j * W) >> 3] >> ((W * j) & W) & ((1 << W) - 1); // little-endian
            buckets[index as usize] += points[i];
        }

        sum = C::ProjectivePoint::identity();

        for i in (0..BUCKET_SIZE - 1).rev() {
            sum += buckets[i];
            *window += sum;
        }
    }

    sum = C::ProjectivePoint::identity();
    for i in (0..WINDOWS).rev() {
        for _ in 0..W {
            sum = sum.double();
        }

        sum += windows[i];
    }

    sum.to_affine()
}
