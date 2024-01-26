use crate::error::Error;
#[cfg(feature = "cait-sith")]
use cait_sith::PresignOutput;

use k256::elliptic_curve::{
    group::{cofactor::CofactorGroup, GroupEncoding},
    hash2curve::{ExpandMsgXmd, FromOkm, GroupDigest},
    CurveArithmetic,
};

#[cfg(feature = "cait-sith")]
pub fn update_cait_sith_presig<C: cait_sith::CSCurve>(
    verifying_key: C::AffinePoint,
    pre_sig: &PresignOutput<C>,
    private_share: C::Scalar,
    message: &[u8],
    associated_data: &[u8],
    cxt: &[u8],
) -> Result<PresignOutput<C>, Error>
where
    C: GroupDigest,
    <C as CurveArithmetic>::ProjectivePoint: CofactorGroup,
    <C as CurveArithmetic>::Scalar: FromOkm,
{
    use k256::elliptic_curve::group::{Curve, Group};
    let rerandomizer =
        compute_rerandomizer::<C>(verifying_key, pre_sig.big_r, message, associated_data, cxt)?;
    let big_r =
        C::ProjectivePoint::from(pre_sig.big_r) + C::ProjectivePoint::generator() * rerandomizer;
    Ok(PresignOutput {
        big_r: big_r.to_affine(),
        k: pre_sig.k + rerandomizer,
        sigma: pre_sig.sigma + rerandomizer * private_share,
    })
}

pub fn compute_rerandomizer<C>(
    verifying_key: C::AffinePoint,
    big_r: C::AffinePoint,
    message: &[u8],
    associated_data: &[u8],
    cxt: &[u8],
) -> Result<C::Scalar, Error>
where
    C: GroupDigest,
    <C as CurveArithmetic>::ProjectivePoint: CofactorGroup,
    <C as CurveArithmetic>::Scalar: FromOkm,
{
    const SPACE: &[u8] = &[0u8; 32];
    let mut hash_bytes = C::ProjectivePoint::from(verifying_key)
        .to_bytes()
        .as_ref()
        .to_vec();
    hash_bytes.extend_from_slice(SPACE);
    hash_bytes.extend_from_slice(C::ProjectivePoint::from(big_r).to_bytes().as_ref());
    hash_bytes.extend_from_slice(SPACE);
    hash_bytes.extend_from_slice(message);
    hash_bytes.extend_from_slice(SPACE);
    hash_bytes.extend_from_slice(associated_data);
    hash_to_scalar::<C>(&hash_bytes, cxt)
}

pub fn hash_to_scalar<C>(id: &[u8], cxt: &[u8]) -> Result<C::Scalar, Error>
where
    C: GroupDigest,
    <C as CurveArithmetic>::ProjectivePoint: CofactorGroup,
    <C as CurveArithmetic>::Scalar: FromOkm,
{
    let scalar = C::hash_to_scalar::<ExpandMsgXmd<sha2::Sha256>>(&[id], &[cxt])?;
    Ok(scalar)
}
