use crate::error::Error;

use k256::elliptic_curve::{
    group::cofactor::CofactorGroup,
    hash2curve::{ExpandMsgXmd, FromOkm, GroupDigest},
    CurveArithmetic,
};

pub fn hash_to_scalar<C>(id: &[u8], cxt: &[u8]) -> Result<C::Scalar, Error>
where
    C: GroupDigest,
    <C as CurveArithmetic>::ProjectivePoint: CofactorGroup,
    <C as CurveArithmetic>::Scalar: FromOkm,
{
    let scalar = C::hash_to_scalar::<ExpandMsgXmd<sha2::Sha256>>(&[id], &[cxt])?;
    Ok(scalar)
}
