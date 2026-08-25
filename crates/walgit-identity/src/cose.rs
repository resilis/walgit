use ed25519_dalek::{Signature, VerifyingKey};

use crate::{IdentityError, cbor};

pub(crate) struct Sign1<'a> {
    pub(crate) protected: &'a [u8],
    pub(crate) kid: [u8; 16],
    pub(crate) payload: &'a [u8],
    signature: [u8; 64],
}

impl<'a> Sign1<'a> {
    pub(crate) fn parse(
        bytes: &'a [u8],
        maximum: usize,
        maximum_payload: usize,
    ) -> Result<Self, IdentityError> {
        let mut cursor = cbor::Cursor::new(bytes, maximum)?;
        if cursor.array(4, 4)? != 4 {
            return Err(IdentityError::Cose("COSE_Sign1 must have four items"));
        }
        let protected = cursor.bytes(1, 64)?;
        let kid = parse_protected(protected)?;
        if cursor.map(0, 0)? != 0 {
            return Err(IdentityError::Cose("unprotected header must be empty"));
        }
        let payload = cursor.bytes(1, maximum_payload)?;
        let signature: [u8; 64] = cursor.bytes(64, 64)?.try_into().expect("length checked");
        cursor.finish()?;
        Ok(Self {
            protected,
            kid,
            payload,
            signature,
        })
    }

    pub(crate) fn verify(&self, key: &[u8; 32], external_aad: &[u8]) -> Result<(), IdentityError> {
        let key = VerifyingKey::from_bytes(key).map_err(|_| IdentityError::Signature)?;
        let signature = Signature::from_bytes(&self.signature);
        key.verify_strict(
            &sig_structure(self.protected, external_aad, self.payload),
            &signature,
        )
        .map_err(|_| IdentityError::Signature)
    }
}

fn parse_protected(bytes: &[u8]) -> Result<[u8; 16], IdentityError> {
    let mut cursor = cbor::Cursor::new(bytes, 64)?;
    if cursor.map(2, 2)? != 2 || cursor.uint()? != 1 || cursor.int()? != -8 || cursor.uint()? != 4 {
        return Err(IdentityError::Cose(
            "protected header is not exact EdDSA/kid map",
        ));
    }
    let kid = cursor.bytes(16, 16)?.try_into().expect("length checked");
    cursor.finish()?;
    Ok(kid)
}

#[cfg(test)]
pub(crate) fn protected(kid: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(23);
    cbor::map(&mut out, 2);
    cbor::uint(&mut out, 1);
    cbor::int(&mut out, -8);
    cbor::uint(&mut out, 4);
    cbor::bytes(&mut out, kid);
    out
}

pub(crate) fn sig_structure(protected: &[u8], external_aad: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + protected.len() + external_aad.len() + payload.len());
    cbor::array(&mut out, 4);
    cbor::text(&mut out, b"Signature1");
    cbor::bytes(&mut out, protected);
    cbor::bytes(&mut out, external_aad);
    cbor::bytes(&mut out, payload);
    out
}
