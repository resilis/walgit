//! Nominal SHA-256 types for the V5.8 stored-byte preimages.

use sha2::{Digest, Sha256};

/// The SHA-256 value encoded in a content-addressed physical object key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ContentAddressDigest([u8; 32]);

impl ContentAddressDigest {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn lower_hex(&self) -> String {
        hex::encode(self.0)
    }
}

macro_rules! stored_digest {
    ($name:ident, $constructor:ident) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            pub fn $constructor(bytes: &[u8]) -> Self {
                Self(Sha256::digest(bytes).into())
            }

            pub fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            pub fn lower_hex(&self) -> String {
                hex::encode(self.0)
            }
        }
    };
}

stored_digest!(ProtobufObjectDigest, of_exact_protobuf);
stored_digest!(RawPayloadDigest, of_exact_payload);
stored_digest!(SignedEnvelopeDigest, of_exact_cose_sign1);
stored_digest!(VerificationRingDigest, of_exact_ring_cose_sign1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoredDigestKind {
    ProtobufObject,
    RawPayload,
    VerificationRing,
}
