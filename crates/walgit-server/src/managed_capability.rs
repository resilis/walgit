//! Strict verification for short-lived repository capabilities issued by Cloud Core.
//!
//! WalGit stores only bounded Ed25519 public JWK components. It does not mint these
//! credentials and never receives the signing key.

use std::time::Duration;

use base64::Engine;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::Deserialize;
use walgit_config::{ManagedTokensConfig, TenantRole};
use walgit_git::RepoId;

const MAX_JWT_BYTES: usize = 4_096;
const CLOCK_SKEW_SECONDS: u64 = 30;

#[derive(Debug)]
pub(crate) struct VerifiedCapability {
    pub(crate) subject: String,
    pub(crate) repository: RepoId,
    pub(crate) role: TenantRole,
}

pub(crate) struct ManagedCapabilityVerifier {
    issuer: String,
    audience: String,
    max_ttl: Duration,
    keys: Vec<VerificationKey>,
}

struct VerificationKey {
    kid: String,
    key: DecodingKey,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityHeader {
    alg: String,
    typ: String,
    kid: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityClaims {
    v: u64,
    iss: String,
    aud: String,
    sub: String,
    tenant: String,
    repository: String,
    role: TenantRole,
    iat: u64,
    nbf: u64,
    exp: u64,
}

impl ManagedCapabilityVerifier {
    pub(crate) fn new(config: &ManagedTokensConfig) -> anyhow::Result<Self> {
        let keys = config
            .keys
            .iter()
            .map(|configured| {
                let key = DecodingKey::from_ed_components(&configured.x).map_err(|_| {
                    anyhow::anyhow!(
                        "server.auth.managed_tokens contains an invalid Ed25519 public key"
                    )
                })?;
                Ok(VerificationKey {
                    kid: configured.kid.clone(),
                    key,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Self {
            issuer: config.issuer.clone(),
            audience: config.audience.clone(),
            max_ttl: config.max_ttl,
            keys,
        })
    }

    pub(crate) fn verify(&self, jwt: &str, now: u64) -> Option<VerifiedCapability> {
        if jwt.is_empty() || jwt.len() > MAX_JWT_BYTES || jwt.as_bytes().contains(&b'=') {
            return None;
        }
        let mut segments = jwt.split('.');
        let header_segment = segments.next()?;
        let payload_segment = segments.next()?;
        let signature_segment = segments.next()?;
        if header_segment.is_empty()
            || payload_segment.is_empty()
            || signature_segment.is_empty()
            || segments.next().is_some()
        {
            return None;
        }
        let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(header_segment)
            .ok()?;
        let header: CapabilityHeader = serde_json::from_slice(&header_bytes).ok()?;
        if header.alg != "EdDSA" || header.typ != "walgit-capability+jwt" || header.kid.is_empty() {
            return None;
        }
        let key = self.keys.iter().find(|key| key.kid == header.kid)?;

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false;
        let claims = decode::<CapabilityClaims>(jwt, &key.key, &validation)
            .ok()?
            .claims;

        if claims.v != 1
            || claims.iss != self.issuer
            || claims.aud != self.audience
            || !valid_subject(&claims.sub)
            || claims.iat > claims.nbf
            || claims.nbf > claims.exp
        {
            return None;
        }
        let lifetime = claims.exp.checked_sub(claims.iat)?;
        if lifetime == 0 || lifetime > self.max_ttl.as_secs() {
            return None;
        }
        if now.saturating_add(CLOCK_SKEW_SECONDS) < claims.nbf
            || now > claims.exp.saturating_add(CLOCK_SKEW_SECONDS)
        {
            return None;
        }
        let repository = RepoId::new(claims.tenant, claims.repository).ok()?;
        Some(VerifiedCapability {
            subject: claims.sub,
            repository,
            role: claims.role,
        })
    }
}

fn valid_subject(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::{Value, json};
    use walgit_config::ManagedTokenPublicKey;

    const NOW: u64 = 2_000_000_000;

    fn fixture() -> (ManagedCapabilityVerifier, SigningKey) {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(signing.verifying_key().to_bytes());
        let verifier = ManagedCapabilityVerifier::new(&ManagedTokensConfig {
            issuer: "cloud-core".into(),
            audience: "walgit-production".into(),
            keys: vec![ManagedTokenPublicKey {
                kid: "active".into(),
                x,
            }],
            max_ttl: Duration::from_secs(900),
        })
        .unwrap();
        (verifier, signing)
    }

    fn header() -> Value {
        json!({"alg":"EdDSA","typ":"walgit-capability+jwt","kid":"active"})
    }

    fn claims(role: &str) -> Value {
        json!({
            "v": 1,
            "iss": "cloud-core",
            "aud": "walgit-production",
            "sub": "agent:build-17",
            "tenant": "acme",
            "repository": "widgets",
            "role": role,
            "iat": NOW,
            "nbf": NOW,
            "exp": NOW + 900
        })
    }

    fn token(signing: &SigningKey, header: Value, claims: Value) -> String {
        let encoding = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = encoding.encode(serde_json::to_vec(&header).unwrap());
        let claims = encoding.encode(serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{header}.{claims}");
        let signature = signing.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", encoding.encode(signature.to_bytes()))
    }

    #[test]
    fn accepts_closed_exact_repository_claims_for_each_tenant_role() {
        let (verifier, signing) = fixture();
        for (encoded, expected) in [
            ("reader", TenantRole::Reader),
            ("writer", TenantRole::Writer),
            ("admin", TenantRole::Admin),
        ] {
            let verified = verifier
                .verify(&token(&signing, header(), claims(encoded)), NOW)
                .expect("valid capability");
            assert_eq!(verified.subject, "agent:build-17");
            assert_eq!(verified.repository.to_string(), "acme/widgets");
            assert_eq!(verified.role, expected);
        }
    }

    #[test]
    fn rejects_wrong_signature_header_or_closed_claim_shape() {
        let (verifier, signing) = fixture();
        let foreign = SigningKey::from_bytes(&[8; 32]);

        let mut wrong_typ = header();
        wrong_typ["typ"] = json!("JWT");
        let mut wrong_kid = header();
        wrong_kid["kid"] = json!("retired");
        let mut unknown_header = header();
        unknown_header["extra"] = json!(true);
        let mut unknown_claim = claims("reader");
        unknown_claim["scope"] = json!("*");
        let mut wrong_issuer = claims("reader");
        wrong_issuer["iss"] = json!("someone-else");
        let mut wrong_audience = claims("reader");
        wrong_audience["aud"] = json!("another-service");
        let mut wrong_version = claims("reader");
        wrong_version["v"] = json!(2);
        let mut unknown_role = claims("reader");
        unknown_role["role"] = json!("owner");
        let mut bad_repo = claims("reader");
        bad_repo["repository"] = json!("../widgets");

        for candidate in [
            token(&foreign, header(), claims("reader")),
            token(&signing, wrong_typ, claims("reader")),
            token(&signing, wrong_kid, claims("reader")),
            token(&signing, unknown_header, claims("reader")),
            token(&signing, header(), unknown_claim),
            token(&signing, header(), wrong_issuer),
            token(&signing, header(), wrong_audience),
            token(&signing, header(), wrong_version),
            token(&signing, header(), unknown_role),
            token(&signing, header(), bad_repo),
        ] {
            assert!(verifier.verify(&candidate, NOW).is_none());
        }
    }

    #[test]
    fn rejects_invalid_time_windows_and_oversize_tokens() {
        let (verifier, signing) = fixture();
        let mut reversed = claims("reader");
        reversed["nbf"] = json!(NOW + 2);
        reversed["exp"] = json!(NOW + 1);
        let mut too_long = claims("reader");
        too_long["exp"] = json!(NOW + 901);
        let mut future = claims("reader");
        future["iat"] = json!(NOW + 31);
        future["nbf"] = json!(NOW + 31);
        future["exp"] = json!(NOW + 100);
        let mut expired = claims("reader");
        expired["iat"] = json!(NOW - 901);
        expired["nbf"] = json!(NOW - 901);
        expired["exp"] = json!(NOW - 31);

        for candidate in [reversed, too_long, future, expired] {
            assert!(
                verifier
                    .verify(&token(&signing, header(), candidate), NOW)
                    .is_none()
            );
        }
        assert!(
            verifier
                .verify(&"a".repeat(MAX_JWT_BYTES + 1), NOW)
                .is_none()
        );
    }
}
