//! Versioned, context-bound device pin submissions.
use serde::{Deserialize, Serialize};

/// A device-created v2 fingerprint with its explicit authenticated context.
/// Values and salts stay on devices. Deserialization is untrusted: membership
/// validates version/context and cgrd later verifies the actual v2 opening.
///
/// ```compile_fail
/// let raw = cpns::Fingerprint::from_bytes([0; 32]);
/// let pin: cmbr::PinV2 = raw.into();
/// ```
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinV2 {
    version: u8,
    community: String,
    member: String,
    field: String,
    fingerprint: [u8; 32],
}
impl PinV2 {
    /// Device-side creation using cpns's v2 algorithm and authenticated context.
    /// Never call this with a value or salt received by the permanent server.
    pub fn seal(context: &cpns::FingerprintContext<'_>, value: &[u8], salt: &cpns::Salt) -> Self {
        Self {
            version: 2,
            community: context.community.into(),
            member: context.member.into(),
            field: context.field.into(),
            fingerprint: *cpns::fingerprint_v2(context, value, salt).as_bytes(),
        }
    }
    /// Device digest for constructing a canonical cblc change commitment.
    pub fn fingerprint(&self) -> cpns::Fingerprint {
        cpns::Fingerprint::from_bytes(self.fingerprint)
    }
    pub(crate) fn checked(
        &self,
        community: &str,
        member: &str,
        field: &str,
    ) -> crate::Result<cpns::Fingerprint> {
        if self.version != 2
            || self.community != community
            || self.member != member
            || self.field != field
        {
            return Err(crate::Error::Pin);
        }
        Ok(self.fingerprint())
    }
}
impl std::fmt::Debug for PinV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PinV2([redacted])")
    }
}
