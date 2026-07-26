use crate::error::{HsweError, Result};

const TAG_FORMAT_VERSION: u8 = 1;
const EPOCH_TAG_KIND: u8 = 1;
const MAX_APPLICATION_DOMAIN_BYTES: usize = 255;

/// A canonical HSWE v0.1 encryption/signing tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tag {
    application_domain: String,
    epoch: u64,
}

impl Tag {
    /// Creates a canonical epoch tag.
    pub fn epoch(application_domain: impl Into<String>, epoch: u64) -> Result<Self> {
        let application_domain = application_domain.into();

        if application_domain.is_empty() || application_domain.len() > MAX_APPLICATION_DOMAIN_BYTES
        {
            return Err(HsweError::InputTooLarge);
        }

        Ok(Self {
            application_domain,
            epoch,
        })
    }

    /// Returns the application-specific domain as UTF-8 text.
    pub fn application_domain(&self) -> &str {
        &self.application_domain
    }

    /// Returns the epoch number.
    pub fn epoch_number(&self) -> u64 {
        self.epoch
    }

    /// Returns the only permitted v0.1 byte encoding for this tag.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let domain_bytes = self.application_domain.as_bytes();
        let domain_length =
            u8::try_from(domain_bytes.len()).expect("validated application domain length");

        let mut bytes = Vec::with_capacity(3 + domain_bytes.len() + 8);
        bytes.push(TAG_FORMAT_VERSION);
        bytes.push(EPOCH_TAG_KIND);
        bytes.push(domain_length);
        bytes.extend_from_slice(domain_bytes);
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes
    }

    /// Parses a canonical v0.1 epoch tag and rejects every other encoding.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 11 {
            return Err(HsweError::InvalidTagEncoding);
        }

        if bytes[0] != TAG_FORMAT_VERSION {
            return Err(HsweError::InvalidTagEncoding);
        }

        if bytes[1] != EPOCH_TAG_KIND {
            return Err(HsweError::UnsupportedTagKind);
        }

        let domain_length = usize::from(bytes[2]);

        if domain_length == 0 {
            return Err(HsweError::InvalidTagEncoding);
        }

        let expected_length = 3 + domain_length + 8;
        if bytes.len() != expected_length {
            return Err(HsweError::InvalidTagEncoding);
        }

        let domain_end = 3 + domain_length;
        let domain = core::str::from_utf8(&bytes[3..domain_end])
            .map_err(|_| HsweError::InvalidTagEncoding)?;

        let epoch_bytes: [u8; 8] = bytes[domain_end..]
            .try_into()
            .map_err(|_| HsweError::InvalidTagEncoding)?;

        Self::epoch(domain, u64::from_be_bytes(epoch_bytes))
    }
}
