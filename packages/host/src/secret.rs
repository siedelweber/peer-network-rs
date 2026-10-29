//! Fixed-capacity secret-owned acquisition and protocol buffers.
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use std::fmt;

use crate::Refusal;

pub(crate) const LIMIT: usize = 1_048_576;

pub(crate) struct Buffer {
    bytes: SecretBox<[u8]>,
    length: usize,
    capacity: usize,
}

impl Buffer {
    pub(crate) fn new() -> Self {
        Self::with_capacity(LIMIT)
    }
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: SecretBox::new(vec![0; capacity].into_boxed_slice()),
            length: 0,
            capacity,
        }
    }
    // Caveat: The protocol-storage borrow is forwarded only through a separately labelled host consumer, including classified-public observation after classification; these reviewed consumers require slices rather than a secret container.
    // (´[ROOT-cav:observe:secret-host-secret-bytes-1]´)
    // Justified: Each labelled borrow below serves only its stated consumer until its stated endpoint; those byte-oriented APIs cannot accept the carrier.
    #[allow(clippy::disallowed_methods)]
    pub(crate) fn expose_bytes(&self) -> &[u8] {
        &self.bytes.expose_secret(/* (´[ROOT-cav:observe:secret-host-secret-bytes-1]´) */)[..self.length]
    }
    // Caveat: The mutable private buffer goes only to acquisition or encoding into protected storage; the byte-oriented APIs cannot accept the container.
    // (´[ROOT-cav:observe:secret-host-secret-storage-1]´)
    // Justified: Each labelled borrow below serves only its stated consumer until its stated endpoint; those byte-oriented APIs cannot accept the carrier.
    #[allow(clippy::disallowed_methods)]
    pub(crate) fn expose_storage(&mut self) -> &mut [u8] {
        self.bytes.expose_secret_mut(/* (´[ROOT-cav:observe:secret-host-secret-storage-1]´) */)
    }
    pub(crate) fn len(&self) -> usize {
        self.length
    }
    pub(crate) fn set_length(&mut self, length: usize) -> Result<(), Refusal> {
        if length > self.capacity {
            return Err(Refusal::RepresentationLimit);
        }
        self.length = length;
        Ok(())
    }
    // Caveat: Incoming private bytes are copied directly into protected storage through a borrow ending when copying returns; the container has no bounded append operation.
    // (´[ROOT-cav:observe:secret-host-secret-append-2]´)
    // Justified: Each labelled borrow below serves only its stated consumer until its stated endpoint; those byte-oriented APIs cannot accept the carrier.
    #[allow(clippy::disallowed_methods)]
    pub(crate) fn append(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        let end = self.length.checked_add(bytes.len()).ok_or(Refusal::RepresentationLimit)?;
        if end > self.capacity {
            return Err(Refusal::RepresentationLimit);
        }
        self.bytes.expose_secret_mut(/* (´[ROOT-cav:observe:secret-host-secret-append-2]´) */)[self.length..end]
            .copy_from_slice(bytes);
        self.length = end;
        Ok(())
    }
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, Refusal> {
        let mut value = Self::new();
        value.append(bytes)?;
        Ok(value)
    }
}

impl fmt::Debug for Buffer {
    /// Justified: Protocol and secret-carrier trait plumbing inherits the enclosing host operation; re-observation would duplicate content or format secret state.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBuffer { role: store-transport, value: [REDACTED] }")
    }
}

#[cfg(test)]
mod tests {
    use super::Buffer;
    use crate::Refusal;

    /// Claim: Buffer length reports public bookkeeping after bounded append and explicit length changes; refused growth preserves that bookkeeping without borrowing the protected bytes.
    /// ´claim:host:buffer-length-needs-no-secret-borrow´
    /// ´test:unit:length-metadata´
    #[test]
    fn length_metadata() {
        let mut value = Buffer::with_capacity(3);
        assert_eq!(value.len(), 0);
        value.append(b"ab").unwrap();
        assert_eq!(value.len(), 2);
        assert_eq!(value.append(b"cd"), Err(Refusal::RepresentationLimit));
        assert_eq!(value.len(), 2);
        assert_eq!(value.set_length(4), Err(Refusal::RepresentationLimit));
        assert_eq!(value.len(), 2);
        value.set_length(1).unwrap();
        assert_eq!(value.len(), 1);
        value.append(b"cd").unwrap();
        assert_eq!(value.len(), 3);
        value.set_length(0).unwrap();
        assert_eq!(value.len(), 0);
    }
}
