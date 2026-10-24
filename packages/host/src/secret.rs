//! Fixed-capacity secret-owned acquisition and protocol buffers.
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use std::fmt;

use crate::Refusal;

pub(crate) const LIMIT: usize = 1_048_576;

pub(crate) struct Buffer {
    bytes: SecretBox<[u8]>,
    length: usize,
}

impl Buffer {
    pub(crate) fn new() -> Self {
        Self {
            bytes: SecretBox::new(vec![0; LIMIT].into_boxed_slice()),
            length: 0,
        }
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes.expose_secret()[..self.length]
    }
    pub(crate) fn storage(&mut self) -> &mut [u8] {
        self.bytes.expose_secret_mut()
    }
    pub(crate) fn set_length(&mut self, length: usize) -> Result<(), Refusal> {
        if length > LIMIT {
            return Err(Refusal::RepresentationLimit);
        }
        self.length = length;
        Ok(())
    }
    pub(crate) fn append(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        let end = self.length.checked_add(bytes.len()).ok_or(Refusal::RepresentationLimit)?;
        if end > LIMIT {
            return Err(Refusal::RepresentationLimit);
        }
        self.bytes.expose_secret_mut()[self.length..end].copy_from_slice(bytes);
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
