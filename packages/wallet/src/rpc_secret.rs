//! Secret-owned configuration and fixed-capacity exchange storage.
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use std::fmt;

pub(crate) struct Buffer {
    bytes: SecretBox<[u8]>,
    length: usize,
}

impl Buffer {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            bytes: SecretBox::new(vec![0; capacity].into_boxed_slice()),
            length: 0,
        }
    }
    // Caveat: Borrowed private RPC bytes go to the reviewed cookie, encoding or socket consumer; those APIs require slices rather than the container.
    // (´[ROOT-cav:observe:secret-wallet-rpc-secret-bytes-1]´)
    // Justified: Borrowed private RPC bytes go to the reviewed cookie, encoding or socket consumer; those APIs require slices rather than the container.
    #[allow(clippy::disallowed_methods)]
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes.expose_secret(/* (´[ROOT-cav:observe:secret-wallet-rpc-secret-bytes-1]´) */)[..self.length]
    }
    // Caveat: The acquisition API writes directly into the protected buffer through its mutable slice; it cannot accept the container.
    // (´[ROOT-cav:observe:secret-wallet-rpc-secret-vacant-1]´)
    // Justified: The acquisition API writes directly into the protected buffer through its mutable slice; it cannot accept the container.
    #[allow(clippy::disallowed_methods)]
    pub(crate) fn vacant(&mut self) -> &mut [u8] {
        &mut self.bytes.expose_secret_mut(/* (´[ROOT-cav:observe:secret-wallet-rpc-secret-vacant-1]´) */)[self.length..]
    }
    pub(crate) fn advance(&mut self, count: usize) {
        self.length += count;
    }
    pub(crate) fn append(&mut self, bytes: &[u8]) -> Result<(), crate::rpc::RpcRefusal> {
        if bytes.len() > self.vacant().len() {
            return Err(crate::rpc::RpcRefusal::RequestBytes);
        }
        self.vacant()[..bytes.len()].copy_from_slice(bytes);
        self.advance(bytes.len());
        Ok(())
    }
}

impl fmt::Debug for Buffer {
    /// Justified: Formatting exposes only the carrier role, never exchange bytes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretRpcBuffer")
    }
}
