//! Secret-owned configuration and fixed-capacity exchange storage.
//!
//! Every exit from the carrier is a consumer-specific method with its own labelled exception;
//! no method lends the protected bytes to an arbitrary caller.
use crate::rpc::RpcRefusal;
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use std::{ffi::OsStr, fmt, fs::File, io::Read as _, os::unix::ffi::OsStrExt as _, path::Path};

pub(crate) struct Buffer {
    bytes: SecretBox<[u8]>,
    capacity: usize,
    length: usize,
}

impl Buffer {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            bytes: SecretBox::new(vec![0; capacity].into_boxed_slice()),
            capacity,
            length: 0,
        }
    }
    pub(crate) fn len(&self) -> usize {
        self.length
    }
    // Caveat: Ordinary path, prefix and encoding bytes are copied into the protected storage through its mutable slice; slice copying cannot accept the container.
    // (´[ROOT-cav:observe:secret-wallet-rpc-secret-append-1]´)
    // Justified: Ordinary path, prefix and encoding bytes are copied into the protected storage through its mutable slice; slice copying cannot accept the container.
    #[allow(clippy::disallowed_methods)]
    pub(crate) fn append(&mut self, bytes: &[u8]) -> Result<(), RpcRefusal> {
        if bytes.len() > self.capacity - self.length {
            return Err(RpcRefusal::RequestBytes);
        }
        let end = self.length + bytes.len();
        self.bytes.expose_secret_mut(/* (´[ROOT-cav:observe:secret-wallet-rpc-secret-append-1]´) */)[self.length..end]
            .copy_from_slice(bytes);
        self.length = end;
        Ok(())
    }
    // Caveat: The opened cookie file reads directly into the protected storage through its mutable slice until the capacity or end of file; the file API cannot accept the container.
    // (´[ROOT-cav:observe:secret-wallet-rpc-secret-read-cookie-1]´)
    // Justified: The opened cookie file reads directly into the protected storage through its mutable slice; the file API cannot accept the container.
    #[allow(clippy::disallowed_methods)]
    pub(crate) fn read_cookie(&mut self, file: &mut File) -> Result<(), RpcRefusal> {
        while self.length < self.capacity {
            let count = file
                .read(
                    &mut self.bytes.expose_secret_mut(/* (´[ROOT-cav:observe:secret-wallet-rpc-secret-read-cookie-1]´) */)
                        [self.length..],
                )
                .map_err(|_| RpcRefusal::Cookie)?;
            if count == 0 {
                break;
            }
            self.length += count;
        }
        Ok(())
    }
    // Caveat: A private descriptor-relative cookie path is borrowed by the no-follow open until it returns; the filesystem API requires ordinary path bytes.
    // (´[ROOT-cav:observe:secret-wallet-rpc-secret-open-1]´)
    // Justified: A private descriptor-relative cookie path is borrowed by the no-follow open until it returns; the filesystem API requires ordinary path bytes.
    #[allow(clippy::disallowed_methods)]
    pub(crate) fn open(&self, directory: bool) -> Result<File, RpcRefusal> {
        crate::rpc_cookie::open(
            Path::new(OsStr::from_bytes(
                &self.bytes.expose_secret(/* (´[ROOT-cav:observe:secret-wallet-rpc-secret-open-1]´) */)[..self.length],
            )),
            directory,
        )
    }
    // Caveat: Cookie bytes are borrowed by the cookie grammar check, which returns only whether they conform; the byte-level grammar requires a slice.
    // (´[ROOT-cav:observe:secret-wallet-rpc-secret-grammar-1]´)
    // Justified: Cookie bytes are borrowed by the cookie grammar check, which returns only whether they conform; the byte-level grammar requires a slice.
    #[allow(clippy::disallowed_methods)]
    pub(crate) fn cookie_grammar(&self) -> Result<(), RpcRefusal> {
        crate::rpc_cookie::grammar(
            &self.bytes.expose_secret(/* (´[ROOT-cav:observe:secret-wallet-rpc-secret-grammar-1]´) */)[..self.length],
        )
        .map(drop)
    }
    // Caveat: Conforming cookie bytes are borrowed by the Basic encoder, which writes its output only into the target carrier; the encoder requires a slice.
    // (´[ROOT-cav:observe:secret-wallet-rpc-secret-basic-1]´)
    // Justified: Conforming cookie bytes are borrowed by the Basic encoder, which writes its output only into the target carrier; the encoder requires a slice.
    #[allow(clippy::disallowed_methods)]
    pub(crate) fn encode_basic(&self, target: &mut Self) -> Result<(), RpcRefusal> {
        let cookie = crate::rpc_cookie::grammar(
            &self.bytes.expose_secret(/* (´[ROOT-cav:observe:secret-wallet-rpc-secret-basic-1]´) */)[..self.length],
        )?;
        crate::rpc::basic(cookie, target)
    }
    // Caveat: Basic authorization bytes leave the carrier as a sensitive header value, and from it pass through hyper's write buffer, for one exchange on the host-secured connection (´[ROOT-cav:devnet:basic-header-exposure]´); hyper's header and connection APIs cannot accept the carrier, and neither copy is zeroized.
    // (´[ROOT-cav:observe:secret-wallet-rpc-secret-header-1]´)
    // Justified: Basic authorization bytes leave the carrier only as a sensitive header value whose request and connection are dropped at exchange completion; hyper's header and connection APIs cannot accept the carrier.
    #[allow(clippy::disallowed_methods)]
    pub(crate) fn header(&self) -> Result<hyper::header::HeaderValue, RpcRefusal> {
        let mut value = hyper::header::HeaderValue::from_bytes(
            &self.bytes.expose_secret(/* (´[ROOT-cav:observe:secret-wallet-rpc-secret-header-1]´) */)[..self.length],
        )
        .map_err(|_| RpcRefusal::Cookie)?;
        value.set_sensitive(true);
        Ok(value)
    }
    #[cfg(test)]
    // Fixture-only secret boundary: compares carrier bytes created by the calling test or its isolated cookie fixture.
    // Caveat: Fixture carrier bytes are borrowed only for equality with the test's expected bytes; slice comparison cannot accept the container.
    // (´[ROOT-cav:observe:secret-wallet-rpc-secret-equals-1]´)
    // Justified: Fixture carrier bytes are borrowed only for equality with the test's expected bytes; slice comparison cannot accept the container.
    #[allow(clippy::disallowed_methods)]
    pub(crate) fn equals(&self, expected: &[u8]) -> bool {
        &self.bytes.expose_secret(/* (´[ROOT-cav:observe:secret-wallet-rpc-secret-equals-1]´) */)[..self.length] == expected
    }
}

impl fmt::Debug for Buffer {
    /// Justified: Formatting exposes only the carrier role, never exchange bytes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretRpcBuffer")
    }
}
