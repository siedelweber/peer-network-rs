//! Secret-owned inputs for (´[ROOT-dec:observe:secrets]´).
//! Acquisition and consumers must retain the boundary in
//! (´[ROOT-inv:observe:secret-boundary]´); these carriers do not sanitize strings.

use std::fmt;

pub use secrecy::{SecretBox, SecretString};

/// Finite private-material roles; no role can contain a private value.
#[derive(Clone, Copy, Debug)]
pub enum SecretRole {
    /// Instance signing material.
    SigningKey,
    /// Authentication token or credential.
    Authentication,
    /// The entire private connection configuration.
    Connection,
}

/// A role-labelled, secret-owned string with neither Display nor Serialize.
pub struct PrivateString {
    role: SecretRole,
    value: SecretString,
}

impl PrivateString {
    /// Adopt storage that was already secret-typed at acquisition.
    #[must_use]
    /// Justified: Const evaluation cannot emit runtime events; the caller operation accounts its execution without changing this compile-time contract.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    pub const fn new(role: SecretRole, value: SecretString) -> Self {
        Self { role, value }
    }

    /// Borrow the protected carrier, without exposing its contents.
    #[must_use]
    /// Justified: Const evaluation cannot emit runtime events; the caller operation accounts its execution without changing this compile-time contract.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    pub const fn secret(&self) -> &SecretString {
        &self.value
    }
}

impl fmt::Debug for PrivateString {
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "PrivateString {{ role: {:?}, value: [REDACTED] }}", self.role)
    }
}

/// Secret-owned bytes, including whole zeroizing private input buffers.
pub struct PrivateBytes {
    role: SecretRole,
    value: SecretBox<[u8]>,
}

impl PrivateBytes {
    /// Adopt an already protected input buffer, never an ordinary observation value.
    #[must_use]
    /// Justified: Const evaluation cannot emit runtime events; the caller operation accounts its execution without changing this compile-time contract.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    pub const fn new(role: SecretRole, value: SecretBox<[u8]>) -> Self {
        Self { role, value }
    }

    /// Borrow the protected carrier; explicit exposure consumers require admission.
    #[must_use]
    /// Justified: Const evaluation cannot emit runtime events; the caller operation accounts its execution without changing this compile-time contract.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    pub const fn secret(&self) -> &SecretBox<[u8]> {
        &self.value
    }
}

impl fmt::Debug for PrivateBytes {
    /// Justified: This observation or protected-carrier primitive executes inside the explicit operation and delivery machinery; instrumenting it recursively would make observation observe itself.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "PrivateBytes {{ role: {:?}, value: [REDACTED] }}", self.role)
    }
}
