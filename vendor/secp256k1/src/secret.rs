// SPDX-License-Identifier: CC0-1.0

//! Diagnostics for owned secrets never depend on their value.

macro_rules! impl_owned_secret {
    ($thing:ident) => {
        impl core::fmt::Debug for $thing {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                f.write_str(concat!(stringify!($thing), "([REDACTED])"))
            }
        }
        impl Drop for $thing {
            fn drop(&mut self) { self.non_secure_erase(); }
        }
    };
}
