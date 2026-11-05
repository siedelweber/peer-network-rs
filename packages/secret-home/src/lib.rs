//! A private owning mapping; no byte export or signing operation is admitted.
//! (´[ROOT-amend:crypto:secret-home]´)
#![deny(unsafe_op_in_unsafe_fn)]

use rustix::mm::{Advice, MapFlags, ProtFlags};
use rustix::process::{DumpableBehavior, Resource, Rlimit};
use std::ffi::c_void;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use zeroize::Zeroize;

static BUDGET: OnceLock<usize> = OnceLock::new();
static PAGE_SIZE: OnceLock<Result<usize, Error>> = OnceLock::new();
static RESERVED: AtomicUsize = AtomicUsize::new(0);

/// Content-free failure classes; operating-system details never contain a key.
/// (´[ROOT-amend:crypto:secret-home]´)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Platform,
    Protection,
    Budget,
    Mapping,
    Advice,
    Lock,
    Entropy,
    Size,
    Process,
}

/// Process-start protection and the declared total mapping budget.
/// (´[ROOT-amend:crypto:secret-home]´)
pub struct Protection {
    page: usize,
    budget: usize,
    process: u32,
}

impl std::fmt::Debug for Protection {
    /// Justified: This bootstrap carrier emits only a constant without process or budget details.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Protection")
    }
}

/// A borrowed import buffer with constant diagnostics and erasure on drop.
/// The caller's earlier copies remain its responsibility.
/// (´[ROOT-amend:crypto:secret-home]´)
pub struct Staging<'a>(&'a mut [u8]);

impl<'a> Staging<'a> {
    /// Justified: Bootstrap borrows caller staging without copying or observing its bytes, before the labelled import operation.
    pub fn acquire(bytes: &'a mut [u8]) -> Self {
        Self(bytes)
    }
}
impl std::fmt::Debug for Staging<'_> {
    /// Justified: Import staging diagnostics emit one constant without reading its bytes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Staging([REDACTED])")
    }
}
impl Drop for Staging<'_> {
    /// Justified: Borrowed staging destruction erases the caller buffer without observation.
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Protection {
    /// Clear dumpability and the core limit, verify both, then admit one budget.
    /// Call at process start before accepting secret material or spawning workers.
    /// (´[ROOT-amend:crypto:secret-home]´)
    /// # Errors
    /// Refuses unsupported platforms, inaccessible kernel state or a budget
    /// outside the current memlock limit. Process protections are not rolled back.
    #[tracing::instrument(
        name = "amend:crypto:secret-home",
        fields(
            execution_owner = "SECRETHOME",
            claim_owner = "ROOT",
            claim_label = "amend:crypto:secret-home",
            source_item = "Protection::establish"
        ),
        ret
    )]
    pub fn establish(budget: usize) -> Result<Self, Error> {
        if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            return Err(Error::Platform);
        }
        let page = (*PAGE_SIZE.get_or_init(page_size))?;
        if budget == 0 || !budget.is_multiple_of(page) || budget > isize::MAX as usize {
            return Err(Error::Budget);
        }
        let limit = rustix::process::getrlimit(Resource::Memlock);
        if limit.current.is_some_and(|v| u64::try_from(budget).map_or(true, |b| b > v)) {
            return Err(Error::Budget);
        }
        rustix::process::set_dumpable_behavior(DumpableBehavior::NotDumpable).map_err(|_| Error::Protection)?;
        rustix::process::setrlimit(
            Resource::Core,
            Rlimit {
                current: Some(0),
                maximum: Some(0),
            },
        )
        .map_err(|_| Error::Protection)?;
        verify_process()?;
        if *BUDGET.get_or_init(|| budget) != budget {
            return Err(Error::Budget);
        }
        Ok(Self {
            page,
            budget,
            process: std::process::id(),
        })
    }

    /// Fill the new home directly from the OS; partial entropy failures erase it.
    /// (´[ROOT-amend:crypto:secret-home]´)
    /// # Errors
    /// Refuses failed protection, size, allocation, advice, locking or entropy.
    #[tracing::instrument(
        name = "amend:crypto:secret-home",
        fields(
            execution_owner = "SECRETHOME",
            claim_owner = "ROOT",
            claim_label = "amend:crypto:secret-home",
            source_item = "Protection::generate"
        ),
        ret
    )]
    pub fn generate(&self, size: usize) -> Result<Home, Error> {
        self.generate_with(size, |bytes| getrandom::fill(bytes).map_err(|_| Error::Entropy))
    }

    /// Copy from caller staging, erasing that staging on success and refusal.
    /// Copies retained by the caller before this borrow are outside this contract.
    /// (´[ROOT-amend:crypto:secret-home]´)
    /// # Errors
    /// Refuses failed protection, size, allocation, advice or locking.
    #[tracing::instrument(
        name = "amend:crypto:secret-home",
        fields(
            execution_owner = "SECRETHOME",
            claim_owner = "ROOT",
            claim_label = "amend:crypto:secret-home",
            source_item = "Protection::import"
        ),
        ret
    )]
    pub fn import(&self, staging: &mut Staging<'_>) -> Result<Home, Error> {
        let result = self.generate_with(staging.0.len(), |bytes| {
            bytes.copy_from_slice(staging.0);
            Ok(())
        });
        staging.0.zeroize();
        result
    }

    /// Justified: Acquisition inherits the public constructor boundary and never observes raw secret bytes.
    fn generate_with(&self, size: usize, fill: impl FnOnce(&mut [u8]) -> Result<(), Error>) -> Result<Home, Error> {
        if self.process != std::process::id() {
            return Err(Error::Process);
        }
        verify_process()?;
        if size == 0 {
            return Err(Error::Size);
        }
        let len = size.checked_add(self.page - 1).ok_or(Error::Size)? / self.page * self.page;
        if len > self.budget || len > isize::MAX as usize {
            return Err(Error::Budget);
        }
        RESERVED
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                n.checked_add(len).filter(|v| *v <= self.budget)
            })
            .map_err(|_| Error::Budget)?;
        let mut home = match Home::map(len, self.process) {
            Ok(home) => home,
            Err(error) => {
                RESERVED.fetch_sub(len, Ordering::SeqCst);
                return Err(error);
            }
        };
        if home.pointer.is_null() {
            return Err(Error::Mapping);
        }
        home.protect()?;
        home.lock()?;
        fill(&mut home.bytes()[..size])?;
        Ok(home)
    }
}

/// Justified: Bootstrap checks only public kernel protection state and discards operating-system errors.
fn verify_process() -> Result<(), Error> {
    if rustix::process::dumpable_behavior().map_err(|_| Error::Protection)? != DumpableBehavior::NotDumpable
        || rustix::process::getrlimit(Resource::Core)
            != (Rlimit {
                current: Some(0),
                maximum: Some(0),
            })
    {
        return Err(Error::Protection);
    }
    Ok(())
}

/// Justified: Bootstrap decodes only the public platform page size and refuses unknown layouts.
fn page_size() -> Result<usize, Error> {
    // Linux x86_64 auxv consists of native-endian pairs of 64-bit words.
    let data = std::fs::read("/proc/self/auxv").map_err(|_| Error::Platform)?;
    for pair in data.as_chunks::<16>().0 {
        let key = u64::from_ne_bytes(pair[..8].try_into().map_err(|_| Error::Platform)?);
        if key == 6 {
            let size = usize::try_from(u64::from_ne_bytes(pair[8..].try_into().map_err(|_| Error::Platform)?))
                .map_err(|_| Error::Platform)?;
            if size.is_power_of_two() && isize::try_from(size).is_ok() {
                return Ok(size);
            }
        }
    }
    Err(Error::Platform)
}

/// A non-copying owner, with no public byte view or implicit cloning/formatting.
/// Only moves of this pointer-bearing handle are allowed; mapping bytes stay put.
/// (´[ROOT-amend:crypto:secret-home]´)
pub struct Home {
    pointer: *mut c_void,
    len: usize,
    process: u32,
    locked: bool,
}

impl std::fmt::Debug for Home {
    /// Justified: Secret-home diagnostics are constant regardless of secret contents or allocation address.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Home([REDACTED])")
    }
}

impl Home {
    // Justified: Only this owner creates anonymous mappings under the inventoried exception.
    #[expect(unsafe_code, reason = "owned anonymous mapping")]
    fn map(len: usize, process: u32) -> Result<Self, Error> {
        // SAFETY: The nonzero bounded length requests a fresh private readable/writable anonymous mapping, with no fixed address or overlapping allocation. This owner alone releases it.
        // (´[ROOT-cav:crypto:home-map]´)
        let pointer = unsafe {
            rustix::mm::mmap_anonymous(
                std::ptr::null_mut(),
                len,
                ProtFlags::READ | ProtFlags::WRITE,
                MapFlags::PRIVATE,
            )
        }
        .map_err(|_| Error::Mapping)?;
        Ok(Self {
            pointer,
            len,
            process,
            locked: false,
        })
    }

    // Justified: Only the owned complete mapping receives fork and dump exclusion advice.
    #[expect(unsafe_code, reason = "owned mapping advice")]
    fn protect(&mut self) -> Result<(), Error> {
        for advice in [Advice::LinuxDontDump, Advice::LinuxDontFork] {
            // SAFETY: This single owner holds the live page-aligned mapping with its original full length; no slice exists and neither advice changes the parent's readable/writable mapping.
            // (´[ROOT-cav:crypto:home-advice]´)
            unsafe { rustix::mm::madvise(self.pointer, self.len, advice) }.map_err(|_| Error::Advice)?;
        }
        Ok(())
    }

    // Justified: Lock only this allocation and refuse locking failure before writing secret material.
    #[expect(unsafe_code, reason = "owned mapping lock")]
    fn lock(&mut self) -> Result<(), Error> {
        // SAFETY: This single owner holds the live page-aligned mapping with its original full length; it has not been unmapped and no slice is active.
        // (´[ROOT-cav:crypto:home-lock]´)
        unsafe { rustix::mm::mlock(self.pointer, self.len) }.map_err(|_| Error::Lock)?;
        self.locked = true;
        Ok(())
    }

    // Justified: The sole private byte view lends the owned initialized mapping for the duration of an exclusive borrow.
    #[expect(unsafe_code, reason = "exclusive owned mapping bytes")]
    fn bytes(&mut self) -> &mut [u8] {
        assert_eq!(self.process, std::process::id(), "mapping belongs to another process");
        assert!(!self.pointer.is_null());
        // SAFETY: This owner's non-null live readable/writable anonymous mapping is zero-initialized. Its original length is within one allocation and isize::MAX. The exclusive self borrow bounds the slice lifetime and excludes other accesses; release requires that borrow to end.
        // (´[ROOT-cav:crypto:home-bytes]´)
        unsafe { std::slice::from_raw_parts_mut(self.pointer.cast(), self.len) }
    }

    /// Justified: Destruction erases the whole private mapping without exporting or observing its contents.
    fn erase(&mut self) {
        self.bytes().zeroize();
    }

    // Justified: Unlock follows full-allocation erasure and the end of every byte borrow.
    #[expect(unsafe_code, reason = "owned mapping unlock")]
    fn unlock(&mut self) -> Result<(), rustix::io::Errno> {
        // SAFETY: This single owner still holds the live page-aligned mapping and its original full length; all byte borrows have ended and the mapping has not been released.
        // (´[ROOT-cav:crypto:home-unlock]´)
        unsafe { rustix::mm::munlock(self.pointer, self.len) }
    }

    // Justified: Release only the original owned mapping after erasure, with no surviving byte references.
    #[expect(unsafe_code, reason = "owned mapping release")]
    fn unmap(&mut self) -> Result<(), rustix::io::Errno> {
        // SAFETY: This single owner releases its original page-aligned mapping and full length exactly once; no Rust reference survives and no later operation uses the pointer.
        // (´[ROOT-cav:crypto:home-unmap]´)
        unsafe { rustix::mm::munmap(self.pointer, self.len) }
    }
}

impl Drop for Home {
    /// Justified: Destruction erases in place before unlock and release without observing secret data.
    fn drop(&mut self) {
        // DONTFORK removes the mapping in a child. An inherited handle must not touch it.
        if self.process != std::process::id() {
            return;
        }
        if !self.pointer.is_null() {
            self.erase();
            #[cfg(test)]
            tests::observe_erased(self.bytes());
        }
        if self.locked {
            let _ = self.unlock();
        }
        let _ = self.unmap();
        RESERVED.fetch_sub(self.len, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests;
