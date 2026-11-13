//! A private owning mapping; no byte export or signing operation is admitted.
//! (´[ROOT-amend:crypto:secret-home]´)
#![deny(unsafe_op_in_unsafe_fn)]

use rustix::mm::{Advice, MapFlags, ProtFlags};
use rustix::process::{DumpableBehavior, Resource, Rlimit};
use std::ffi::c_void;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
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

// A held namespace descriptor prevents namespace inode reuse while an owner exists.
struct ProcessIdentity {
    pid: u32,
    namespace: Arc<std::fs::File>,
    task: Arc<std::fs::File>,
}

impl ProcessIdentity {
    fn acquire() -> Result<Self, Error> {
        Ok(Self {
            pid: std::process::id(),
            namespace: Arc::new(std::fs::File::open("/proc/self/ns/pid").map_err(|_| Error::Process)?),
            task: Arc::new(std::fs::File::open("/proc/self").map_err(|_| Error::Process)?),
        })
    }

    fn share(&self) -> Self {
        Self {
            pid: self.pid,
            namespace: Arc::clone(&self.namespace),
            task: Arc::clone(&self.task),
        }
    }

    fn is_current(&self) -> bool {
        #[cfg(test)]
        tests::IDENTITY_CHECKS.fetch_add(1, Ordering::SeqCst);
        if self.pid != std::process::id() {
            return false;
        }
        let Ok(held) = self.namespace.metadata() else {
            return false;
        };
        let Ok(current) = std::fs::metadata("/proc/self/ns/pid") else {
            return false;
        };
        if (held.dev(), held.ino()) != (current.dev(), current.ino()) {
            return false;
        }
        // Resolve through the retained proc directory, not a reusable PID path.
        // A fresh lookup cannot reuse a buffered proc read after the task exits.
        std::fs::metadata(format!("/proc/self/fd/{}/stat", self.task.as_raw_fd())).is_ok()
    }
}

/// Process-start protection and the declared total mapping budget.
/// (´[ROOT-amend:crypto:secret-home]´)
pub struct Protection {
    page: usize,
    budget: usize,
    process: ProcessIdentity,
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
            process: ProcessIdentity::acquire()?,
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
        if !self.process.is_current() {
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
        let mut home = match Home::map(len, self.process.share()) {
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
        fill(&mut home.checked_bytes()?[..size])?;
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
    process: ProcessIdentity,
    locked: bool,
    released: bool,
    completion: Option<Result<(), CompletionError>>,
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
    fn map(len: usize, process: ProcessIdentity) -> Result<Self, Error> {
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
            released: false,
            completion: None,
        })
    }

    // Justified: Only the owned complete mapping receives fork and dump exclusion advice.
    #[expect(unsafe_code, reason = "owned mapping advice")]
    fn protect(&mut self) -> Result<(), Error> {
        #[cfg(test)]
        if tests::refuse_advice() {
            return Err(Error::Advice);
        }
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

    // Justified: Operations require a live allocation and establish process identity before borrowing private mapping bytes.
    fn checked_bytes(&mut self) -> Result<&mut [u8], Error> {
        if self.released {
            return Err(Error::Mapping);
        }
        let current = self.process.is_current();
        #[cfg(test)]
        let current = current && !tests::refuse_ownership();
        if !current {
            return Err(Error::Process);
        }
        Ok(self.bytes())
    }

    // Justified: The sole private byte view lends the owned initialized mapping after the caller's identity check.
    #[expect(unsafe_code, reason = "exclusive owned mapping bytes")]
    fn bytes(&mut self) -> &mut [u8] {
        assert!(!self.pointer.is_null());
        // SAFETY: checked_bytes or Drop established this process as the owner before this private call, with no intervening fork or mapping invalidation. This owner's non-null live readable/writable anonymous mapping is zero-initialized. Its original length is within one allocation and isize::MAX. The exclusive self borrow bounds the slice lifetime and excludes other accesses; release requires that borrow to end.
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
        #[cfg(test)]
        if let Some(result) = tests::before_unlock() {
            return result;
        }
        // SAFETY: This single owner still holds the live page-aligned mapping and its original full length; all byte borrows have ended and the mapping has not been released.
        // (´[ROOT-cav:crypto:home-unlock]´)
        unsafe { rustix::mm::munlock(self.pointer, self.len) }
    }

    // Justified: Release only the original owned mapping after erasure, with no surviving byte references.
    #[expect(unsafe_code, reason = "owned mapping release")]
    fn unmap(&mut self) -> Result<(), rustix::io::Errno> {
        #[cfg(test)]
        if let Some(result) = tests::before_unmap() {
            return result;
        }
        // SAFETY: This single owner releases its original page-aligned mapping and full length exactly once; no Rust reference survives and no later operation uses the pointer.
        // (´[ROOT-cav:crypto:home-unmap]´)
        unsafe { rustix::mm::munmap(self.pointer, self.len) }
    }
}

impl Drop for Home {
    /// Justified: Destruction erases in place before unlock and release without observing secret data.
    fn drop(&mut self) {
        if self.completion.is_some() {
            #[cfg(test)]
            if !self.released && self.process.is_current() {
                tests::observe_retained(self.bytes());
            }
            return;
        }
        // DONTFORK removes the mapping in a child. An inherited handle must not touch it.
        if self.released || !self.process.is_current() {
            return;
        }
        if !self.pointer.is_null() {
            self.erase();
            #[cfg(test)]
            tests::observe_erased(self.bytes());
        }
        let _ = self.release();
    }
}

#[cfg(test)]
mod tests;

/// Content-free completion failure; both cleanup results remain distinguishable.
/// (´[ROOT-amend:crypto:secret-home]´)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionError {
    Ownership,
    Cleanup { unlock: bool, unmap: bool },
}

impl std::fmt::Display for CompletionError {
    /// Justified: Completion diagnostics format only a fixed public failure class.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Ownership => "home ownership unconfirmed",
            Self::Cleanup { .. } => "home cleanup unconfirmed",
        })
    }
}

impl std::error::Error for CompletionError {}

impl Home {
    /// Consume the home and confirm erasure, unlock and release, without exporting bytes.
    /// A refused attempt is not retried by Drop; its unreleased mapping remains reserved.
    /// (´[ROOT-amend:crypto:secret-home]´)
    /// # Errors
    /// Returns ownership refusal before byte access, or both unconfirmed cleanup flags.
    #[tracing::instrument(
        name = "amend:crypto:secret-home",
        fields(
            execution_owner = "SECRETHOME",
            claim_owner = "ROOT",
            claim_label = "amend:crypto:secret-home",
            source_item = "Home::complete"
        ),
        ret
    )]
    pub fn complete(mut self) -> Result<(), CompletionError> {
        self.finish()
    }

    // Justified: Cache the content-free result so consuming completion and fallback destruction never repeat an attempt.
    fn finish(&mut self) -> Result<(), CompletionError> {
        if let Some(result) = self.completion {
            return result;
        }
        let result = self.finish_once();
        self.completion = Some(result);
        result
    }

    // Justified: The checked slice establishes ownership once and erases the entire allocation without exporting it.
    fn finish_once(&mut self) -> Result<(), CompletionError> {
        let bytes = self.checked_bytes().map_err(|_| CompletionError::Ownership)?;
        bytes.zeroize();
        #[cfg(test)]
        tests::observe_erased(bytes);
        self.release()
    }

    // Justified: Cleanup follows erasure; only successful unmapping releases the allocation reservation.
    fn release(&mut self) -> Result<(), CompletionError> {
        if self.released {
            return Ok(());
        }
        let unlock = self.locked && self.unlock().is_err();
        if !unlock {
            self.locked = false;
        }
        let unmap = self.unmap().is_err();
        if !unmap {
            self.released = true;
            self.locked = false;
            RESERVED.fetch_sub(self.len, Ordering::SeqCst);
            #[cfg(test)]
            tests::released();
        }
        if unlock || unmap {
            Err(CompletionError::Cleanup { unlock, unmap })
        } else {
            Ok(())
        }
    }
}
