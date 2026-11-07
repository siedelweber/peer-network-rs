use super::*;

static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
static OBSERVE_ERASE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static ERASED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub(super) static IDENTITY_CHECKS: AtomicUsize = AtomicUsize::new(0);

pub(super) fn observe_erased(bytes: &[u8]) {
    if OBSERVE_ERASE.swap(false, Ordering::SeqCst) {
        ERASED.store(bytes.iter().all(|byte| *byte == 0), Ordering::SeqCst);
    }
}

fn protection() -> Protection {
    Protection::establish(65_536).unwrap()
}

fn locked_kib() -> usize {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmLck:")
                .map(|v| v.split_whitespace().next().unwrap().parse().unwrap())
        })
        .unwrap()
}

/// The Linux mapping retains its address while the handle moves, reads back locked,
/// no-dump and no-fork flags, and erases every allocation byte before release.
/// ´claim:crypto:home-protections-and-erasure-are-observed´
/// ´test:unit:kernel-home´
#[test]
fn kernel_home() {
    let _serial = SERIAL.lock().unwrap();
    let protection = protection();
    verify_process().unwrap();
    let before = locked_kib();
    let mut input = [0xa5; 32];
    let mut home = protection.import(&mut Staging::acquire(&mut input)).unwrap();
    assert_eq!(input, [0; 32]);
    assert_eq!(&home.checked_bytes()[..32], &[0xa5; 32]);
    let address = home.pointer as usize;
    let mut handles = Vec::new();
    handles.push(home);
    let mut home = handles.pop().unwrap();
    assert_eq!(home.pointer as usize, address);
    assert!(locked_kib() >= before + home.len / 1024);
    let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
    let mut selected = false;
    let mut flags = None;
    for line in smaps.lines() {
        if let Some((start, rest)) = line.split_once('-')
            && let (Ok(start), Some(end)) = (usize::from_str_radix(start, 16), rest.split_whitespace().next())
            && let Ok(end) = usize::from_str_radix(end, 16)
        {
            selected = start <= address && address < end;
        }
        if selected && line.starts_with("VmFlags:") {
            flags = Some(line.to_owned());
            break;
        }
    }
    let flags = flags.unwrap();
    for flag in ["lo", "dd", "dc"] {
        assert!(flags.split_whitespace().any(|value| value == flag), "{flags}");
    }
    home.checked_bytes().fill(0x5a);
    ERASED.store(false, Ordering::SeqCst);
    OBSERVE_ERASE.store(true, Ordering::SeqCst);
    drop(home);
    assert!(ERASED.load(Ordering::SeqCst));
    assert_eq!(locked_kib(), before);
}

/// Partial entropy failure refuses and releases its mapping; imported staging is
/// erased even on a refused size, and the ordinary generator calls the OS source.
/// ´claim:crypto:home-acquisition-failures-erase-and-refuse´
/// ´test:unit:acquisition´
#[test]
fn acquisition() {
    let _serial = SERIAL.lock().unwrap();
    let protection = protection();
    let before = RESERVED.load(Ordering::SeqCst);
    let error = protection
        .generate_with(32, |bytes| {
            bytes.fill(0x5a);
            Err(Error::Entropy)
        })
        .unwrap_err();
    assert_eq!(error, Error::Entropy);
    assert_eq!(RESERVED.load(Ordering::SeqCst), before);
    let mut oversized = vec![0x5a; 65_537];
    assert_eq!(
        protection.import(&mut Staging::acquire(&mut oversized)).unwrap_err(),
        Error::Budget
    );
    assert!(oversized.iter().all(|byte| *byte == 0));
    assert_eq!(protection.generate(0).unwrap_err(), Error::Size);
    drop(protection.generate(32).unwrap());
    let full = protection.generate(65_536).unwrap();
    assert_eq!(protection.generate(1).unwrap_err(), Error::Budget);
    drop(full);
}

/// The secret mapping owner has neither Copy, Clone nor Display, and Debug is
/// constant across different imported bytes; process bootstrap diagnostics are constant too.
/// ´claim:crypto:home-has-no-implicit-secret-observation´
/// ´test:unit:ownership´
#[test]
fn ownership() {
    trait Ambiguous<A> {
        fn probe() {}
    }
    impl<T: ?Sized> Ambiguous<()> for T {}
    impl<T: Copy> Ambiguous<u8> for T {}
    impl<T: Clone> Ambiguous<u16> for T {}
    impl<T: ?Sized + std::fmt::Display> Ambiguous<u32> for T {}
    let _serial = SERIAL.lock().unwrap();
    let _ = <Home as Ambiguous<_>>::probe;
    let _ = <Staging<'_> as Ambiguous<_>>::probe;
    let protection = protection();
    for byte in [0x35, 0xd7] {
        let home = protection.import(&mut Staging::acquire(&mut [byte; 32])).unwrap();
        assert_eq!(format!("{home:?}"), "Home([REDACTED])");
    }
    assert_eq!(format!("{protection:?}"), "Protection");
}

/// Equal numeric PIDs do not identify a process across namespaces: a distinct held
/// namespace refuses acquisition and byte access, while the actual identity passes.
/// This finite kernel-handle control does not claim to execute a namespace fork.
/// ´claim:crypto:home-identity-includes-the-held-namespace´
/// ´test:unit:namespace-identity´
#[test]
fn namespace_identity() {
    if std::env::var_os("PN_HOME_TASK_CHILD").is_some() {
        use std::io::Read;
        let mut byte = [0];
        let _ = std::io::stdin().read(&mut byte).unwrap();
        return;
    }
    if std::env::var_os("PN_HOME_NAMESPACE_CHILD").is_none() {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "tests::namespace_identity", "--nocapture"])
            .env("PN_HOME_NAMESPACE_CHILD", "1")
            .output()
            .unwrap();
        assert!(result.status.success(), "{result:?}");
        return;
    }
    let _serial = SERIAL.lock().unwrap();
    let mut protection = protection();
    assert!(protection.process.is_current());
    let original = protection.process.share();
    // Keep a proc directory open across task death; it must not become a
    // liveness assertion for a later process reusing the numeric PID.
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "tests::namespace_identity", "--nocapture"])
        .env("PN_HOME_TASK_CHILD", "1")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let dead_task = Arc::new(std::fs::File::open(format!("/proc/{}", child.id())).unwrap());
    drop(child.stdin.take());
    assert!(child.wait().unwrap().success());
    protection.process.task = dead_task;
    assert_eq!(protection.process.pid, std::process::id());
    assert!(!protection.process.is_current());
    assert_eq!(protection.generate(32).unwrap_err(), Error::Process);
    protection.process = original.share();
    let other = Arc::new(std::fs::File::open("/proc/self/ns/mnt").unwrap());
    let a = original.namespace.metadata().unwrap();
    let b = other.metadata().unwrap();
    assert_ne!((a.dev(), a.ino()), (b.dev(), b.ino()));
    protection.process.namespace = Arc::clone(&other);
    assert_eq!(protection.process.pid, std::process::id());
    assert!(!protection.process.is_current());
    assert_eq!(protection.generate(32).unwrap_err(), Error::Process);
    protection.process = original;
    let mut home = protection.generate(32).unwrap();
    let original = home.process.share();
    home.process.namespace = Arc::clone(&other);
    assert_eq!(home.process.pid, std::process::id());
    assert!(!home.process.is_current());
    let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = home.checked_bytes();
    }));
    home.process = original;
    assert!(refused.is_err());
    assert!(home.process.is_current());
    let reserved = RESERVED.load(Ordering::SeqCst);
    let locked = locked_kib();
    home.process.namespace = other;
    ERASED.store(false, Ordering::SeqCst);
    OBSERVE_ERASE.store(true, Ordering::SeqCst);
    drop(home);
    assert!(!ERASED.load(Ordering::SeqCst));
    assert_eq!(RESERVED.load(Ordering::SeqCst), reserved);
    assert_eq!(locked_kib(), locked);
    // This isolated child exits with the deliberately untouched mapping: no second
    // owner is manufactured to reclaim it and no test reads released memory.
}

/// Neither shared nor mutable dereferencing can expose the home's bytes implicitly.
/// ´claim:crypto:home-has-no-deref-surface´
/// ´test:unit:no-deref´
#[test]
fn no_deref() {
    trait Ambiguous<A> {
        fn probe() {}
    }
    impl<T: ?Sized> Ambiguous<()> for T {}
    impl<T: ?Sized + std::ops::Deref> Ambiguous<u8> for T {}
    impl<T: ?Sized + std::ops::DerefMut> Ambiguous<u16> for T {}
    let _ = <Home as Ambiguous<_>>::probe;
}

/// Descriptor exhaustion in an isolated owning process cannot prevent one-check
/// destruction from erasing the full mapping, releasing it and its reservation.
/// ´claim:crypto:home-drop-survives-descriptor-exhaustion´
/// ´test:unit:descriptor-exhaustion´
#[test]
fn descriptor_exhaustion() {
    if std::env::var_os("PN_HOME_DESCRIPTOR_CHILD").is_none() {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "tests::descriptor_exhaustion", "--nocapture"])
            .env("PN_HOME_DESCRIPTOR_CHILD", "1")
            .output()
            .unwrap();
        assert!(result.status.success(), "{result:?}");
        return;
    }
    let _serial = SERIAL.lock().unwrap();
    let protection = protection();
    let reserved = RESERVED.load(Ordering::SeqCst);
    let locked = locked_kib();
    let mut home = protection.generate(32).unwrap();
    home.checked_bytes().fill(0xa5);
    // read_dir temporarily opens one descriptor; retain the actual live set only.
    let open: Vec<_> = std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_str().unwrap().parse::<u64>().unwrap())
        .collect();
    let limit = open.into_iter().max().unwrap();
    let original = rustix::process::getrlimit(Resource::Nofile);
    rustix::process::setrlimit(
        Resource::Nofile,
        Rlimit {
            current: Some(limit),
            maximum: original.maximum,
        },
    )
    .unwrap();
    // Fill any holes below that limit; no descriptor at or above it can be opened.
    let mut fillers = Vec::new();
    let refused = loop {
        match std::fs::File::open("/dev/null") {
            Ok(file) => fillers.push(file),
            Err(error) => break error,
        }
    };
    assert_eq!(refused.raw_os_error(), Some(rustix::io::Errno::MFILE.raw_os_error()));
    assert!(protection.process.is_current());
    ERASED.store(false, Ordering::SeqCst);
    OBSERVE_ERASE.store(true, Ordering::SeqCst);
    let checks = IDENTITY_CHECKS.load(Ordering::SeqCst);
    drop(home);
    assert_eq!(IDENTITY_CHECKS.load(Ordering::SeqCst), checks + 1);
    assert!(ERASED.load(Ordering::SeqCst));
    assert_eq!(RESERVED.load(Ordering::SeqCst), reserved);
    rustix::process::setrlimit(Resource::Nofile, original).unwrap();
    drop(fillers);
    assert_eq!(locked_kib(), locked);
}

/// A foreign PID with unchanged namespace and task handles refuses access and
/// destruction; this isolates the same-namespace fork guard without executing fork.
/// ´claim:crypto:home-foreign-pid-never-touches-mapping´
/// ´test:unit:foreign-pid´
#[test]
fn foreign_pid() {
    if std::env::var_os("PN_HOME_FOREIGN_CHILD").is_none() {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "tests::foreign_pid", "--nocapture"])
            .env("PN_HOME_FOREIGN_CHILD", "1")
            .output()
            .unwrap();
        assert!(result.status.success(), "{result:?}");
        return;
    }
    let _serial = SERIAL.lock().unwrap();
    let mut protection = protection();
    let mut home = protection.generate(32).unwrap();
    let reserved = RESERVED.load(Ordering::SeqCst);
    let locked = locked_kib();
    protection.process.pid ^= 1;
    assert_eq!(protection.generate(32).unwrap_err(), Error::Process);
    home.process.pid ^= 1;
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = home.checked_bytes();
        }))
        .is_err()
    );
    ERASED.store(false, Ordering::SeqCst);
    OBSERVE_ERASE.store(true, Ordering::SeqCst);
    let checks = IDENTITY_CHECKS.load(Ordering::SeqCst);
    drop(home);
    assert_eq!(IDENTITY_CHECKS.load(Ordering::SeqCst), checks + 1);
    assert!(!ERASED.load(Ordering::SeqCst));
    assert_eq!(RESERVED.load(Ordering::SeqCst), reserved);
    assert_eq!(locked_kib(), locked);
}
