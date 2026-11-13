use super::*;

static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
static OBSERVE_ERASE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static ERASED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub(super) static IDENTITY_CHECKS: AtomicUsize = AtomicUsize::new(0);

pub(super) fn observe_erased(bytes: &[u8]) {
    FAULT.with_borrow_mut(|state| {
        if state.active {
            state.events.push("erase");
            state.erased = bytes.iter().all(|byte| *byte == 0);
        }
    });
    if OBSERVE_ERASE.swap(false, Ordering::SeqCst) {
        ERASED.store(bytes.iter().all(|byte| *byte == 0), Ordering::SeqCst);
    }
}

#[derive(Default)]
enum FaultKind {
    #[default]
    None,
    Ownership,
    Advice,
    Unlock,
    Unmap,
    Both,
}

#[derive(Default)]
struct Fault {
    active: bool,
    kind: FaultKind,
    released: bool,
    erased: bool,
    retained: Option<(bool, bool)>,
    events: Vec<&'static str>,
}

thread_local! {
    static FAULT: std::cell::RefCell<Fault> = std::cell::RefCell::default();
}

pub(super) fn refuse_ownership() -> bool {
    FAULT.with_borrow(|state| matches!(state.kind, FaultKind::Ownership))
}

pub(super) fn refuse_advice() -> bool {
    FAULT.with_borrow(|state| matches!(state.kind, FaultKind::Advice))
}

pub(super) fn before_unlock() -> Option<Result<(), rustix::io::Errno>> {
    FAULT.with_borrow_mut(|state| {
        if state.active {
            state.events.push("unlock");
        }
        matches!(state.kind, FaultKind::Unlock | FaultKind::Both).then_some(Err(rustix::io::Errno::IO))
    })
}

pub(super) fn before_unmap() -> Option<Result<(), rustix::io::Errno>> {
    FAULT.with_borrow_mut(|state| {
        if state.active {
            state.events.push("unmap");
        }
        if state.released {
            // Observe a mutant's duplicate call without actually unmapping twice.
            Some(Ok(()))
        } else {
            matches!(state.kind, FaultKind::Unmap | FaultKind::Both).then_some(Err(rustix::io::Errno::IO))
        }
    })
}

pub(super) fn released() {
    FAULT.with_borrow_mut(|state| state.released = state.active);
}

pub(super) fn observe_retained(bytes: &[u8]) {
    FAULT.with_borrow_mut(|state| {
        state.retained = Some((bytes.iter().all(|byte| *byte == 0), bytes.iter().all(|byte| *byte == 0x5a)));
    });
}

fn child_case(test: &str, cases: &[&str]) -> Option<String> {
    if let Ok(case) = std::env::var("PN_HOME_COMPLETION_CASE") {
        return Some(case);
    }
    for case in cases {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture"])
            .env("PN_HOME_COMPLETION_CASE", case)
            .output()
            .unwrap();
        assert!(result.status.success(), "completion child {case}: {result:?}");
    }
    None
}

fn set_fault(case: &str) {
    FAULT.with_borrow_mut(|state| {
        *state = Fault {
            active: true,
            kind: match case {
                "ownership" => FaultKind::Ownership,
                "advice" => FaultKind::Advice,
                "unlock" => FaultKind::Unlock,
                "unmap" => FaultKind::Unmap,
                "both" => FaultKind::Both,
                _ => FaultKind::None,
            },
            ..Fault::default()
        };
    });
}

fn present(address: usize) -> bool {
    std::fs::read_to_string("/proc/self/maps").unwrap().lines().any(|line| {
        let range = line.split_whitespace().next().unwrap();
        let (first, last) = range.split_once('-').unwrap();
        let first = usize::from_str_radix(first, 16).unwrap();
        let last = usize::from_str_radix(last, 16).unwrap();
        first <= address && address < last
    })
}

/// Consuming completion checks ownership before bytes, erases a full page before
/// cleanup, returns each injected cleanup failure and retains failed live reservations.
/// An advice refusal during acquisition also releases its zero-initialized page.
/// These finite Linux and injected results do not establish installed sandbox behavior.
/// ´claim:crypto:home-completion-orders-erasure-and-confirms-release´
/// ´test:unit:completion-controls´
#[test]
fn completion_controls() {
    let Some(case) = child_case(
        "tests::completion_controls",
        &["ok", "ownership", "unlock", "unmap", "both", "advice"],
    ) else {
        return;
    };
    let _serial = SERIAL.lock().unwrap();
    let protection = protection();
    let reserved = RESERVED.load(Ordering::SeqCst);
    let locked = locked_kib();
    if case == "advice" {
        set_fault(&case);
        let mut filled = false;
        let result = protection.generate_with(32, |_| {
            filled = true;
            Ok(())
        });
        assert_eq!(result.unwrap_err(), Error::Advice, "advice refusal");
        assert!(!filled, "protection precedes filling");
        assert_eq!(RESERVED.load(Ordering::SeqCst), reserved, "advice reservation");
        FAULT.with_borrow(|state| {
            assert!(state.erased, "advice allocation erased");
            assert_eq!(state.events, ["erase", "unmap"], "advice release order");
        });
        return;
    }
    let mut home = protection.generate(32).unwrap();
    home.checked_bytes().unwrap().fill(0x5a);
    let address = home.pointer as usize;
    let len = home.len;
    assert_eq!(len, protection.page, "one-page allocation");
    assert_eq!(RESERVED.load(Ordering::SeqCst), reserved + len, "mapped reservation");
    assert_eq!(locked_kib(), locked + len / 1024, "locked allocation");
    set_fault(&case);
    let result = home.complete();
    let expected = match case.as_str() {
        "ownership" => Err(CompletionError::Ownership),
        "unlock" => Err(CompletionError::Cleanup {
            unlock: true,
            unmap: false,
        }),
        "unmap" => Err(CompletionError::Cleanup {
            unlock: false,
            unmap: true,
        }),
        "both" => Err(CompletionError::Cleanup {
            unlock: true,
            unmap: true,
        }),
        _ => Ok(()),
    };
    assert_eq!(result, expected, "completion outcome {case}");
    let live = matches!(case.as_str(), "ownership" | "unmap" | "both");
    assert_eq!(present(address), live, "mapping retention {case}");
    assert_eq!(
        RESERVED.load(Ordering::SeqCst),
        reserved + if live { len } else { 0 },
        "reservation retention {case}"
    );
    let still_locked = matches!(case.as_str(), "ownership" | "both");
    assert_eq!(
        locked_kib(),
        locked + if still_locked { len / 1024 } else { 0 },
        "lock accounting {case}"
    );
    FAULT.with_borrow(|state| {
        if case == "ownership" {
            assert!(state.events.is_empty(), "ownership refusal touches no mapping operation");
            assert_eq!(state.retained, Some((false, true)), "ownership mapping untouched");
        } else {
            assert!(state.erased, "full allocation erased before release");
            assert_eq!(state.events, ["erase", "unlock", "unmap"], "one ordered release attempt");
            if live {
                assert_eq!(
                    state.retained,
                    Some((true, false)),
                    "failed release retains only erased bytes"
                );
            }
        }
    });
    // Deliberately retained mappings end with this isolated child, without another owner.
}

/// Repeated internal completion and subsequent consuming completion return the
/// cached result; successful and failed release each perform one syscall attempt
/// and change reservations only after confirmed unmap.
/// ´claim:crypto:home-completion-never-releases-twice´
/// ´test:unit:completion-repeat´
#[test]
fn completion_repeat() {
    let Some(case) = child_case("tests::completion_repeat", &["ok", "unmap"]) else {
        return;
    };
    let _serial = SERIAL.lock().unwrap();
    let protection = protection();
    let reserved = RESERVED.load(Ordering::SeqCst);
    let mut home = protection.generate(32).unwrap();
    home.checked_bytes().unwrap().fill(0x5a);
    let len = home.len;
    set_fault(&case);
    let first = home.finish();
    assert_eq!(home.finish(), first, "repeat result");
    assert_eq!(home.complete(), first, "consuming repeat result");
    FAULT.with_borrow(|state| assert_eq!(state.events, ["erase", "unlock", "unmap"], "no duplicate release"));
    assert_eq!(
        RESERVED.load(Ordering::SeqCst),
        reserved + if case == "unmap" { len } else { 0 },
        "one reservation release"
    );
}

struct Trace(Arc<std::sync::Mutex<String>>);
struct Fields<'a>(&'a mut String);
impl tracing::field::Visit for Fields<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write;
        writeln!(self.0, "{field}={value:?}").unwrap();
    }
}
impl tracing::Subscriber for Trace {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        attrs.record(&mut Fields(&mut self.0.lock().unwrap()));
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, values: &tracing::span::Record<'_>) {
        values.record(&mut Fields(&mut self.0.lock().unwrap()));
    }
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        event.record(&mut Fields(&mut self.0.lock().unwrap()));
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// Completion errors expose only public classes through Debug, Display, source
/// and a real tracing subscriber for the consuming operation with a private sentinel.
/// ´claim:crypto:home-completion-errors-contain-no-private-bytes´
/// ´test:unit:completion-diagnostics´
#[test]
fn completion_diagnostics() {
    let Some(case) = child_case("tests::completion_diagnostics", &["diagnostics", "ownership"]) else {
        return;
    };
    let _serial = SERIAL.lock().unwrap();
    let protection = protection();
    let mut home = protection.generate(32).unwrap();
    home.checked_bytes().unwrap()[..24].copy_from_slice(b"private-completion-value");
    set_fault(if case == "ownership" { "ownership" } else { "both" });
    let trace = Arc::new(std::sync::Mutex::new(String::new()));
    let error = tracing::subscriber::with_default(Trace(Arc::clone(&trace)), || home.complete().unwrap_err());
    let (display, debug) = if case == "ownership" {
        ("home ownership unconfirmed", "Ownership")
    } else {
        ("home cleanup unconfirmed", "Cleanup { unlock: true, unmap: true }")
    };
    assert_eq!(format!("{error}"), display, "content-free Display");
    assert_eq!(format!("{error:?}"), debug, "content-free Debug");
    assert!(std::error::Error::source(&error).is_none(), "no private error source");
    let trace = trace.lock().unwrap();
    assert!(
        trace.contains("Home::complete") && trace.contains(debug),
        "completion trace observed"
    );
    assert!(!trace.contains("private-completion-value"), "content-free trace");
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
    assert_eq!(&home.checked_bytes().unwrap()[..32], &[0xa5; 32]);
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
    home.checked_bytes().unwrap().fill(0x5a);
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
    assert_eq!(home.checked_bytes().unwrap_err(), Error::Process);
    home.process = original;
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
    home.checked_bytes().unwrap().fill(0xa5);
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
    assert_eq!(home.checked_bytes().unwrap_err(), Error::Process);
    ERASED.store(false, Ordering::SeqCst);
    OBSERVE_ERASE.store(true, Ordering::SeqCst);
    let checks = IDENTITY_CHECKS.load(Ordering::SeqCst);
    drop(home);
    assert_eq!(IDENTITY_CHECKS.load(Ordering::SeqCst), checks + 1);
    assert!(!ERASED.load(Ordering::SeqCst));
    assert_eq!(RESERVED.load(Ordering::SeqCst), reserved);
    assert_eq!(locked_kib(), locked);
}
