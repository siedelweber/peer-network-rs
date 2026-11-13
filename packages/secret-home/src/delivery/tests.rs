use super::*;

struct Filter(std::path::PathBuf);

impl Filter {
    fn new(case: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "receiver-filter-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir(&path).unwrap();
        let filter = Self(path);
        // The supported target is x86_64 Linux. The public filter reads only the
        // syscall number and refuses these calls; every other call is allowed.
        let mut instructions = vec![(0x20_u16, 0_u8, 0_u8, 0_u32)];
        for number in if case == "deny-open" { &[434, 438][..] } else { &[438][..] } {
            instructions.push((0x15, 0, 1, *number));
            instructions.push((0x06, 0, 0, 0x0005_0001));
        }
        instructions.push((0x06, 0, 0, 0x7fff_0000));
        let mut bytes = Vec::new();
        for (code, yes, no, value) in instructions {
            bytes.extend_from_slice(&code.to_ne_bytes());
            bytes.extend_from_slice(&[yes, no]);
            bytes.extend_from_slice(&value.to_ne_bytes());
        }
        std::fs::write(filter.0.join("filter"), bytes).unwrap();
        filter
    }
}

impl Drop for Filter {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.0));
    }
}

static WRITE_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

pub(super) fn write_outcome(file: &mut File, bytes: &[u8]) -> Option<std::io::Result<usize>> {
    let case = std::env::var("PN_HOME_WRITE_CASE").ok()?;
    let call = WRITE_CALLS.fetch_add(1, Ordering::SeqCst);
    Some(match call {
        0 => Err(std::io::Error::from(ErrorKind::Interrupted)),
        1 => file.write(&bytes[..7]),
        2 if case == "zero" => Ok(0),
        2 if case == "error" => Err(std::io::Error::from(ErrorKind::Other)),
        _ => file.write(bytes),
    })
}

/// Interrupted writes retry, short writes advance exactly once, and terminal
/// refusals retain the accepted prefix. The seam changes outcomes, never source bytes.
/// ´claim:crypto:protected-delivery-accounts-every-write-outcome´
/// ´test:unit:write-outcomes´
#[test]
fn write_outcomes() {
    use std::io::Read;
    if let Ok(case) = std::env::var("PN_HOME_WRITE_CASE") {
        let protection = crate::Protection::establish(2 * crate::page_size().unwrap()).unwrap();
        let vector = crate::tests::delivery_vector();
        let mut credential = crate::tests::fixture_credential(&protection, vector).unwrap();
        let (mut reader, output) = pipe_files();
        let result = credential.deliver_password(PasswordReceiver(output));
        let length = match case.as_str() {
            "short" => {
                assert_eq!(result, Ok(64), "interrupted and short writes preserve full delivery");
                64
            }
            "zero" | "error" => {
                assert_eq!(
                    result,
                    Err(DeliveryError {
                        accepted: 7,
                        kind: if case == "zero" {
                            DeliveryFailure::ZeroProgress
                        } else {
                            DeliveryFailure::Write
                        }
                    }),
                    "partial failure reports exactly the accepted prefix"
                );
                7
            }
            _ => panic!("closed write fixture"),
        };
        let mut received = Vec::new();
        reader.read_to_end(&mut received).unwrap();
        assert_eq!(received, vector.password[..length], "the kernel receives no repeated prefix");
        assert_eq!(WRITE_CALLS.load(Ordering::SeqCst), 3, "every write result checked");
        assert_eq!(credential.complete(), Ok(()), "completion after every delivery outcome");
        return;
    }
    for case in ["short", "zero", "error"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "delivery::tests::write_outcomes", "--nocapture"])
            .env("PN_HOME_WRITE_CASE", case)
            .output()
            .unwrap();
        assert!(output.status.success(), "write outcome {case}: {output:?}");
    }
}

fn pipe_files() -> (std::io::PipeReader, File) {
    let (reader, writer) = std::io::pipe().unwrap();
    (reader, File::from(OwnedFd::from(writer)))
}

/// Real protected fixture reads reach the delivery failure and trace boundary;
/// no fixture bytes occur in Debug, Display, the source chain or recorded fields.
/// ´claim:crypto:delivery-errors-and-traces-contain-no-private-bytes´
/// ´test:unit:diagnostics´
#[test]
fn diagnostics() {
    let Some(_) = crate::tests::child_case("delivery::tests::diagnostics", &["private"]) else {
        return;
    };
    let protection = crate::Protection::for_credential().unwrap();
    assert_eq!(
        protection.budget,
        2 * protection.page,
        "credential bootstrap admits exactly two pages"
    );
    let vector = crate::tests::delivery_vector();
    let mut credential = crate::tests::fixture_credential(&protection, vector).unwrap();
    let (reader, writer) = pipe_files();
    drop(reader);
    let trace = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let error = tracing::subscriber::with_default(crate::tests::Trace(std::sync::Arc::clone(&trace)), || {
        credential.deliver_password(PasswordReceiver(writer)).unwrap_err()
    });
    assert_eq!(
        format!("{error:?}"),
        "DeliveryError { accepted: 0, kind: ClosedReader }",
        "closed diagnostic vocabulary"
    );
    assert_eq!(error.to_string(), "credential delivery refused", "constant diagnostic");
    assert!(std::error::Error::source(&error).is_none(), "no private dependency source");
    let trace = trace.lock().unwrap();
    assert!(trace.contains("deliver_password"), "delivery trace observed");
    for private in [vector.password, vector.verifier] {
        assert!(
            !trace.contains(std::str::from_utf8(private).unwrap()),
            "no private text in delivery trace"
        );
        assert!(
            !trace.contains(&format!("{private:?}")),
            "no private byte list in delivery trace"
        );
    }
    assert_eq!(credential.complete(), Ok(()), "completion after diagnostic refusal");
}

/// Separate processes exercise ordered startup refusals and the irreversible
/// latch. An unprivileged filter supplies actual denied syscall results.
/// ´claim:crypto:receiver-acquisition-refuses-before-protection´
/// ´test:unit:protocol´
#[test]
fn protocol() {
    if let Ok(case) = std::env::var("PN_HOME_RECEIVER_CASE") {
        let result = acquire_receivers();
        if matches!(case.as_str(), "valid" | "reverse") {
            let (password, verifier) = result.expect("real kernel acquisition accepts valid named pipe roster");
            let first = std::fs::metadata("/proc/self/fd/3").unwrap().ino();
            let second = std::fs::metadata("/proc/self/fd/4").unwrap().ino();
            let expected = if case == "valid" { (first, second) } else { (second, first) };
            assert_eq!(
                (password.0.metadata().unwrap().ino(), verifier.0.metadata().unwrap().ino()),
                expected,
                "names bind both role orders"
            );
            assert_eq!(
                acquire_receivers().unwrap_err(),
                AcquisitionError::InvalidConvention,
                "success consumes the process latch"
            );
            return;
        }
        let expected = match case.as_str() {
            "address" | "absent" | "few" | "slot" | "missing-second" => AcquisitionError::Missing,
            "count" | "overflow" | "identity" => AcquisitionError::InvalidConvention,
            "extra" => AcquisitionError::Additional,
            "names" | "repeat-name" => AcquisitionError::NameMismatch,
            "deny-open" | "deny-duplicate" | "limit" => AcquisitionError::Unavailable,
            "same-pipe" | "read-end" | "regular" => AcquisitionError::ReceiverInvalid,
            _ => panic!("closed fixture cases"),
        };
        assert_eq!(result.unwrap_err(), expected, "ordered startup refusal {case}");
        assert_eq!(
            acquire_receivers().unwrap_err(),
            AcquisitionError::InvalidConvention,
            "refusal consumes the process latch"
        );
        assert!(crate::BUDGET.get().is_none(), "acquisition precedes protection");
        assert_eq!(
            crate::RESERVED.load(Ordering::SeqCst),
            0,
            "refusal precedes entropy and allocation"
        );
        return;
    }
    let launcher = protocol_launcher();
    for case in [
        "address",
        "absent",
        "few",
        "count",
        "overflow",
        "extra",
        "names",
        "repeat-name",
        "slot",
        "deny-open",
        "deny-duplicate",
        "valid",
        "reverse",
        "identity",
        "same-pipe",
        "read-end",
        "regular",
        "missing-second",
        "limit",
    ] {
        let filter = matches!(case, "deny-open" | "deny-duplicate").then(|| Filter::new(case));
        let mut command = if let Some(filter) = &filter {
            let mut command = std::process::Command::new("setpriv");
            command
                .args(["--no-new-privs", "--seccomp-filter"])
                .arg(filter.0.join("filter"))
                .arg("python3");
            command
        } else {
            std::process::Command::new("python3")
        };
        let output = command
            .args(["-c", launcher, case])
            .arg(std::env::current_exe().unwrap())
            .output()
            .unwrap();
        assert!(output.status.success(), "protocol child {case}: {output:?}");
    }
}

/// The pinned runtime restores closed standard streams before the test entry;
/// this finite process control does not assume anything about passed slots three and four.
/// ´claim:crypto:closed-standard-streams-are-restored-before-acquisition´
/// ´test:unit:closed-standard-streams´
#[test]
fn closed_standard_streams() {
    if std::env::var_os("PN_HOME_CLOSED_STANDARD_CHILD").is_some() {
        for fd in 0..=2 {
            assert!(
                std::fs::metadata(format!("/proc/self/fd/{fd}"))
                    .unwrap()
                    .file_type()
                    .is_char_device(),
                "runtime restores closed public stream"
            );
        }
        return;
    }
    let launcher = r"
import os,sys
os.environ['PN_HOME_CLOSED_STANDARD_CHILD']='1'
for fd in (0,1,2): os.close(fd)
os.execv(sys.argv[1],[sys.argv[1],'--exact','delivery::tests::closed_standard_streams','--nocapture'])
";
    let output = std::process::Command::new("python3")
        .args(["-c", launcher])
        .arg(std::env::current_exe().unwrap())
        .output()
        .unwrap();
    assert!(output.status.success(), "closed standard streams child: {output:?}");
}

/// Finite public metadata and pipe fixtures distinguish malformed counts and
/// wrong receivers; no deployment wiring or process-handle availability is inferred.
/// ´claim:crypto:named-receiver-validation-is-closed´
/// ´test:unit:validation´
#[test]
fn validation() {
    for value in ["", "-1", "+2", " 2", "18446744073709551616"] {
        assert_eq!(
            decimal(value.as_ref()),
            Err(AcquisitionError::InvalidConvention),
            "invalid count {value}"
        );
    }
    assert_eq!(decimal("2".as_ref()), Ok(2), "exact count");
    let (_a, mut a) = pipe_files();
    let (_b, mut b) = pipe_files();
    assert_eq!(validate(&mut a, &mut b), Ok(()), "two distinct writable pipes");
    let mut same = a.try_clone().unwrap();
    assert_eq!(
        validate(&mut a, &mut same),
        Err(AcquisitionError::ReceiverInvalid),
        "one pipe cannot carry both roles"
    );
    let (reader, _writer) = std::io::pipe().unwrap();
    let mut read_end = File::from(OwnedFd::from(reader));
    assert_eq!(
        validate(&mut a, &mut read_end),
        Err(AcquisitionError::ReceiverInvalid),
        "read end refuses"
    );
    let mut regular = File::open(std::env::current_exe().unwrap()).unwrap();
    assert_eq!(
        validate(&mut a, &mut regular),
        Err(AcquisitionError::ReceiverInvalid),
        "non-pipe refuses"
    );
}

/// A real protected fixture delivers its password and verifier to separate
/// owned pipes, with independent expected bytes; both homes then complete.
/// ´claim:crypto:typed-deliveries-preserve-the-two-protected-frames´
/// ´test:unit:protected-delivery´
#[test]
fn protected_delivery() {
    use std::io::Read;
    let Some(_) = crate::tests::child_case("delivery::tests::protected_delivery", &["delivery"]) else {
        return;
    };
    let protection = crate::Protection::establish(2 * crate::page_size().unwrap()).unwrap();
    let vector = crate::tests::delivery_vector();
    let mut credential = crate::tests::fixture_credential(&protection, vector).unwrap();
    let (mut password, password_out) = pipe_files();
    let (mut verifier, verifier_out) = pipe_files();
    assert_eq!(
        credential.deliver_password(PasswordReceiver(password_out)),
        Ok(64),
        "password delivered once"
    );
    assert_eq!(
        credential.deliver_verifier(VerifierReceiver(verifier_out)),
        Ok(135),
        "verifier delivered once"
    );
    assert_eq!(credential.complete(), Ok(()), "both homes completed");
    let mut p = Vec::new();
    let mut v = Vec::new();
    password.read_to_end(&mut p).unwrap();
    verifier.read_to_end(&mut v).unwrap();
    assert_eq!(p, vector.password, "password receiver has independent public fixture");
    assert_eq!(v, vector.verifier, "verifier receiver has independent public fixture");
}

/// A closed pipe reader yields a typed content-free failure with no accepted
/// bytes; the other role remains independently deliverable and both homes complete.
/// ´claim:crypto:delivery-refusal-retains-independent-completion´
/// ´test:unit:closed-reader´
#[test]
fn closed_reader() {
    let Some(_) = crate::tests::child_case("delivery::tests::closed_reader", &["closed"]) else {
        return;
    };
    let protection = crate::Protection::establish(2 * crate::page_size().unwrap()).unwrap();
    let vector = crate::tests::delivery_vector();
    let mut credential = crate::tests::fixture_credential(&protection, vector).unwrap();
    let (reader, password) = pipe_files();
    drop(reader);
    let error = credential.deliver_password(PasswordReceiver(password)).unwrap_err();
    assert_eq!(
        error,
        DeliveryError {
            accepted: 0,
            kind: DeliveryFailure::ClosedReader
        },
        "closed reader typed refusal"
    );
    assert_eq!(error.to_string(), "credential delivery refused", "constant delivery Display");
    assert!(std::error::Error::source(&error).is_none(), "no dependency error source");
    let (_reader, verifier) = pipe_files();
    assert_eq!(
        credential.deliver_verifier(VerifierReceiver(verifier)),
        Ok(135),
        "second role attempted after first refusal"
    );
    assert_eq!(credential.complete(), Ok(()), "both completions after delivery refusal");
}

fn protocol_launcher() -> &'static str {
    r"
import os,sys
case=sys.argv[1]
for name in ('LISTEN_PID','LISTEN_FDS','LISTEN_FDNAMES','LISTEN_PIDFDID'):
    os.environ.pop(name,None)
os.environ.update(LISTEN_PID=str(os.getpid()),LISTEN_FDS='2',LISTEN_FDNAMES='password:verifier',PN_HOME_RECEIVER_CASE=case)
if case=='address': os.environ['LISTEN_PID']='0'; os.environ['LISTEN_FDS']='not-a-count'
if case=='absent': del os.environ['LISTEN_FDS']
if case=='few': os.environ['LISTEN_FDS']='1'
if case=='count': os.environ['LISTEN_FDS']='-2'
if case=='overflow': os.environ['LISTEN_FDS']='18446744073709551616'
if case=='extra': os.environ['LISTEN_FDS']='3'; os.environ['LISTEN_FDNAMES']='wrong'
if case=='names': os.environ['LISTEN_FDNAMES']='verifier:unknown'
if case=='repeat-name': os.environ['LISTEN_FDNAMES']='password:password'
if case in ('deny-open','deny-duplicate','valid','reverse','identity','limit','same-pipe','read-end','regular','missing-second'):
    import fcntl
    a,b=os.pipe(); c,d=os.pipe()
    x=fcntl.fcntl(a if case=='read-end' else b,fcntl.F_DUPFD_CLOEXEC,10); y=fcntl.fcntl(b if case=='same-pipe' else d,fcntl.F_DUPFD_CLOEXEC,10)
    os.dup2(x,3); os.dup2(y,4)
    for fd in set((a,b,c,d,x,y))-{3,4}: os.close(fd)
    if case=='reverse': os.environ['LISTEN_FDNAMES']='verifier:password'
    if case=='identity': os.environ['LISTEN_PIDFDID']='0'
    if case=='missing-second': os.close(4)
    if case=='regular':
        fd=os.open('/dev/null',os.O_WRONLY); os.dup2(fd,3); os.close(fd)
    if case=='limit':
        import resource
        resource.setrlimit(resource.RLIMIT_NOFILE,(7,7))
os.execv(sys.argv[2],[sys.argv[2],'--exact','delivery::tests::protocol','--nocapture'])
"
}
