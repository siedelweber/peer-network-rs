//! Public launch refusals precede any protected receiver input.
//! (´[ROOT-rule:observe:credential-store-contract]´)

use pn_testkit::{RuntimePath, runtime_path};
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn artifact() -> std::io::Result<PathBuf> {
    runtime_path(RuntimePath::Executable("pn-credential-generator"))
}

/// The host binds the selected build's artifact bytes at resolution; each missing prerequisite and a same-length replacement refuses before launch. Replacement between resolution and exec, and a caller setting runner variables or rewriting the receipt and its inputs, are outside the claim.
/// ´claim:host:credential-artifact-binding-refuses-substitution´
/// ´test:unit:binding´
#[test]
fn binding() {
    if let Ok(case) = std::env::var("PN_HOST_BINDING_CASE") {
        let error = artifact()
            .expect_err("unbound artifact must refuse before launch")
            .to_string();
        let expected = match case.as_str() {
            "missing" => "absolute existing executable file",
            "substituted" => "artifact bytes differ",
            "record" => "artifact record absent",
            "focused" => "build manifest absent",
            "interpreter" => "interpreter absent",
            _ => panic!("closed public binding cases"),
        };
        assert!(error.contains(expected), "assigned binding refusal: {case}: {error}");
        return;
    }
    let binary = artifact().expect("selected runner artifact required, without fallback");
    let manifest = PathBuf::from(std::env::var_os("PN_TEST_BUILD_MANIFEST").unwrap());
    let original: serde_json::Value = serde_json::from_slice(&std::fs::read(manifest).unwrap()).unwrap();
    let directory = std::env::temp_dir().join(format!("credential-binding-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    for case in ["missing", "substituted", "record", "focused", "interpreter"] {
        let mut data = original.clone();
        let mut child = Command::new(std::env::current_exe().unwrap());
        child
            .args(["--exact", "credential_fixture::binding", "--nocapture"])
            .env("PN_HOST_BINDING_CASE", case);
        match case {
            "missing" => {
                child.env("CARGO_BIN_EXE_pn-credential-generator", directory.join("absent"));
            }
            "substituted" => {
                let substitute = directory.join("substitute");
                let file = std::fs::File::create(&substitute).unwrap();
                file.set_len(std::fs::metadata(&binary).unwrap().len()).unwrap();
                data["credential_executable"]["path"] = substitute.to_str().unwrap().into();
                child.env("CARGO_BIN_EXE_pn-credential-generator", substitute);
            }
            "record" => {
                data.as_object_mut().unwrap().remove("credential_executable");
            }
            "focused" => {
                child.env_remove("PN_TEST_BUILD_MANIFEST");
            }
            "interpreter" => {
                child.env_remove("PN_TEST_PYTHON");
            }
            _ => unreachable!(),
        }
        if case != "focused" {
            let receipt = directory.join(case);
            std::fs::write(&receipt, serde_json::to_vec(&data).unwrap()).unwrap();
            child.env("PN_TEST_BUILD_MANIFEST", receipt);
        }
        let output = child.output().unwrap();
        assert!(
            output.status.success(),
            "binding control {case}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    std::fs::remove_dir_all(directory).unwrap();
}

fn refuse_handover(case: &str) -> (std::process::Output, Vec<u8>, Vec<u8>) {
    let binary = artifact().expect("bound generator artifact precedes launch");
    let interpreter = PathBuf::from(std::env::var_os("PN_TEST_PYTHON").expect("declared interpreter precedes launch"));
    let (mut password, password_writer) = std::io::pipe().unwrap();
    let mut command = Command::new(interpreter);
    command
        .args(["-c", WRAPPER])
        .arg(binary)
        .arg(case)
        .stdin(Stdio::from(password_writer))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let mut verifier = child.stdout.take().unwrap();
    // Command retains its Stdio handles until dropped; both parent writers end here.
    drop(command);
    let output = child.wait_with_output().expect("HANG containment owns wrapper completion");
    let mut first = Vec::new();
    let mut second = Vec::new();
    password
        .read_to_end(&mut first)
        .expect("HANG containment owns password EOF after refusal");
    verifier
        .read_to_end(&mut second)
        .expect("HANG containment owns verifier EOF after refusal");
    (output, first, second)
}

/// Real startup refusals reach their assigned class before credential construction;
/// a later independent refusal keeps each wrapper mutation free of private output.
/// ´claim:host:credential-handover-refuses-before-construction´
/// ´test:unit:handovers´
#[test]
fn handovers() {
    for (case, reason) in [
        ("third", "additional credential receiver"),
        ("count", "credential receiver missing"),
        ("names", "credential receiver name mismatch"),
        ("address", "credential receiver missing"),
        ("identity", "invalid credential receiver convention"),
    ] {
        let (output, password, verifier) = refuse_handover(case);
        assert_eq!(output.status.code(), Some(1), "assigned nonzero generator refusal: {case}");
        assert!(
            password.is_empty() && verifier.is_empty(),
            "no private output before construction: {case}"
        );
        let public = String::from_utf8(output.stderr).unwrap();
        assert!(public.contains(reason), "assigned acquisition refusal: {case}: {public}");
        assert!(!public.contains("password_bytes"), "no terminal success object: {case}");
        for line in public.lines() {
            serde_json::from_str::<serde_json::Value>(line).expect("public JSON only");
        }
    }
}

// Every exercised case has a second, later refusal. No mutation in this part
// may turn a control into a successful credential construction.
const WRAPPER: &str = r"
import os,sys,fcntl,subprocess
binary,case=sys.argv[1:]
a=fcntl.fcntl(0,fcntl.F_DUPFD_CLOEXEC,10)
b=fcntl.fcntl(1,fcntl.F_DUPFD_CLOEXEC,10)
os.close(0);os.close(1)
child='''
import os,sys,fcntl
binary,case,a,b=sys.argv[1:]; a=int(a); b=int(b)
os.dup2(a,3); os.dup2(b,4)
for fd in {a,b}-{3,4}: os.close(fd)
os.dup2(2,1)
null=os.open('/dev/null',os.O_RDONLY); os.dup2(null,0)
if null not in {0,1,2,3,4}: os.close(null)
os.environ.update(LISTEN_PID=str(os.getpid()),LISTEN_FDS='2',LISTEN_FDNAMES='password:verifier')
os.environ.pop('LISTEN_PIDFDID',None)
os.environ['LISTEN_PIDFDID']='public-secondary-refusal'
if case=='third':
    os.dup2(3,5); os.environ['LISTEN_FDS']='3'
if case=='count': os.environ['LISTEN_FDS']='1'
if case=='names': os.environ['LISTEN_FDNAMES']='password:password'
if case=='address': os.environ['LISTEN_PID']='0'
if case=='identity':
    os.dup2(3,4)
    os.environ['LISTEN_PIDFDID']='public-identity-refusal'
os.execv(binary,[binary])
'''
process=subprocess.Popen([sys.executable,'-c',child,binary,case,str(a),str(b)],pass_fds=(a,b),stdin=subprocess.DEVNULL,stdout=sys.stderr,stderr=sys.stderr)
os.close(a);os.close(b)
sys.exit(process.wait())
";
