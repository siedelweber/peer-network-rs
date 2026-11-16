//! Public launch refusals precede any protected receiver input.
//! (´[ROOT-rule:observe:credential-store-contract]´)

use pn_testkit::{RuntimePath, runtime_path};
use std::fmt::Write as _;
use std::io::Read;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

struct FixtureRoot {
    path: PathBuf,
    remove: bool,
}

impl FixtureRoot {
    fn create(prefix: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        Self::create_in(&std::env::temp_dir(), prefix, &NEXT).expect("fixture root atomic creation")
    }

    fn create_in(parent: &std::path::Path, prefix: &str, counter: &std::sync::atomic::AtomicU64) -> std::io::Result<Self> {
        loop {
            let number = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = parent.join(format!("{prefix}-{}-{number}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path, remove: true }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
    }

    fn finish(&mut self) -> std::io::Result<()> {
        if self.remove {
            std::fs::remove_dir_all(&self.path)?;
            self.remove = false;
        }
        Ok(())
    }
}

fn cleanup_result(result: std::io::Result<()>, path: &std::path::Path) {
    if let Err(error) = result {
        if std::thread::panicking() {
            drop(cli_common::emit(
                &serde_json::json!({"fixture_cleanup":path.display().to_string(),"error":error.to_string()}),
            ));
        } else {
            panic!("fixture cleanup failed at {}: {error}", path.display());
        }
    }
}

impl Drop for FixtureRoot {
    fn drop(&mut self) {
        let result = self.finish();
        cleanup_result(result, &self.path);
    }
}

/// Atomic root creation skips an occupied same-number path without acquiring or changing it.
/// ´claim:host:credential-root-creation-skips-occupied´
/// ´test:unit:root-creation´
#[test]
fn root_creation() {
    let guard = FixtureRoot::create("credential-prerequisites");
    let root = &guard.path;
    let counter = std::sync::atomic::AtomicU64::new(0);
    let occupied = root.join(format!("candidate-{}-0", std::process::id()));
    std::fs::create_dir(&occupied).unwrap();
    std::fs::write(occupied.join("unchanged"), b"public owner").unwrap();
    let created = FixtureRoot::create_in(root, "candidate", &counter);
    assert!(created.is_ok(), "existing same-number path does not refuse");
    let created = created.unwrap();
    assert_ne!(created.path, occupied, "existing same-number path is not acquired");
    assert_eq!(std::fs::read(occupied.join("unchanged")).unwrap(), b"public owner");
}

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
    binding_cases(
        &binary,
        &original,
        FixtureRoot::create("credential-binding"),
        &["missing", "substituted", "record", "focused", "interpreter"],
    );
}

fn binding_cases(binary: &std::path::Path, original: &serde_json::Value, mut root: FixtureRoot, cases: &[&str]) {
    let directory = &root.path;
    for &case in cases {
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
                file.set_len(std::fs::metadata(binary).unwrap().len()).unwrap();
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
            "injected" => panic!("public binding failure before launch"),
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
    root.finish().unwrap();
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

// The setup inputs are published test material; Session protects returned capabilities.
// This instance does not call artifact(),
// receive a generated stream, or open the protected provisioning route.
#[derive(Debug, PartialEq, Eq)]
enum InstanceRefusal {
    Programs,
    Version,
    Kernel,
    Collector,
    Limits,
}

fn server_programs(directory: &std::path::Path) -> Result<[PathBuf; 3], InstanceRefusal> {
    let programs = ["postgres", "initdb", "pg_ctl"].map(|name| directory.join(name));
    if !directory.is_absolute() || programs.iter().any(|path| !path.is_file()) {
        return Err(InstanceRefusal::Programs);
    }
    Ok(programs)
}

fn server_version(actual: &str, target: &str) -> Result<(), InstanceRefusal> {
    if actual.trim() != format!("postgres (PostgreSQL) {}", target.trim()) {
        return Err(InstanceRefusal::Version);
    }
    Ok(())
}

fn core_policy(release: &str, pattern: &str) -> Result<(), InstanceRefusal> {
    let patch = release.trim().strip_prefix("7.2.").and_then(|tail| tail.split('-').next());
    if release.contains("-rc") || !patch.is_some_and(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(InstanceRefusal::Kernel);
    }
    if !pattern.starts_with('|') || pattern.trim().len() == 1 {
        return Err(InstanceRefusal::Collector);
    }
    Ok(())
}

fn core_limits(limits: &str) -> Result<(), InstanceRefusal> {
    let row = limits.lines().find(|line| line.starts_with("Max core file size"));
    if !row.is_some_and(|line| line.split_whitespace().skip(4).eq(["1", "1", "bytes"])) {
        return Err(InstanceRefusal::Limits);
    }
    Ok(())
}

fn lower_core_limit(interpreter: &std::path::Path) {
    assert!(
        interpreter.is_absolute() && interpreter.is_file(),
        "registered interpreter is an absolute existing file"
    );
    let result = Command::new(interpreter)
        .args([
            "-c",
            "import resource,sys; resource.prlimit(int(sys.argv[1]),resource.RLIMIT_CORE,(1,1))",
        ])
        .arg(std::process::id().to_string())
        .output()
        .expect("registered interpreter lowers this test process before setup");
    assert!(result.status.success(), "core limit lowering completes");
}

#[derive(Clone, Copy, Debug)]
enum StandingProfile {
    Statement,
    Stages,
    Incompatible,
}

impl StandingProfile {
    fn settings(self) -> Vec<(&'static str, &'static str)> {
        let mut settings = vec![
            ("log_statement", "all"),
            ("log_min_duration_statement", "0"),
            ("log_duration", "on"),
            ("log_min_duration_sample", "0"),
            ("log_statement_sample_rate", "1"),
            ("log_transaction_sample_rate", "1"),
            ("log_min_error_statement", "debug5"),
            ("log_min_messages", "debug5"),
            ("log_error_verbosity", "verbose"),
            ("log_parameter_max_length", "-1"),
            ("log_parameter_max_length_on_error", "-1"),
            ("debug_print_raw_parse", "on"),
            ("debug_print_parse", "on"),
            ("debug_print_rewritten", "on"),
            ("debug_print_plan", "on"),
            ("debug_pretty_print", "on"),
            ("log_lock_waits", "on"),
            ("log_lock_failures", "on"),
            ("log_replication_commands", "on"),
            ("log_temp_files", "0"),
            ("backtrace_functions", "errfinish"),
            ("track_activities", "on"),
            ("client_min_messages", "notice"),
            ("plan_cache_mode", "auto"),
            ("jit_dump_bitcode", "off"),
            ("jit_debugging_support", "off"),
            ("shared_preload_libraries", ""),
            ("session_preload_libraries", ""),
            ("local_preload_libraries", ""),
            ("log_destination", "stderr"),
            ("logging_collector", "off"),
            ("log_connections", ""),
            ("log_disconnections", "off"),
            ("log_hostname", "off"),
            ("log_line_prefix", ""),
            ("wal_level", "minimal"),
            ("archive_mode", "off"),
            ("archive_command", ""),
            ("archive_library", ""),
            ("max_wal_senders", "0"),
            ("max_replication_slots", "0"),
        ];
        let statement = matches!(self, Self::Statement);
        settings.push(("log_statement_stats", if statement { "on" } else { "off" }));
        for name in ["log_parser_stats", "log_planner_stats", "log_executor_stats"] {
            settings.push((name, if statement { "off" } else { "on" }));
        }
        if matches!(self, Self::Incompatible) {
            for (name, value) in &mut settings {
                if *name == "jit_debugging_support" {
                    *value = "on";
                }
            }
        }
        settings
    }
}

struct OwnedInstance {
    root: PathBuf,
    directory: FixtureRoot,
    control: PathBuf,
    running: bool,
}

impl OwnedInstance {
    fn command(program: &std::path::Path, arguments: &[&str]) {
        let output = Command::new(program)
            .args(arguments)
            .output()
            .expect("owned server command starts");
        assert!(
            output.status.success(),
            "owned server command completes under HANG containment: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn start(programs: &[PathBuf; 3], directory: FixtureRoot, profile: StandingProfile) -> Self {
        Self::configured(programs, directory, profile, &[])
    }

    fn configured(
        programs: &[PathBuf; 3],
        directory: FixtureRoot,
        profile: StandingProfile,
        public_settings: &[(&str, &str)],
    ) -> Self {
        let root = directory.path.clone();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut instance = Self {
            root,
            directory,
            control: programs[2].clone(),
            running: false,
        };
        let data = instance.root.join("data");
        let password = instance.root.join("password");
        std::fs::write(&password, b"credential_public_setup_password\n").unwrap();
        std::fs::set_permissions(&password, std::fs::Permissions::from_mode(0o600)).unwrap();
        Self::command(
            &programs[1],
            &[
                "-D",
                data.to_str().unwrap(),
                "--locale=C",
                "--encoding=UTF8",
                "-U",
                "credential_public",
                "--auth=scram-sha-256",
                "--pwfile",
                password.to_str().unwrap(),
            ],
        );
        let mut config = String::from("listen_addresses=''\nport=5432\nshared_buffers='16MB'\nmax_connections=8\n");
        writeln!(config, "unix_socket_directories='{}'", instance.root.display()).unwrap();
        for (name, value) in profile.settings() {
            writeln!(config, "{name}='{value}'").unwrap();
        }
        for (name, value) in public_settings {
            writeln!(config, "{name}='{value}'").unwrap();
        }
        std::fs::write(data.join("postgresql.conf"), config).unwrap();
        // Mark before startup so even a failed readiness observation stops the owned tree.
        instance.running = true;
        Self::command(
            &instance.control,
            &[
                "-D",
                data.to_str().unwrap(),
                "-l",
                instance.root.join("server.log").to_str().unwrap(),
                "-w",
                "-t",
                "600",
                "start",
            ],
        );
        instance
    }

    fn process_limits(&self) -> Vec<(String, String)> {
        let pid = std::fs::read_to_string(self.root.join("data/postmaster.pid")).unwrap();
        let pid = pid.lines().next().unwrap();
        let children = std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children")).unwrap();
        assert!(!children.trim().is_empty(), "owned postmaster has live children");
        std::iter::once(std::process::id().to_string())
            .chain(std::iter::once(pid.to_owned()))
            .chain(children.split_whitespace().map(str::to_owned))
            .map(|process| {
                let limits =
                    std::fs::read_to_string(format!("/proc/{process}/limits")).expect("every owned child limits read back");
                core_limits(&limits).expect("one/one limits inherited by every owned child");
                (process, limits)
            })
            .collect()
    }

    fn stop(&mut self) -> std::io::Result<()> {
        if self.running && self.root.join("data/postmaster.pid").try_exists()? {
            let program = &self.control;
            let output = Command::new(program)
                .arg("-D")
                .arg(self.root.join("data"))
                .args(["-m", "fast", "-w", "-t", "600", "stop"])
                .output()?;
            if !output.status.success() {
                return Err(std::io::Error::other("owned server stop failed"));
            }
        }
        self.running = false;
        Ok(())
    }

    fn finish(&mut self) {
        self.stop().expect("owned server stops before removal");
        self.directory
            .finish()
            .expect("owned instance directory removed after process end");
    }
}

impl Drop for OwnedInstance {
    fn drop(&mut self) {
        let result = self.stop();
        if self.running {
            // A possibly live server keeps its files, including during unwinding.
            self.directory.remove = false;
        }
        cleanup_result(result, &self.root);
    }
}

async fn admitted_connection(instance: &OwnedInstance) -> Result<crate::Session, ()> {
    // Only published setup bytes are assembled here; acquisition keeps real startup private.
    let input = serde_json::to_vec(&serde_json::json!({
        "transport":"unix", "endpoint":instance.root.join(".s.PGSQL.5432"),
        "port":"5432", "user":"credential_public", "database":"postgres",
        "password":"credential_public_setup_password"
    }))
    .unwrap();
    let configuration = crate::Configuration::acquire(Some("host-secured"), &mut input.as_slice()).unwrap();
    let session = tokio::time::timeout(std::time::Duration::from_secs(600), crate::Session::connect(configuration))
        .await
        .expect("HANG awaiting credential fixture authenticated setup connection")
        .expect("host Session authenticates setup");
    for (pid, limits) in instance.process_limits() {
        cli_common::emit(&serde_json::json!({"owned_pid":pid,"limits":limits})).unwrap();
    }
    let rows = session
        .client()
        .query("SELECT current_setting('jit_debugging_support')", &[])
        .await
        .unwrap();
    if rows[0].get::<_, String>(0) != "off" {
        return Err(());
    }
    Ok(session)
}

/// Public prerequisites reject absent programs, a different version, an unreviewed kernel or collector, and unchanged core limits.
/// ´claim:host:credential-instance-prerequisites´
/// ´test:unit:instance-prerequisites´
#[test]
fn instance_prerequisites() {
    let guard = FixtureRoot::create("credential-prerequisites");
    let root = &guard.path;
    assert_eq!(
        server_programs(root),
        Err(InstanceRefusal::Programs),
        "absent server programs refuse"
    );
    assert_eq!(
        server_programs(std::path::Path::new("relative")),
        Err(InstanceRefusal::Programs),
        "relative server programs refuse"
    );
    assert_eq!(
        server_version("postgres (PostgreSQL) 18", "19rc1"),
        Err(InstanceRefusal::Version),
        "wrong server version refuses"
    );
    assert_eq!(
        core_policy("7.3.1", "|collector"),
        Err(InstanceRefusal::Kernel),
        "unreviewed kernel series refuses"
    );
    assert_eq!(
        core_policy("7.2.1", "socket:collector"),
        Err(InstanceRefusal::Collector),
        "non-piped collector refuses"
    );
    assert_eq!(
        core_limits("Max core file size        unlimited unlimited bytes"),
        Err(InstanceRefusal::Limits),
        "skipped lowering refuses at readback"
    );
    core_limits("Max core file size        1 1 bytes").unwrap();
}

/// Two fresh instances with published SCRAM setup inputs retain their distinct text-exposing statistics profiles and one/one inherited core limits, read through the unchanged host Session; an incompatible backend-start connection is refused, and every owned directory is removed after shutdown. No generated credential material is handled.
/// ´claim:host:credential-instance-standing-profiles´
/// ´test:unit:owned-instances´
#[test]
fn owned_instances() {
    let programs = server_programs(&PathBuf::from(
        std::env::var_os("PN_POSTGRESQL_BIN").expect("registered server location"),
    ))
    .unwrap();
    let target =
        std::fs::read_to_string(runtime_path(RuntimePath::Workspace("packages/host/postgresql-target.txt")).unwrap()).unwrap();
    let version = Command::new(&programs[0]).arg("--version").output().unwrap();
    assert!(version.status.success());
    server_version(std::str::from_utf8(&version.stdout).unwrap(), &target).unwrap();
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap();
    let pattern = std::fs::read_to_string("/proc/sys/kernel/core_pattern").unwrap();
    core_policy(&release, &pattern).expect("recorded kernel series and piped route required");
    let attach = std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope").unwrap();
    let interpreter = PathBuf::from(std::env::var_os("PN_TEST_PYTHON").expect("registered interpreter"));
    lower_core_limit(&interpreter);
    assert_eq!(
        core_limits(&std::fs::read_to_string("/proc/self/limits").unwrap()),
        Ok(()),
        "lowering read back before postmaster start"
    );
    cli_common::emit(&serde_json::json!({"owned_kernel":release,"core_pattern":pattern,"attach_scope":attach})).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    for (index, profile) in [
        StandingProfile::Statement,
        StandingProfile::Stages,
        StandingProfile::Incompatible,
    ]
    .into_iter()
    .enumerate()
    {
        let directory = FixtureRoot::create("credential-instance");
        let root = directory.path.clone();
        let mut instance = OwnedInstance::start(&programs, directory, profile);
        runtime.block_on(async {
            if matches!(profile, StandingProfile::Incompatible) {
                assert!(
                    admitted_connection(&instance).await.is_err(),
                    "incompatible backend-start connection refuses"
                );
                return;
            }
            let session = admitted_connection(&instance).await.unwrap();
            let client = session.client();
            for (name, expected) in profile
                .settings()
                .into_iter()
                .chain([("server_version_num", "190000"), ("effective_wal_level", "minimal")])
            {
                let rows = client.query("SELECT current_setting($1)", &[&name]).await.unwrap();
                let actual: String = rows[0].get(0);
                if name == "archive_command" {
                    assert_eq!(actual, "(disabled)", "archive command disabled by archive mode");
                    let rows = client
                        .query(
                            "SELECT setting, applied, error FROM pg_file_settings WHERE name='archive_command'",
                            &[],
                        )
                        .await
                        .unwrap();
                    assert_eq!(rows.len(), 1, "one owned archive command assignment");
                    assert_eq!(rows[0].get::<_, String>(0), "", "archive command configuration empty");
                    assert!(rows[0].get::<_, bool>(1), "archive command assignment applied");
                    assert_eq!(rows[0].get::<_, Option<String>>(2), None, "archive command assignment valid");
                } else {
                    assert_eq!(actual, expected, "standing setting readback: {name}");
                }
                cli_common::emit(&serde_json::json!({"owned_profile":index,"setting":name,"value":actual})).unwrap();
            }
            for (name, query) in [
                ("senders_absent", "SELECT NOT EXISTS (SELECT FROM pg_stat_replication)"),
                ("slots_absent", "SELECT NOT EXISTS (SELECT FROM pg_replication_slots)"),
                ("subscriptions_absent", "SELECT NOT EXISTS (SELECT FROM pg_subscription)"),
                ("receiver_absent", "SELECT NOT EXISTS (SELECT FROM pg_stat_wal_receiver)"),
                ("not_in_recovery", "SELECT NOT pg_is_in_recovery()"),
                (
                    "external_tablespaces_absent",
                    "SELECT NOT EXISTS (SELECT FROM pg_tablespace WHERE pg_tablespace_location(oid) <> '')",
                ),
            ] {
                let rows = client.query(query, &[]).await.unwrap();
                assert!(rows[0].get::<_, bool>(0), "owned topology readback: {name}");
                cli_common::emit(&serde_json::json!({"owned_profile":index,"topology":name,"absent":true})).unwrap();
            }
            drop(session);
        });
        instance.finish();
        assert!(!root.exists(), "owned directory absent after shutdown");
    }
}

/// A binding run that panics after acquiring its root removes that root during unwinding, before any executable is launched.
/// ´claim:host:credential-binding-panic-removes-root´
/// ´test:unit:binding-panic´
#[test]
fn binding_panic() {
    let directory = FixtureRoot::create("credential-binding");
    let path = directory.path.clone();
    let outcome =
        std::panic::catch_unwind(|| binding_cases(std::path::Path::new(""), &serde_json::Value::Null, directory, &["injected"]));
    let panic = outcome.expect_err("binding failure injected before child launch");
    assert_eq!(
        panic.downcast_ref::<&str>(),
        Some(&"public binding failure before launch"),
        "assigned binding panic reached"
    );
    let removed = !path.exists();
    if !removed {
        std::fs::remove_dir_all(&path).unwrap();
    }
    assert!(removed, "failed binding run leaves no directory");
}

/// A panic before server setup removes the owned root; a panic after startup stops the owned server before removing its root, witnessed by its process identity and directory absence.
/// ´claim:host:credential-instance-panic-cleans-up´
/// ´test:unit:instance-panic´
#[test]
fn instance_panic() {
    let directory = FixtureRoot::create("credential-instance");
    let path = directory.path.clone();
    let outcome = std::panic::catch_unwind(|| {
        let _instance = OwnedInstance {
            root: path.clone(),
            directory,
            control: PathBuf::new(),
            running: false,
        };
        panic!("public panic before server setup");
    });
    let panic = outcome.expect_err("pre-start panic injected");
    assert_eq!(
        panic.downcast_ref::<&str>(),
        Some(&"public panic before server setup"),
        "assigned pre-start panic reached"
    );
    let removed = !path.exists();
    if !removed {
        std::fs::remove_dir_all(&path).unwrap();
    }
    assert!(removed, "panicked pre-start owner's root removed");
    lower_core_limit(&PathBuf::from(std::env::var_os("PN_TEST_PYTHON").unwrap()));
    core_limits(&std::fs::read_to_string("/proc/self/limits").unwrap()).unwrap();
    let programs = server_programs(&PathBuf::from(std::env::var_os("PN_POSTGRESQL_BIN").unwrap())).unwrap();
    let directory = FixtureRoot::create("credential-instance");
    let path = directory.path.clone();
    let mut identity = String::new();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let instance = OwnedInstance::start(&programs, directory, StandingProfile::Statement);
        let pid = std::fs::read_to_string(path.join("data/postmaster.pid")).unwrap();
        identity = pid.lines().next().unwrap().to_owned();
        assert!(
            std::path::Path::new(&format!("/proc/{identity}")).exists(),
            "owned server running before panic"
        );
        let _owned = instance;
        panic!("public panic after server startup");
    }));
    let panic = outcome.expect_err("post-start panic injected");
    assert_eq!(
        panic.downcast_ref::<&str>(),
        Some(&"public panic after server startup"),
        "assigned post-start panic reached"
    );
    let stopped = match std::fs::read_to_string(format!("/proc/{identity}/status")) {
        Ok(status) => status.lines().any(|line| line.starts_with("State:\tZ")),
        Err(error) => error.kind() == std::io::ErrorKind::NotFound,
    };
    let removed = !path.exists();
    if !removed {
        let mut rescue = OwnedInstance {
            root: path.clone(),
            directory: FixtureRoot {
                path: path.clone(),
                remove: true,
            },
            control: programs[2].clone(),
            running: !stopped,
        };
        rescue.finish();
    }
    assert!(stopped, "panicked owner's server stopped");
    assert!(removed, "panicked owner's root removed");
}

const CHILD_COMPLETION: &str = "credential fixture child complete";
const CLEANUP_PATHS: [&[u8]; 2] = [b"public-root", b"public-root-\xff"];

fn child_complete() {
    cli_common::emit(&CHILD_COMPLETION).expect("child completion emitted after assertions");
}

/// Cleanup reporting completes in a normally exited child, preserves the original panic, and emits the displayed path and cause for public UTF-8 and non-UTF-8 paths.
/// ´claim:host:credential-cleanup-report-preserves-panic´
/// ´test:unit:cleanup-reporting´
#[test]
fn cleanup_reporting() {
    use std::os::unix::ffi::OsStrExt as _;
    struct Failure<'a>(&'a std::path::Path);
    impl Drop for Failure<'_> {
        fn drop(&mut self) {
            cleanup_result(Err(std::io::Error::other("public cleanup failure")), self.0);
        }
    }
    if !std::env::args().any(|arg| arg == "--include-ignored") {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "credential_fixture::cleanup_reporting",
                "--exact",
                "--include-ignored",
                "--nocapture",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("cleanup reporting child starts");
        assert_eq!(output.status.code(), Some(0), "cleanup reporting child did not abort");
        assert_eq!(
            output
                .stdout
                .windows(CHILD_COMPLETION.len())
                .filter(|part| *part == CHILD_COMPLETION.as_bytes())
                .count(),
            1,
            "cleanup reporting child ran its single test"
        );
        for bytes in CLEANUP_PATHS {
            let path = std::path::Path::new(std::ffi::OsStr::from_bytes(bytes));
            let report = serde_json::to_vec(
                &serde_json::json!({"fixture_cleanup":path.display().to_string(),"error":"public cleanup failure"}),
            )
            .unwrap();
            assert!(
                output.stdout.windows(report.len()).any(|part| part == report),
                "cleanup report names path and cause"
            );
        }
        return;
    }
    core_policy(
        &std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap(),
        &std::fs::read_to_string("/proc/sys/kernel/core_pattern").unwrap(),
    )
    .expect("reviewed core policy before reporter control");
    lower_core_limit(&PathBuf::from(std::env::var_os("PN_TEST_PYTHON").unwrap()));
    core_limits(&std::fs::read_to_string("/proc/self/limits").unwrap()).expect("reporter child core limit read back");
    for bytes in CLEANUP_PATHS {
        let path = std::path::Path::new(std::ffi::OsStr::from_bytes(bytes));
        let outcome = std::panic::catch_unwind(|| {
            let _failure = Failure(path);
            panic!("public original panic");
        });
        let panic = outcome.expect_err("original panic reaches its catcher");
        assert_eq!(
            panic.downcast_ref::<&str>(),
            Some(&"public original panic"),
            "cleanup error preserves original panic"
        );
    }
    child_complete();
}

mod raw;
