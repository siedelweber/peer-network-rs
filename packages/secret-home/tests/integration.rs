use pn_secret_home::{Error, Protection};
use rustix::process::{Resource, Rlimit};

/// An isolated child lowers the kernel memlock limit after bootstrap: acquisition
/// refuses Lock rather than creating an unlocked home, and a budget above the
/// lowered limit also refuses. The parent requires successful child assertions.
/// ´claim:crypto:home-lock-failure-never-degrades´
/// ´test:integration:kernel-limits´
#[test]
fn kernel_limits() {
    if std::env::var_os("PN_SECRET_HOME_LIMIT_CHILD").is_some() {
        let protection = Protection::establish(65_536).unwrap();
        rustix::process::setrlimit(
            Resource::Memlock,
            Rlimit {
                current: Some(0),
                maximum: Some(0),
            },
        )
        .unwrap();
        assert_eq!(protection.generate(32).unwrap_err(), Error::Lock);
        assert_eq!(Protection::establish(65_536).unwrap_err(), Error::Budget);
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "kernel_limits", "--nocapture"])
        .env("PN_SECRET_HOME_LIMIT_CHILD", "1")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
}
