"""Measure Cargo configuration precedence over a manifest lint in isolation."""

import json

from clippy_fixture import crate, run


def findings(result):
    return [record["message"] for line in result.stdout.splitlines()
            if (record := json.loads(line)).get("reason") == "compiler-message"
            and (record["message"].get("code") or {}).get("code") == "clippy::must_use_candidate"]


def main():
    with crate("foundation-pedantic-probe", "pub fn answer() -> u32 { 42 }\n", '[lints.clippy]\npedantic = "deny"\n') as root:
        command = ["cargo", "clippy", "--locked", "--lib", "--message-format=json"]
        baseline = run(command, root)
        baseline_findings = findings(baseline)
        if baseline.returncode == 0 or not baseline_findings:
            raise RuntimeError(f"pedantic baseline did not refuse: {baseline.stdout} {baseline.stderr}")
        (root / ".cargo").mkdir()
        (root / ".cargo/config.toml").write_text('[build]\nrustflags = ["-A", "clippy::pedantic"]\n')
        configured = run(command, root)
        configured_findings = findings(configured)
        print("RUSTFLAGS-MEASUREMENT=" + json.dumps({
            "lint": "clippy::must_use_candidate",
            "baseline_status": baseline.returncode,
            "baseline_findings": len(baseline_findings),
            "configured_status": configured.returncode,
            "configured_findings": len(configured_findings),
            "configuration_overrides_manifest": configured.returncode == 0 and not configured_findings,
        }, sort_keys=True))
        if configured.returncode != 0 or configured_findings:
            raise RuntimeError("Cargo configuration did not override the manifest lint as recorded")


if __name__ == "__main__":
    main()
