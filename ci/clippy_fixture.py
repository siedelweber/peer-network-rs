"""Build isolated, dependency-free lint witnesses on the compute node."""

import contextlib
import os
from pathlib import Path
import subprocess
import tempfile
import time


def run(command, root):
    started = time.monotonic()
    environment = os.environ.copy()
    environment.pop("RUSTFLAGS", None)
    environment.pop("CARGO_ENCODED_RUSTFLAGS", None)
    result = subprocess.run(command, cwd=root, env=environment, capture_output=True, text=True)
    print(f"SCRATCH-COMMAND={command!r} STATUS={result.returncode} WALL={time.monotonic()-started:.6f}s")
    return result


@contextlib.contextmanager
def crate(name, source, lints):
    temporary_root = Path(os.environ.get("TMPDIR", str(Path.home() / ".cache/tmp")))
    temporary_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="foundation-", dir=temporary_root) as directory:
        root = Path(directory)
        print(f"SCRATCH-CRATE={root}")
        (root / "src").mkdir()
        (root / "Cargo.toml").write_text(f'[package]\nname = "{name}"\nversion = "0.0.0"\nedition = "2024"\n[workspace]\nmembers = []\n{lints}')
        (root / "src/lib.rs").write_text(source)
        result = run(["cargo", "generate-lockfile", "--offline"], root)
        if result.returncode:
            raise RuntimeError(result.stderr)
        yield root
