#!/usr/bin/env python3
"""Test the compiler forks in isolated copies, preserving package lockfiles.

The workspace deliberately excludes these packages. The SLEIGH allocation
benchmark also needs an external open_sleigh checkout, so run its library
and documentation suites rather than that integration target.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def source_hashes(directory):
    result = {}
    for path in directory.rglob("*"):
        relative = path.relative_to(directory)
        if "target" in relative.parts:
            continue
        if path.is_symlink() or path.is_junction():
            raise RuntimeError(f"vendor source must not contain links: {path}")
        if path.is_file():
            result[relative.as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", default="stable")
    arguments = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", arguments.toolchain):
        parser.error("toolchain must be a Rustup toolchain name")
    root = Path(__file__).resolve().parents[1]
    sources = [root / "vendor" / name for name in ("wazabin-pcode", "wazabin-sleigh")]
    for source in sources:
        if not source.is_dir() or source.is_symlink() or source.is_junction():
            raise RuntimeError(f"missing or linked vendor package: {source}")
    before = [source_hashes(source) for source in sources]
    temporary = Path(tempfile.mkdtemp(prefix="ghidra-vendor-tests-"))
    copies = [temporary / source.name for source in sources]
    for source, destination in zip(sources, copies):
        shutil.copytree(source, destination, ignore=shutil.ignore_patterns("target"))
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(temporary / "target")
    environment["RUSTDOCFLAGS"] = "-D warnings"
    cargo = shutil.which("cargo")
    if cargo is None:
        raise RuntimeError("cargo is not on PATH")
    prefix = [cargo, "+" + arguments.toolchain, "test"]
    pcode, sleigh = copies
    patch = "patch.crates-io.wazabin-pcode.path=" + json.dumps(pcode.as_posix())
    commands = [
        prefix + ["--locked", "--all-features", "--manifest-path", str(pcode / "Cargo.toml")],
        prefix + ["--lib", "--all-features", "--manifest-path", str(sleigh / "Cargo.toml"), "--config", patch],
        prefix + ["--locked", "--doc", "--all-features", "--manifest-path", str(sleigh / "Cargo.toml"), "--config", patch],
    ]
    print(f"Testing compiler forks with {arguments.toolchain} in {temporary}", flush=True)
    try:
        for command in commands:
            subprocess.run(command, cwd=temporary, env=environment, check=True)
    finally:
        after = [source_hashes(source) for source in sources]
        if after != before:
            raise RuntimeError("checked-in vendor files changed during isolated tests")
    print("Compiler fork suites passed; checked-in vendor sources and lockfiles unchanged.", flush=True)


if __name__ == "__main__":
    main()
