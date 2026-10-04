#!/usr/bin/env python3
"""Compile and test the local PIN verifier without Qt or a Telegram build."""

import argparse
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile


def openssl_flags(root):
    if root:
        root = Path(root)
        return [f"-I{root / 'include'}"], [
            f"-L{root / 'lib'}", f"-Wl,-rpath,{root / 'lib'}", "-lcrypto"
        ]
    if shutil.which("pkg-config"):
        available = subprocess.run(
            ["pkg-config", "--exists", "libcrypto"], check=False)
        if available.returncode == 0:
            return (
                shlex.split(subprocess.check_output(
                    ["pkg-config", "--cflags", "libcrypto"], text=True)),
                shlex.split(subprocess.check_output(
                    ["pkg-config", "--libs", "libcrypto"], text=True)),
            )
    bundled = Path("/opt/homebrew/opt/openssl@3")
    if bundled.is_dir():
        return openssl_flags(bundled)
    raise SystemExit("Specify --openssl-root or install libcrypto pkg-config metadata.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cxx", default=os.environ.get("CXX", "c++"))
    parser.add_argument("--openssl-root", default=os.environ.get("OPENSSL_ROOT_DIR"))
    parser.add_argument("--sanitize", action="store_true")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    sources = repo / "Telegram" / "SourceFiles"
    includes, libraries = openssl_flags(args.openssl_root)

    with tempfile.TemporaryDirectory(prefix="leemen-local-pin-") as temporary:
        directory = Path(temporary)
        executable = directory / "local_pin_tests"
        command = shlex.split(args.cxx) + [
            "-std=c++20", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-pedantic",
            f"-I{sources}", *includes,
            str(sources / "leemen" / "local_pin.cpp"),
            str(sources / "test" / "leemen" / "local_pin_tests.cpp"),
            "-o", str(executable), *libraries,
        ]
        if args.sanitize:
            command += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
        subprocess.run(command, check=True)
        subprocess.run([str(executable)], check=True)


if __name__ == "__main__":
    main()
