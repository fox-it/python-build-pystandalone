# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import argparse
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Optional

import lief

from .utils import extract_python_archive


def run_dist_python(
    dist_root: Path,
    python_info,
    args: list[str],
    extra_env: Optional[dict[str, str]] = None,
    **runargs,
) -> subprocess.CompletedProcess[str]:
    """Runs a `python` process from an extracted PBS distribution.

    This function attempts to isolate the spawned interpreter from any
    external interference (PYTHON* environment variables), etc.
    """
    env = dict(os.environ)

    # Wipe PYTHON environment variables.
    for k in env:
        if k.startswith("PYTHON"):
            del env[k]

    if extra_env:
        env.update(extra_env)

    return subprocess.run(
        [str(dist_root / python_info["python_exe"])] + args,
        cwd=dist_root,
        env=env,
        **runargs,
    )


def run_custom_unittests(pbs_source_dir: Path, dist_root: Path, python_info) -> int:
    """Runs custom PBS unittests against a distribution."""

    args = [
        "-m",
        "unittest",
        "pythonbuild.disttests",
    ]

    env = {
        "PYTHONPATH": str(pbs_source_dir),
        "TARGET_TRIPLE": python_info["target_triple"],
        "BUILD_OPTIONS": python_info["build_options"],
    }

    res = run_dist_python(dist_root, python_info, args, env, stderr=subprocess.STDOUT)

    return res.returncode


def run_stdlib_tests(dist_root: Path, python_info, harness_args: list[str]) -> int:
    """Run Python stdlib tests for a PBS distribution.

    The passed path is the `python` directory from the extracted distribution
    archive.
    """
    args = [
        str(dist_root / python_info["run_tests"]),
    ]

    args.extend(harness_args)

    return run_dist_python(dist_root, python_info, args).returncode


def create_pystandalone_test_payload(dist_root: Path, python_info) -> bytes:
    """Create a payload for pystandalone tests from a PBS distribution."""
    stdlib = (dist_root / python_info["python_paths"]["stdlib"]).resolve()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(stdlib.rglob("*")):
            relative_path = path.relative_to(stdlib)
            top = relative_path.parts[0] if relative_path.parts else ""

            if top.startswith(("abc", "codecs", "encodings", "io", "this")):
                zf.write(path, arcname=str(relative_path))
    payload_library = buf.getvalue()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "bootstrap.py",
            "import sys; print(sys.argv[1:]); import this; print('Great success!', flush=True)",
        )
    payload_bootstrap = buf.getvalue()

    payload = io.BytesIO()
    payload.write(len(payload_library).to_bytes(4, "little"))
    payload.write(payload_library)
    payload.write(len(payload_bootstrap).to_bytes(4, "little"))
    payload.write(payload_bootstrap)
    return payload.getvalue()


def patch_pe(binary: bytes, payload: bytes) -> bytes:
    if (pe := lief.PE.parse(io.BytesIO(binary))) is None:
        return binary

    for node in pe.resources.childs:
        if node.id == lief.PE.ResourcesManager.TYPE.RCDATA:
            data = next(next(node.childs).childs)
            data.content = payload  # type: ignore
            break

    return pe.write_to_bytes()


def patch_elf(binary: bytes, payload: bytes) -> bytes:
    if (elf := lief.ELF.parse(io.BytesIO(binary))) is None:
        return binary

    section = elf.get_section(".pystandalone")

    # There are some issues with the way lief writes ELF files, so patch the payload in-place
    buf = bytearray(binary)
    buf[section.file_offset : section.file_offset + len(payload)] = payload

    return bytes(buf)


def patch_macho(binary: bytes, payload: bytes) -> bytes:
    if (fat := lief.MachO.parse(io.BytesIO(binary))) is None:
        return binary

    for macho in fat:
        section = macho.get_section("__pystandalone")
        section.content = list(payload)  # type: ignore

    with tempfile.NamedTemporaryFile() as tf:
        fat.write(tf.name)
        subprocess.run(
            ["codesign", "--force", "--sign", "-", tf.name],
            capture_output=True,
            check=True,
        )
        return Path(tf.name).read_bytes()


def run_pystandalone_tests(dist_root: Path, python_info) -> int:
    """Run pystandalone tests for a PBS distribution.

    The passed path is the `python` directory from the extracted distribution
    archive.
    """
    print("Running pystandalone tests...", file=sys.stderr)
    payload = create_pystandalone_test_payload(dist_root, python_info)

    # Copy the python executable to a temporary directory so that it's not using any files from the distribution
    with tempfile.TemporaryDirectory() as td:
        # Use shutil.copy so that we also copy permission bits
        temp_exe = Path(td) / "python"
        shutil.copy(dist_root / python_info["python_exe"], temp_exe)

        exe_buf = temp_exe.read_bytes()
        if "-apple-darwin" in python_info["target_triple"]:
            exe_buf = patch_macho(exe_buf, payload)
        elif "-unknown-linux-" in python_info["target_triple"]:
            exe_buf = patch_elf(exe_buf, payload)
        elif "-pc-windows-" in python_info["target_triple"]:
            exe_buf = patch_pe(exe_buf, payload)

        temp_exe.write_bytes(exe_buf)

        env = dict(os.environ)

        # Wipe PYTHON environment variables.
        for k in env:
            if k.startswith("PYTHON"):
                del env[k]

        result = subprocess.run(
            [temp_exe, "some-argument"], env=env, capture_output=True, text=True
        )

        if result.returncode != 0 or not all(
            x in result.stdout
            for x in (
                "some-argument",
                "The Zen of Python, by Tim Peters",
                "Great success!",
            )
        ):
            print(
                f"pystandalone test failed (return code {result.returncode})",
                file=sys.stderr,
            )
            print("stdout:", file=sys.stderr)
            print(result.stdout, file=sys.stderr)
            print("stderr:", file=sys.stderr)
            print(result.stderr, file=sys.stderr)
            return 1

    print("OK", file=sys.stderr)

    return 0


def main(pbs_source_dir: Path, raw_args: list[str]) -> int:
    """test-distribution.py functionality."""

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--stdlib",
        action="store_true",
        help="Run the stdlib test harness",
    )
    parser.add_argument(
        "dist",
        nargs=1,
        help="Path to distribution to test",
    )
    parser.add_argument(
        "harness_args",
        nargs=argparse.REMAINDER,
        help="Raw arguments to pass to Python's test harness",
    )

    args = parser.parse_args(raw_args)

    dist_path_raw = Path(args.dist[0])

    td = None
    try:
        if dist_path_raw.is_file():
            td = tempfile.TemporaryDirectory()
            dist_path = extract_python_archive(dist_path_raw, Path(td.name))
        else:
            dist_path = dist_path_raw

        python_json = dist_path / "PYTHON.json"

        with python_json.open("r", encoding="utf-8") as fh:
            python_info = json.load(fh)

        codes = []

        codes.append(run_custom_unittests(pbs_source_dir, dist_path, python_info))

        if args.stdlib:
            codes.append(run_stdlib_tests(dist_path, python_info, args.harness_args))

        codes.append(run_pystandalone_tests(dist_path, python_info))

        if len(codes) == 0:
            print("no tests run")
            return 1

        if any(code != 0 for code in codes):
            return 1

        return 0

    finally:
        if td:
            td.cleanup()
