#!/usr/bin/env python3
import argparse
import os
import pathlib
import shutil
import subprocess
import sys

from pythonbuild.downloads import DOWNLOADS
from pythonbuild.utils import download_entry, extract_tar_to_directory

ROOT = pathlib.Path(os.path.abspath(__file__)).parent.parent
BUILD = ROOT / "build"
CPYTHON_PATH = BUILD / "cpython"
DOWNLOADS_PATH = BUILD / "downloads"
SUPPORT = ROOT / "pystandalone"
SRC_DIR = SUPPORT / "src"
PATCH_DIR = SUPPORT / "patch"

DUMMY_PAYLOAD_SIZE = 1024 * 1024 * 4

PATCH_FILES = [
    # Small include changes
    "Include/Python.h",
    "Include/cpython/initconfig.h",
    # Zipimport changes
    "Lib/zipimport.py",
    # IO module changes
    "Modules/_io/fileio.c",
    # SSL module changes
    "Modules/_ssl.c",
    # Pystandalone init
    "Modules/main.c",
    # Pystandalone hook <3.12
    "Python/pylifecycle.c",
    # Pystandalone hook >3.12
    "Python/import.c",
    # Misc config changes
    "Python/initconfig.c",
]
PLATFORM_PATCH_FILES = {
    "macos": [
        "Makefile.pre.in",
    ],
    "linux": [
        "Makefile.pre.in",
    ],
    "windows": [
        "PC/pyconfig.h",  # <3.13
        "PC/pyconfig.h.in",  # >3.13
        "PC/python_exe.rc",
        "PCbuild/pythoncore.vcxproj",
        "PCbuild/pythoncore.vcxproj.filters",
        # >3.11
        "PCbuild/_freeze_module.vcxproj",
        "PCbuild/_freeze_module.vcxproj.filters",
    ],
}


def main():
    BUILD.mkdir(exist_ok=True)
    DOWNLOADS_PATH.mkdir(exist_ok=True)

    parser = argparse.ArgumentParser(add_help=False)

    parser.add_argument(
        "--python",
        choices={
            "cpython-3.9",
            "cpython-3.10",
            "cpython-3.11",
            "cpython-3.12",
            "cpython-3.13",
            "cpython-3.14",
            "cpython-3.15",
        },
        default="cpython-3.11",
        help="Python distribution to build",
    )
    parser.add_argument(
        "--dev",
        action="store_true",
        help="Only prepare a patched source code directory, do not build",
    )
    parser.add_argument(
        "--create-patch",
        action="store_true",
        help="Create patch files from the source modifications",
    )
    parser.add_argument(
        "--create-platform-patch",
        action="store_true",
        help="Only create platform-specific patch files (implies --create-patch)",
    )

    args, rest = parser.parse_known_args()

    if sys.platform == "darwin":
        platform = "macos"
    elif sys.platform == "linux":
        platform = "linux"
    elif sys.platform == "win32":
        platform = "windows"
    else:
        raise RuntimeError(f"Unsupported platform: {sys.platform}")

    if args.dev:
        python_source = prepare_cpython_dev(args.python, platform)
        print(f"Prepared CPython source at: {python_source}")
        return 0

    if args.create_patch or args.create_platform_patch:
        entry = DOWNLOADS[args.python]
        python_source = CPYTHON_PATH / f"Python-{entry['version']}-{platform}-dev"
        patch_file = PATCH_DIR / f"{args.python}.patch"

        if not python_source.exists():
            print(f"Dev source directory does not exist: {python_source}")
            return 1

        if not args.create_platform_patch:
            with patch_file.open("w") as fh:
                subprocess.run(
                    ["git", "diff", *PATCH_FILES],
                    cwd=python_source,
                    check=True,
                    bufsize=0,
                    stdout=fh,
                )
            print(f"Created patch file at: {patch_file}")

        if platform in PLATFORM_PATCH_FILES:
            platform_patch_file = PATCH_DIR / f"{args.python}-{platform}.patch"
            with platform_patch_file.open("w") as fh:
                platform_patch_files = [
                    file
                    for file in PLATFORM_PATCH_FILES.get(platform, [])
                    if (python_source / file).exists()
                ]
                subprocess.run(
                    ["git", "diff", *platform_patch_files],
                    cwd=python_source,
                    check=True,
                    bufsize=0,
                    stdout=fh,
                )
            print(f"Created platform patch file at: {platform_patch_file}")
        return 0

    cwd = pathlib.Path(".").resolve()
    if cwd.name == "cpython-unix":
        rest.append(f"--python={args.python}")

        args = [
            sys.executable,
            str(cwd / "build-main.py"),
            *rest,
        ]

        os.execve(sys.executable, args, os.environ)
    elif cwd.name == "cpython-windows":
        rest.append(f"--python={args.python}")

        args = [
            sys.executable,
            str(cwd / "build.py"),
            *rest,
        ]

        subprocess.run(args, check=True, bufsize=0)


def prepare_cpython_dev(python: str, platform: str) -> pathlib.Path:
    entry = DOWNLOADS[python]
    python_source = CPYTHON_PATH / f"Python-{entry['version']}-{platform}-dev"

    if python_source.exists():
        print(f"Source directory already exists: {python_source}")
        return python_source

    # Clone the CPython source at the correct version
    subprocess.run(
        [
            "git",
            "clone",
            "--branch",
            f"v{entry['version']}",
            "--depth",
            "1",
            "https://github.com/python/cpython",
            str(python_source),
        ],
        check=True,
        bufsize=0,
    )

    # Apply our patches
    if (patch_file := PATCH_DIR / f"{python}.patch").exists():
        print(f"Applying patch file {patch_file} to {python_source}")
        subprocess.run(
            ["git", "apply", "-C1", str(patch_file)],
            cwd=python_source,
            check=True,
            bufsize=0,
        )

    # Apply platform patches
    if (patch_file := PATCH_DIR / f"{python}-{platform}.patch").exists():
        print(f"Applying platform patch file {patch_file} to {python_source}")
        subprocess.run(
            ["git", "apply", "-C1", str(patch_file)],
            cwd=python_source,
            check=True,
            bufsize=0,
        )

    # Copy our additional source files
    shutil.copytree(SRC_DIR, python_source, dirs_exist_ok=True)

    return python_source


def prepare_cpython_source(python: str, platform: str) -> pathlib.Path:
    entry = DOWNLOADS[python]
    python_archive = download_entry(python, DOWNLOADS_PATH)
    python_source = CPYTHON_PATH / f"Python-{entry['version']}"

    if python_source.exists():
        print(f"Removing existing source directory: {python_source}")
        shutil.rmtree(python_source)

    print(f"Extracting Python {python_archive}")
    extract_tar_to_directory(python_archive, CPYTHON_PATH)

    # Apply our patches
    if (patch_file := PATCH_DIR / f"{python}.patch").exists():
        print(f"Applying patch file {patch_file} to {python_source}")
        subprocess.run(
            ["patch", "-p1", "-i", str(patch_file)],
            cwd=python_source,
            check=True,
            bufsize=0,
        )

    # Apply platform patches
    if (patch_file := PATCH_DIR / f"{python}-{platform}.patch").exists():
        print(f"Applying platform patch file {patch_file} to {python_source}")
        subprocess.run(
            ["patch", "-p1", "-i", str(patch_file)],
            cwd=python_source,
            check=True,
            bufsize=0,
        )

    # Copy our additional source files
    shutil.copytree(SRC_DIR, python_source, dirs_exist_ok=True)

    return python_source


if __name__ == "__main__":
    try:
        sys.exit(main())
    except subprocess.CalledProcessError as e:
        sys.exit(e.returncode)
