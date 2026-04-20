# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import importlib.machinery
import io
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Optional

TERMINFO_DIRS = [
    "/etc/terminfo",
    "/lib/terminfo",
    "/usr/share/terminfo",
]

TCL_PATHS = [
    # POSIX
    ("lib", "tcl", "tcl"),
    # Windows.
    ("tcl",),
]

HERE = os.path.dirname(sys.executable)
INSTALL_ROOT = os.path.dirname(HERE)

# Need to set TCL_LIBRARY so local tcl/tk files get picked up.
for parts in TCL_PATHS:
    candidate = os.path.join(INSTALL_ROOT, *parts)

    if os.path.exists(candidate):
        os.environ["TCL_LIBRARY"] = candidate
        break

# Need to set TERMINFO_DIRS so terminfo database can be located.
if "TERMINFO_DIRS" not in os.environ:
    terminfo_dirs = [p for p in TERMINFO_DIRS if os.path.exists(p)]
    if terminfo_dirs:
        os.environ["TERMINFO_DIRS"] = ":".join(terminfo_dirs)


class TestPythonInterpreter(unittest.TestCase):
    def test_pystandalone(self):
        import _pystandalone  # type: ignore

        assert _pystandalone is not None, "_pystandalone module not found"

        assert not _pystandalone.has_library(), "Unexpected library present"
        assert not _pystandalone.has_payload(), "Unexpected payload present"
        assert not _pystandalone.has_bootstrap(), "Unexpected bootstrap present"

        assert _pystandalone.get_library() is None
        assert _pystandalone.get_bootstrap() is None
        assert _pystandalone.get_payload() is None

        buf = _pystandalone.rand_bytes(10)
        assert isinstance(buf, bytes) and len(buf) == 10

        assert _pystandalone.ciphers

        for name, key_len, iv_len, expected in [
            ("aes-256-cbc", 32, 16, "4272671e68ed88bb2c8d1006920083ab"),
            ("aes-192-cbc", 24, 16, "edd9764f98be22399bdf7892b77d2450"),
            ("aes-128-cbc", 16, 16, "4d0f1cb7b95156fb94bc31ee34a3f461"),
            ("aes-256-ecb", 32, 0, "be93ce4e7fff84620c170e74a572d73a"),
            ("aes-192-ecb", 24, 0, "e76a1ec14da673b424527c8e991d3d44"),
            ("aes-128-ecb", 16, 0, "dfde7f4034e4f56c1ba162edf8359f41"),
            ("aes-256-gcm", 32, 12, "374f5886f101f65244bafc8122e9b7a0"),
        ]:
            try:
                cipher = _pystandalone.cipher(name, b"\x69" * key_len, b"\x67" * iv_len)
            except ValueError as e:
                raise ValueError(f"cipher {name} is unsupported") from e

            assert cipher.encrypt(b"\x42" * 16) == bytes.fromhex(expected), (
                f"cipher {name} did not return the expected value"
            )

        public_key = """
-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgGcYJbjRfFzEyqUJllBLXXAl/KYf
nng5tHAwY1CmOkhdJc4c+vPlXewaiNzQl7XWW9491Is5K24q6kKfUUw7HGOSW4IV
+BXnbCQJX2mvKE1W6/ajdzQ3mnX1glG7PehZvVTgntfRrAjasHRo+hslE5nYNMWZ
os91j5H7o/zhdI/JAgMBAAE=
-----END PUBLIC KEY-----
    """

        cipher = _pystandalone.rsa(public_key.strip())
        assert cipher.encrypt(b"This is a test!"), "RSA encryption failed"

        import hashlib

        assert (
            hashlib.sha256(cipher.der()).hexdigest()
            == "983bc41ea25170b001189b8344a8fbd8dba1a07c0c353f96dbd36b84be1255e0"
        ), "RSA DER output is incorrect"

        import zipfile
        import zipimport

        for func in (
            zipimport.metazipimporter.__init__,
            zipimport._read_directory,
            zipimport._get_data,
        ):
            assert "buf" in func.__code__.co_varnames

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("hello.py", "print('Hello, world!')")

        meta_zip = zipimport.metazipimporter("<archive>", buf.getvalue())
        assert meta_zip.archive == "<archive>"
        assert meta_zip._buf == buf.getvalue()

        meta_spec = meta_zip.find_spec("hello")
        assert meta_spec.name == "hello"
        assert meta_spec.origin == f"<archive>{os.sep}hello.py"
        assert meta_zip.get_data("hello.py") == b"print('Hello, world!')"

        import datetime

        assert datetime.timezone.utc, "Issues with datetime module"

        import subprocess

        if sys.platform == "win32":
            result = subprocess.run(
                ["cmd", "/c", "echo Hello from pystandalone"], capture_output=True
            )
        else:
            result = subprocess.run(
                ["echo", "Hello from pystandalone"], capture_output=True
            )

        assert result.returncode == 0, "Subprocess call failed"
        assert result.stdout.strip() == b"Hello from pystandalone", (
            "Subprocess output is incorrect"
        )

    def test_compression(self):
        import bz2
        import lzma
        import zlib

        self.assertTrue(lzma.is_check_supported(lzma.CHECK_CRC64))
        self.assertTrue(lzma.is_check_supported(lzma.CHECK_SHA256))

        bz2.compress(b"test")
        zlib.compress(b"test")

    def test_ctypes(self):
        import ctypes

        # pythonapi will be None on statically linked binaries.
        is_static = "static" in os.environ["BUILD_OPTIONS"]
        if is_static:
            self.assertIsNone(ctypes.pythonapi)
        else:
            self.assertIsNotNone(ctypes.pythonapi)

        # https://bugs.python.org/issue42688
        @ctypes.CFUNCTYPE(None, ctypes.c_int, ctypes.c_char_p)
        def error_handler(fif, message):
            pass

    @unittest.skipIf(os.name == "nt", "curses not available on Windows")
    @unittest.skipIf(True, "curses is disabled in pystandalone")
    def test_curses_import(self):
        import curses

        assert curses is not None

    @unittest.skipIf(os.name == "nt", "curses not available on Windows")
    @unittest.skipIf("TERM" not in os.environ, "TERM not set")
    @unittest.skipIf(True, "curses is disabled in pystandalone")
    def test_curses_interactive(self):
        import curses

        curses.initscr()
        curses.endwin()

    def test_hashlib(self):
        import hashlib

        wanted_hashes = {
            "blake2b",
            "blake2s",
            "md5",
            "md5-sha1",
            "ripemd160",
            "sha1",
            "sha224",
            "sha256",
            "sha384",
            "sha3_224",
            "sha3_256",
            "sha3_384",
            "sha3_512",
            "sha512",
            "sha512_224",
            "sha512_256",
            "shake_128",
            "shake_256",
            "sm3",
        }

        # Legacy algorithms only present on OpenSSL 1.1.
        if os.name == "nt" and sys.version_info[0:2] < (3, 11):
            wanted_hashes.add("md4")
            wanted_hashes.add("whirlpool")

        for hash in wanted_hashes:
            self.assertIn(hash, hashlib.algorithms_available)

    @unittest.skipIf(os.name == "nt", "_testcapi not built on Windows")
    @unittest.skipIf(
        os.environ["TARGET_TRIPLE"].endswith("-musl")
        and "static" in os.environ["BUILD_OPTIONS"],
        "_testcapi not available on statically-linked distributions",
    )
    @unittest.skipIf(True, "_testcapi is disabled in pystandalone")
    def test_testcapi(self):
        import _testcapi  # type: ignore

        self.assertIsNotNone(_testcapi)

        if sys.version_info[0:2] >= (3, 13):
            import _testlimitedcapi  # type: ignore

            self.assertIsNotNone(_testlimitedcapi)

    @unittest.skipIf(True, "sqlite3 is disabled in pystandalone")
    def test_sqlite(self):
        import sqlite3

        self.assertEqual(sqlite3.sqlite_version_info, (3, 50, 4))

        # Optional SQLite3 features are enabled.
        conn = sqlite3.connect(":memory:")
        # Extension loading enabled.
        self.assertTrue(hasattr(conn, "enable_load_extension"))
        # Backup feature requires modern SQLite, which we always have.
        self.assertTrue(hasattr(conn, "backup"))
        # Ensure that various extensions are present. These will raise if they are not.
        extensions = ["fts3", "fts4", "fts5", "geopoly", "rtree"]
        cursor = conn.cursor()
        for extension in extensions:
            with self.subTest(extension=extension):
                cursor.execute(
                    f"CREATE VIRTUAL TABLE test{extension} USING {extension}(a, b, c);"
                )

        # Test various SQLite flags and features requested / expected by users.
        # The DBSTAT virtual table shows some metadata about disk usage.
        # https://www.sqlite.org/dbstat.html
        self.assertNotEqual(
            cursor.execute("SELECT COUNT(*) FROM dbstat;").fetchone()[0],
            0,
        )

        # The serialize/deserialize API is configurable at compile time.
        if sys.version_info[0:2] >= (3, 11):
            self.assertEqual(conn.serialize()[:15], b"SQLite format 3")

        # The "enhanced query syntax" (-DSQLITE_ENABLE_FTS3_PARENTHESIS) allows parenthesizable
        # AND, OR, and NOT operations. The "standard query syntax" only has OR as a keyword, so we
        # can test for the difference with a query using AND.
        # https://www.sqlite.org/fts3.html#_set_operations_using_the_enhanced_query_syntax
        cursor.execute("INSERT INTO testfts3 VALUES('hello world', '', '');")
        self.assertEqual(
            cursor.execute(
                "SELECT COUNT(*) FROM testfts3 WHERE a MATCH 'hello AND world';"
            ).fetchone()[0],
            1,
        )

        # fts3_tokenizer() takes/returns native pointers. Newer SQLite versions require the use of
        # bound parameters with this function to avoid the risk of a SQL injection esclating into a
        # full RCE. This requirement can be disabled at either compile time or runtime for
        # backwards compatibility. Ensure that the check is enabled (more secure) by default but
        # applications can still use fts3_tokenize with a bound parameter. See discussion at
        # https://github.com/astral-sh/python-build-standalone/pull/562#issuecomment-3254522958
        wild_pointer = struct.pack("P", 0xDEADBEEF)
        with self.assertRaises(sqlite3.OperationalError) as caught:
            cursor.execute(
                f"SELECT fts3_tokenizer('mytokenizer', x'{wild_pointer.hex()}')"
            )
        self.assertEqual(str(caught.exception), "fts3tokenize disabled")
        cursor.execute("SELECT fts3_tokenizer('mytokenizer', ?)", (wild_pointer,))

        conn.close()

    def test_ssl(self):
        import ssl

        self.assertTrue(ssl.HAS_TLSv1)
        self.assertTrue(ssl.HAS_TLSv1_1)
        self.assertTrue(ssl.HAS_TLSv1_2)
        self.assertTrue(ssl.HAS_TLSv1_3)

        # OpenSSL 1.1 on older CPython versions on Windows. 3.5 everywhere
        # else. The format is documented a bit here:
        # https://docs.openssl.org/1.1.1/man3/OPENSSL_VERSION_NUMBER/
        # https://docs.openssl.org/3.5/man3/OpenSSL_version/
        # For 1.x it is the three numerical version components, the
        # suffix letter as a 1-based integer, and 0xF for "release". For
        # 3.x it is the major, minor, 0, patch, and 0.
        if os.name == "nt" and sys.version_info[0:2] < (3, 11):
            wanted_version = (1, 1, 1, 23, 15)
        else:
            wanted_version = (3, 5, 0, 5, 0)

        self.assertEqual(ssl.OPENSSL_VERSION_INFO, wanted_version)

        ssl.create_default_context()

    @unittest.skipIf(
        sys.version_info[:2] < (3, 13),
        "Free-threaded builds are only available in 3.13+",
    )
    def test_gil_disabled(self):
        import sysconfig

        if "freethreaded" in os.environ.get("BUILD_OPTIONS", "").split("+"):
            wanted = 1
        else:
            wanted = 0

        self.assertEqual(sysconfig.get_config_var("Py_GIL_DISABLED"), wanted)

    @unittest.skipIf(
        sys.version_info[:2] < (3, 14),
        "zstd is only available in 3.14+",
    )
    def test_zstd_multithreaded(self):
        from compression import zstd  # type: ignore

        max_threads = zstd.CompressionParameter.nb_workers.bounds()[1]
        assert max_threads > 0, (
            "Expected multithreading to be enabled but max threads is zero"
        )

    @unittest.skipIf("TCL_LIBRARY" not in os.environ, "TCL_LIBRARY not set")
    @unittest.skipIf("DISPLAY" not in os.environ, "DISPLAY not set")
    @unittest.skipIf(True, "tkinter is disabled in pystandalone")
    def test_tkinter(self):
        import tkinter as tk

        class Application(tk.Frame):
            def __init__(self, master=None):
                super().__init__(master)
                self.master = master
                self.pack()

                self.hi_there = tk.Button(self)
                self.hi_there["text"] = "Hello World\n(click me)"
                self.hi_there["command"] = self.say_hi
                self.hi_there.pack(side="top")

                self.quit = tk.Button(
                    self, text="QUIT", fg="red", command=self.master.destroy
                )
                self.quit.pack(side="bottom")

            def say_hi(self):
                print("hi there, everyone!")

        root = tk.Tk()
        Application(master=root)

    def test_hash_algorithm(self):
        self.assertTrue(
            sys.hash_info.algorithm.startswith("siphash"),
            msg=f"{sys.hash_info.algorithm=!r} is not siphash",
        )

    def test_libc_identity(self):
        def assertLibc(value):
            for libc in ("-gnu", "-musl"):
                if os.environ["TARGET_TRIPLE"].endswith(libc):
                    self.assertIn(libc, value)
                else:
                    self.assertNotIn(libc, value)

        if hasattr(sys.implementation, "_multiarch"):
            assertLibc(sys.implementation._multiarch)

        assertLibc(importlib.machinery.EXTENSION_SUFFIXES[0])

    @unittest.skipIf(
        sys.version_info[:2] < (3, 11),
        "not yet implemented",
    )
    @unittest.skipIf(os.name == "nt", "no symlinks or argv[0] on Windows")
    def test_getpath(self):
        def assertPythonWorks(path: Path, argv0: Optional[str] = None):
            output = subprocess.check_output(
                [argv0 or path, "-c", "print(42)"], executable=path, text=True
            )
            self.assertEqual(output.strip(), "42")

        with tempfile.TemporaryDirectory(prefix="verify-distribution-") as t:
            tmpdir = Path(t)
            symlink = tmpdir / "python"
            symlink.symlink_to(sys.executable)
            with self.subTest(msg="symlink without venv"):
                assertPythonWorks(symlink)

            # TODO: --copies does not work right
            for flag in ("--symlinks",):
                with self.subTest(flag=flag):
                    venv = tmpdir / f"venv_{flag}"
                    subprocess.check_call(
                        [symlink, "-m", "venv", flag, "--without-pip", venv]
                    )
                    assertPythonWorks(venv / "bin" / "python")

        with self.subTest(msg="weird argv[0]"):
            assertPythonWorks(sys.executable, argv0="/dev/null")


if __name__ == "__main__":
    unittest.main()
