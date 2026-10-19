"""Inspect the emitted PPK family, including ABI ownership and rebuild sources."""

import json
import tomllib
import unittest
from pathlib import Path

NAME = "timed"
CLIENT = "clock"
API = "timed"
LIBRARY = "libtimed"
VERSION = "0.1.10"
LIBDIR = "usr/lib/x86_64-linux-peios"
NAMES = [
    "clock",
    "clock-debuginfo",
    "libtimed",
    "libtimed-debuginfo",
    "libtimed-devel",
    "timed",
    "timed-debuginfo",
    "timed-debugsource",
    "timed-source",
]
RUNTIME = {
    "timed": "usr/sbin/timed",
    "clock": "usr/bin/clock",
    "libtimed": "usr/lib/x86_64-linux-peios/libtimed.so.1",
}


class FamilyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path("packages.store")
        self.index = json.loads((self.root / "index.json").read_text())
        self.packages = {p["name"].removeprefix("dev.peios."): p for p in self.index["packages"]}
        self.files = {
            name: tomllib.loads((self.root / p["manifest"]).read_text())["files"]
            for name, p in self.packages.items()
        }

    def test_complete_unsigned_family(self) -> None:
        self.assertEqual(set(self.packages), set(NAMES))
        self.assertFalse(self.index["release_ready"])
        for package in self.packages.values():
            self.assertEqual(package["version"], VERSION + "-1")
            self.assertFalse(package["release_ready"])
            if "build" in package:
                self.assertFalse(package["build"]["signed"])
                self.assertIn(
                    package["build"]["userspace_abi"], {"peios-native", "debian-development"}
                )
                self.assertIsInstance(package["package_metadata"]["package"]["license"], str)

    def test_runtime_ownership(self) -> None:
        for owner, path in RUNTIME.items():
            for package, files in self.files.items():
                self.assertEqual(path in files, package == owner)
            self.assertTrue(self.files[owner][path]["exec"])
        client = self.packages[CLIENT]["package_metadata"]
        self.assertEqual(client["dependencies"]["dev.peios." + LIBRARY], "= " + VERSION + "-1")
        self.assertNotIn("dev.peios." + NAME, client["dependencies"])
        self.assertFalse(
            any(p.startswith(("var/", "usr/share/regim/")) for p in self.files[CLIENT])
        )

    def test_shared_library_and_split_debug(self) -> None:
        development = self.files[LIBRARY + "-devel"]
        self.assertEqual(
            development[LIBDIR + "/" + LIBRARY + ".so"], {"symlink": LIBRARY + ".so.1"}
        )
        for path in [
            "usr/include/peios/" + API + ".h",
            "usr/include/peios/" + API + "-types.h",
            LIBDIR + "/pkgconfig/" + API + ".pc",
            "usr/share/man/man3/" + LIBRARY + ".3.gz",
        ]:
            self.assertIn(path, development)
        for component in RUNTIME:
            debug = component + "-debuginfo"
            self.assertEqual(sum(path.endswith(".debug") for path in self.files[debug]), 1)
            self.assertEqual(
                self.packages[debug]["package_metadata"]["dependencies"],
                {"dev.peios." + component: "= " + VERSION + "-1"},
            )

    def test_rebuild_source_contains_shared_boundary_and_build_rules(self) -> None:
        source = self.files[NAME + "-source"]
        for path in [
            "Cargo.toml",
            "Cargo.lock",
            "MODULE.bazel",
            "bazel",
            NAME + "/src/main.rs",
            LIBRARY + "/include/peios/" + API + ".h",
            API + "-client/src/lib.rs",
            "packages/stage.py",
            "vendor/ppk/src/lib.rs",
        ]:
            self.assertIn("usr/src/" + NAME + "/" + path, source)
        for path in source:
            self.assertFalse(
                {".git", ".ci-sdk", ".trail-cache", "__pycache__", "target", "out", "archive"}
                & set(Path(path).parts),
                path,
            )


if __name__ == "__main__":
    unittest.main()
