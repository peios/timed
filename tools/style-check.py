#!/usr/bin/env python3
"""Check maintained sources against the pinned PSC language profiles."""

import os
import shutil
import subprocess
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def tool(name: str, expected: str) -> str:
    directory = os.environ.get("PEIOS_STYLE_BIN")
    path = str(Path(directory) / name) if directory else shutil.which(name)
    if path is None:
        raise SystemExit(f"missing {name}; run tools/prepare-style-tools.py OUTSIDE_REPO")
    version = subprocess.check_output([path, "--version"], text=True)
    if expected not in version.splitlines():
        raise SystemExit(f"unexpected {name} version: {version.strip()}")
    return path


def run(args: list[str]) -> None:
    subprocess.run(args, cwd=ROOT, check=True)


def main() -> None:
    python = sorted(
        str(p.relative_to(ROOT))
        for root in ("tools", "packages")
        for p in (ROOT / root).glob("*.py")
    )
    if (ROOT / "tools/check-docs").exists():
        python.append("tools/check-docs")
    ruff = tool("ruff", "ruff 0.17.0")
    run([ruff, "check", "--no-cache", "--config", "tools/ruff.toml", *python])
    run([ruff, "format", "--check", "--no-cache", "--config", "tools/ruff.toml", *python])
    shell = ["bazel", "tools/check", "tools/offline-build"] + sorted(
        str(p.relative_to(ROOT))
        for directory in ("tests", "libexec")
        for p in (ROOT / directory).rglob("*")
        if p.is_file() and (p.suffix == ".sh" or p.parent.name == "libexec")
    )
    run([tool("shellcheck", "version: 0.11.0"), *shell])
    run([tool("shfmt", "v3.14.1"), "-d", "-i", "4", *shell])
    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]
    roots = [name for name in workspace["members"] if not name.startswith("vendor/")]
    starlark = [
        str(p.relative_to(ROOT))
        for p in ROOT.rglob("*")
        if p.is_file()
        and (p.name == "BUILD.bazel" or p.suffix == ".bzl")
        and not {"target", ".git", ".ci-sdk"} & set(p.relative_to(ROOT).parts)
    ]
    starlark.append("MODULE.bazel")
    directory = os.environ.get("PEIOS_STYLE_BIN")
    buildifier = str(Path(directory) / "buildifier") if directory else "buildifier"
    if "buildifier version: 10.1.0" not in [
        line.strip()
        for line in subprocess.check_output([buildifier, "--version"], text=True).splitlines()
    ]:
        raise SystemExit("buildifier must be version 10.1.0")
    run(
        [
            buildifier,
            "-mode=check",
            "-lint=warn",
            "-warnings=load,unused-variable,function-docstring",
            *starlark,
        ]
    )
    clang_format = tool("clang-format", "clang-format version 18.1.8")
    headers = sorted(
        str(path.relative_to(ROOT))
        for path in (ROOT / "libtimed").rglob("*")
        if path.suffix in {".h", ".c"}
    )
    run([clang_format, "--dry-run", "--Werror", "--style=file:tools/clang-format.yaml", *headers])
    data = sorted(
        str(p.relative_to(ROOT))
        for root in ("packages", ".github")
        for p in (ROOT / root).rglob("*")
        if p.suffix in {".json", ".yml"}
    )
    if data:
        run([tool("prettier", "3.9.10"), "--config", "tools/prettier.json", "--check", *data])
    run(
        [
            "rustup",
            "run",
            "1.98.1",
            "rustfmt",
            "--check",
            "--config-path",
            "tools/rustfmt.toml",
            *sorted(
                str(path.relative_to(ROOT))
                for name in roots
                for path in (ROOT / name).rglob("*.rs")
            ),
            *sorted(
                str(path.relative_to(ROOT)) for path in (ROOT / "fuzz/fuzz_targets").glob("*.rs")
            ),
            "packages/check_blobs.rs",
        ]
    )


if __name__ == "__main__":
    main()
