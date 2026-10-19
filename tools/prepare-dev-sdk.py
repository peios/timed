#!/usr/bin/env python3
"""Build a development C SDK from an explicit consolidated source checkout."""

import argparse
import hashlib
import json
import shutil
import subprocess
import tomllib
from pathlib import Path


def output(source: Path, command: list[str]) -> str:
    """Read a successful command's standard output without hiding diagnostics."""
    return subprocess.check_output(command, cwd=source, text=True).strip()


def prepare(source: Path, destination: Path, output_base: Path | None) -> None:
    """Install matched headers and libraries and record their source provenance."""
    if destination.exists():
        raise ValueError("destination must not exist; choose a fresh SDK directory")
    if destination == source or source in destination.parents:
        raise ValueError("put development SDK output outside the source checkout")
    bazel = [str(source / "bazel")]
    if output_base:
        bazel.append(f"--output_base={output_base}")
    targets = {"libpeios.so.0": "//libpeios:shared", "libpeios.a": "//libpeios:static"}
    subprocess.run([*bazel, "build", *targets.values()], cwd=source, check=True)
    execution_root = Path(output(source, [*bazel, "info", "execution_root"]))
    libraries = {}
    for name, target in targets.items():
        files = output(source, [*bazel, "cquery", target, "--output=files"]).splitlines()
        if len(files) != 1:
            raise RuntimeError(f"expected one library for {target}, got {files}")
        libraries[name] = execution_root / files[0]
    version = tomllib.loads((source / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    destination.mkdir(parents=True)
    shutil.copytree(source / "libpeios/include", destination / "include")
    shutil.copytree(source / "vendor/kernel/include/uapi/pkm", destination / "include/pkm")
    lib = destination / "lib"
    lib.mkdir()
    for name, library in libraries.items():
        shutil.copyfile(library, lib / name)
    (lib / "libpeios.so").symlink_to("libpeios.so.0")
    pc = lib / "pkgconfig"
    pc.mkdir()
    (pc / "peios.pc").write_text(
        f"prefix={destination}\nlibdir=${{prefix}}/lib\nincludedir=${{prefix}}/include\n"
        f"Name: peios\nDescription: Peios development C SDK\nVersion: {version}\n"
        "Libs: -L${libdir} -lpeios\nCflags: -I${includedir}\n"
    )
    provenance = {
        "version": version,
        "commit": output(source, ["git", "rev-parse", "HEAD"]),
        "status": output(source, ["git", "status", "--porcelain"]),
        "diff_sha256": hashlib.sha256(
            subprocess.check_output(["git", "diff", "HEAD"], cwd=source)
        ).hexdigest(),
        "kernel": json.loads((source / "vendor/kernel/ORIGIN.json").read_text()),
        "sha256": {
            str(path.relative_to(destination)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(destination.rglob("*"))
            if path.is_file()
        },
    }
    (destination / "provenance.json").write_text(json.dumps(provenance, indent=4) + "\n")


def main() -> None:
    """Parse explicit source and output paths for local builds and CI."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--output-base", type=Path)
    args = parser.parse_args()
    prepare(
        args.source.resolve(),
        args.destination.resolve(),
        args.output_base.resolve() if args.output_base else None,
    )


if __name__ == "__main__":
    main()
