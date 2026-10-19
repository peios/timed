#!/usr/bin/python3
"""Stage and validate declared event artifacts before writing any PPK commit."""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import TypedDict, cast

sys.dont_write_bytecode = True
from licences import collect  # noqa: E402
from validate import validate  # noqa: E402


class ComponentInput(TypedDict):
    """Declared binary and transitive source inputs from the staging rule."""

    binary: str
    inputs: list[str]


class StageSpec(TypedDict):
    """Internal staging manifest emitted by packages/build.bzl."""

    components: dict[str, ComponentInput]
    sources: list[str]
    version: str
    sdk: str
    rustc: str
    native: bool


FAMILY = json.loads(Path("packages/family.json").read_text(encoding="utf-8"))
DESTINATIONS = FAMILY["destinations"]


def copy(source: Path, target: Path) -> None:
    """Copy a file while normalizing its mode for an installed payload."""
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(0o755 if source.stat().st_mode & 0o111 else 0o644)


def split_debug(component: str, elf: Path, output: Path) -> None:
    """Split ELF debug data and record the GNU build ID and debug link."""
    notes = subprocess.check_output(["readelf", "-n", str(elf)], text=True)
    match = re.search(r"Build ID: ([0-9a-f]+)", notes)
    if not match:
        raise ValueError(f"missing build ID: {elf}")
    build_id = match.group(1)
    debug = (
        output / f"debug/{component}/usr/lib/debug/.build-id/{build_id[:2]}/{build_id[2:]}.debug"
    )
    debug.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["objcopy", "--only-keep-debug", elf, debug], check=True)
    subprocess.run(["strip", "--strip-unneeded", elf], check=True)
    subprocess.run(["objcopy", f"--add-gnu-debuglink={debug}", elf], check=True)


def source_files(inputs: list[Path]) -> list[Path]:
    """Resolve declared source files and generated bindings, rejecting missing inputs."""
    files = set()
    for path in inputs:
        if path.is_dir():
            # Generated bindings and build-script source products, not compiled archives.
            files.update(
                p for p in path.rglob("*") if p.is_file() and p.suffix in {".rs", ".h", ".c"}
            )
        elif path.is_file():
            files.add(path)
        else:
            raise ValueError(f"missing declared input: {path}")
    return sorted(files)


def stage_data(sources: list[Path], output: Path, version: str) -> None:
    """Stage inert configuration, manuals, service hooks, and C development files."""
    name, api, library = FAMILY["name"], FAMILY["api"], FAMILY["library"]
    for source in sources:
        if source.parent == Path("docs/man"):
            target = output / f"usr/share/man/man{source.suffix[1:]}/{source.name}.gz"
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("wb") as stream:
                subprocess.run(["gzip", "-n", "-9", "-c", source], stdout=stream, check=True)
        elif source.parent == Path("registry.d"):
            copy(source, output / "usr/share/regim" / source.name)
        elif source.parent == Path("docs") and source.suffix in {".regman", ".evman"}:
            copy(source, output / ("usr/share/" + source.suffix[1:]) / source.name)
        elif source.parent == Path(library + "/include/peios"):
            copy(source, output / "usr/include/peios" / source.name)
        elif source.parent == Path("libexec"):
            copy(source, output / "usr/libexec" / name / source.name)
        elif source == Path("etc/resolv.conf"):
            copy(source, output / "usr/etc/resolv.conf")
    directory = output / "usr/lib/x86_64-linux-peios"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / (library + ".so")).symlink_to(library + ".so.1")
    metadata = directory / "pkgconfig" / (api + ".pc")
    metadata.parent.mkdir(exist_ok=True)
    metadata.write_text(
        "prefix=/usr\nlibdir=${prefix}/lib/x86_64-linux-peios\nincludedir=${prefix}/include\n\n"
        f"Name: {api}\nDescription: {name} client and configuration library\n"
        f"Version: {version}\nLibs: -L${{libdir}} -l{api}\nCflags: -I${{includedir}}\n"
    )


def check_versions(sources: list[Path], version: str) -> None:
    """Require every workspace manifest and verify the owned source-family version."""
    workspace = tomllib.loads(Path("Cargo.toml").read_text())["workspace"]
    if workspace["package"]["version"] != version:
        raise ValueError("workspace version differs from Bazel")
    declared_sources = set(sources)
    for member in workspace["members"]:
        manifest = Path(member) / "Cargo.toml"
        if manifest not in declared_sources:
            raise ValueError(f"missing workspace manifest: {manifest}")
        declared = tomllib.loads(manifest.read_text())["package"]["version"]
        if not member.startswith("vendor/") and declared not in (version, {"workspace": True}):
            raise ValueError(f"source version differs from Bazel: {manifest}")


def _stage_components(
    components: dict[str, ComponentInput], output: Path, debug_inputs: set[Path]
) -> dict[str, str]:
    if set(components) != set(DESTINATIONS):
        raise ValueError("incomplete timed binary set")
    expressions = {}
    metadata = [
        p
        for p in debug_inputs
        if p.name in {"Cargo.toml", "Cargo.lock"} or p.parts[0] == "third-party"
    ]
    for name, component in components.items():
        elf = output / DESTINATIONS[name]
        copy(Path(component["binary"]), elf)
        split_debug(name, elf, output)
        inputs = source_files([Path(path) for path in component["inputs"]])
        debug_inputs.update(inputs)
        expressions[name] = collect(inputs + metadata, output / "licenses" / name)
    return expressions


def _stage_debug_sources(debug_inputs: set[Path], output: Path, sdk: Path) -> None:
    # Only source inputs declared by Bazel enter debugsource; never walk a checkout or cache.
    debug_root = output / "usr/src/debug/dev.peios.timed"
    for source in sorted(debug_inputs):
        if source.is_relative_to(sdk) or source.suffix in {".so", ".a", ".rlib", ".o"}:
            continue
        if source.is_absolute() or ".." in source.parts:
            raise ValueError(f"non-relative declared source: {source}")
        copy(source, debug_root / source)


def _check_licences(expressions: dict[str, str]) -> None:
    """Each package names the checked binary closure whose notices it ships."""
    for path in sorted(Path("packages/definitions").glob("*.json")):
        definition = json.loads(path.read_text())
        if definition["license_component"] not in expressions:
            raise ValueError(f"unknown licence closure in {path}")


def _write_build_record(
    spec: StageSpec, output: Path, debug_inputs: set[Path], expressions: dict[str, str]
) -> None:
    fingerprints = {
        str(path): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(debug_inputs)
        if path.is_file()
    }
    record = {
        "version": spec["version"],
        "userspace_abi": "peios-native" if spec["native"] else "debian-development",
        "release_ready": False,
        "signed": False,
        "checks": "native-hardening-and-payload" if spec["native"] else "development-payload",
        "input_digest": hashlib.sha256(
            json.dumps(fingerprints, sort_keys=True).encode("utf-8")
        ).hexdigest(),
        "licences": expressions,
    }
    (output / "build.json").write_text(
        json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )


def main() -> None:
    """Stage the declared build inputs and write provenance after validation succeeds."""
    spec = cast(StageSpec, json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")))
    output = Path(sys.argv[2])
    output.mkdir(parents=True, exist_ok=True)
    sources = [Path(path) for path in spec["sources"]]
    check_versions(sources, spec["version"])
    debug_inputs = set(sources)
    expressions = _stage_components(spec["components"], output, debug_inputs)
    _stage_debug_sources(debug_inputs, output, Path(spec["sdk"]))
    expressions["debugsource"] = collect(sorted(debug_inputs), output / "licenses/debugsource")
    _check_licences(expressions)
    stage_data(sources, output, spec["version"])
    os.environ["RUSTC"] = str(Path(spec["rustc"]).absolute())
    validate(output, native=spec["native"], sdk=Path(spec["sdk"]))
    _write_build_record(spec, output, debug_inputs, expressions)


if __name__ == "__main__":
    main()
