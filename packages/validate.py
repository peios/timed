"""Check timed's staged network payload without launching applications or applying seeds."""

import gzip
import json
import os
import re
import subprocess
from pathlib import Path

FAMILY = json.loads(Path("packages/family.json").read_text())
LIBDIR = "usr/lib/x86_64-linux-peios"


def require(condition: bool, message: str) -> None:
    """Keep package gates effective when Python assertions are disabled."""
    if not condition:
        raise ValueError(message)


def readelf(path: Path, option: str) -> str:
    """Read one ELF view, tolerating binary CRC bytes in the debug-link section."""
    return subprocess.check_output(
        ["readelf", option, str(path)],
        text=True,
        errors="replace",
        env=os.environ | {"LC_ALL": "C"},
    )


def build_id(notes: str, path: Path) -> str:
    """Extract the single GNU build identity required by split debugging."""
    matches = re.findall(r"Build ID: ([0-9a-f]+)", notes)
    require(len(matches) == 1 and len(matches[0]) >= 3, f"{path}: missing or ambiguous build ID")
    return matches[0]


def validate_elf(stage: Path, binary: str, *, native: bool) -> None:
    """Require linked hardening and the matching shared-family split debug payload."""
    library = binary in FAMILY["sonames"]
    elf = stage / FAMILY["destinations"][binary]
    require(elf.is_file() and os.access(elf, os.X_OK), f"{elf}: missing executable")
    header, program, dynamic = (readelf(elf, option) for option in ("-h", "-lW", "-dW"))
    notes, sections = readelf(elf, "-n"), readelf(elf, "-SW")
    require(bool(re.search(r"Type:\s+DYN\b", header)), f"{elf}: not position independent")
    require("GNU_RELRO" in program and "BIND_NOW" in dynamic, f"{elf}: missing full RELRO")
    stack = [line for line in program.splitlines() if "GNU_STACK" in line]
    require(len(stack) == 1 and bool(re.search(r"\sRW\s", stack[0])), f"{elf}: executable stack")
    if not library:
        require(bool(re.search(r"FLAGS_1.*\bPIE\b", dynamic)), f"{elf}: missing PIE flag")
    for needed in FAMILY["needed"].get(binary, []):
        require(f"Shared library: [{needed}]" in dynamic, f"{elf}: missing {needed}")
    if library:
        soname = FAMILY["sonames"][binary]
        require(f"Library soname: [{soname}]" in dynamic, f"{elf}: wrong SONAME")
    if binary == "nss":
        require(
            "libpeios" not in dynamic and "libgcc_s" not in dynamic,
            f"{elf}: unexpected NSS dependency",
        )
    require(not re.search(r"\((RPATH|RUNPATH|TEXTREL)\)", dynamic), f"{elf}: unsafe dynamic tag")
    require(".debug_info" not in sections, f"{elf}: unsplit debug information")
    if native:
        require("IBT" in notes and "SHSTK" in notes, f"{elf}: missing native CET properties")
        require(bool(re.search(r"\(RELR\)", dynamic)), f"{elf}: missing native packed relocations")
    identity = build_id(notes, elf)
    component = binary
    debug = stage / f"debug/{component}/usr/lib/debug/.build-id/{identity[:2]}/{identity[2:]}.debug"
    require(debug.is_file() and debug.stat().st_size > 0, f"{elf}: missing split debug file")
    require(".debug_info" in readelf(debug, "-SW"), f"{debug}: missing debug information")
    require(build_id(readelf(debug, "-n"), debug) == identity, f"{debug}: build ID mismatch")
    require(debug.name in readelf(elf, "--string-dump=.gnu_debuglink"), f"{elf}: wrong debug link")
    forbidden = {str(Path.cwd().resolve()), str(Path.cwd().resolve()).split("/execroot/")[0]}
    for path in (elf, debug):
        contents = path.read_bytes()
        for prefix in forbidden:
            require(len(prefix) <= 1 or prefix.encode() not in contents, f"{path}: leaked {prefix}")


def validate_data(stage: Path) -> None:
    """Validate preserved seeds and references without applying machine policy."""
    for source in Path("registry.d").glob("*.reg"):
        target = stage / "usr/share/regim" / source.name
        require(target.read_bytes() == source.read_bytes(), f"changed seed: {source}")
    for source in Path("docs").glob("*"):
        if source.suffix in {".regman", ".evman"}:
            target = stage / ("usr/share/" + source.suffix[1:]) / source.name
            require(target.read_bytes() == source.read_bytes(), f"changed reference: {source}")
    for source in Path("docs/man").iterdir():
        target = stage / f"usr/share/man/man{source.suffix[1:]}/{source.name}.gz"
        with gzip.open(target, "rb") as stream:
            require(stream.read() == source.read_bytes(), f"changed manual: {source}")
    library = FAMILY["library"]
    require(
        (stage / LIBDIR / (library + ".so")).readlink() == Path(library + ".so.1"),
        "wrong linker symlink",
    )
    for suffix in (".h", "-types.h"):
        require(
            (stage / "usr/include/peios" / (FAMILY["api"] + suffix)).is_file(),
            "missing public header",
        )


def validate(stage: Path, *, native: bool, sdk: Path) -> None:
    """Check linked binaries and inert payloads; never launch a privileged service."""
    require(sdk.is_dir(), "missing declared SDK")
    for binary in FAMILY["destinations"]:
        validate_elf(stage, binary, native=native)
    validate_data(stage)
