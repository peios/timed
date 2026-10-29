# Building timed

Use pekit to build the time daemon, its clock command, and its C client
library, and to run their tests. Pekit builds each crate on its
own, so a change rebuilds only the crates it reaches. The supported
development host is x86-64 Linux.

## Before you start

You need pekit and Git. Everything else is pinned and fetched by pekit on
the first build: the Bootlin C toolchain, Rust 1.98.1 with Clippy, libclang,
and the crates `Cargo.lock` selects. The first build needs network access;
later builds find what they need in pekit's store, and every step runs
without network access in a sandbox that holds only its declared inputs.

The build files use the gcslib libraries named in `workspace.gcsl` and the
build files, and the libraries of peios-rs and the Peios SDK. `pekit lock`
pins their commits in `pekit.lock`.

## Build

```sh
pekit build timed clock libtimed
```

| Target | Output |
|---|---|
| `timed` | Time daemon |
| `clock` | Clock command, a client of timed's socket |
| `libtimed` | Public C client library, `libtimed.so.1` by its shared object name (SONAME) |
| `libresolvd`, `libtrust` | resolvd's and trustd's C client libraries, built from the crates timed vendors |

Pekit prints where each output is, under `pekit-out/<target>/`. The
programs load `libpeios.so.0` by its SONAME. timed also loads
`libresolvd.so.1` and `libtrust.so.1`, and `clock` loads `libtimed.so.1`.
They carry no runtime search path, so running them needs those libraries
installed. Do not run the daemon on
the development host as part of a build check.

## Test

```sh
pekit test
```

Each member's unit and integration tests are a test of their own, named
after the member: `timed_core`, `ntp`, and so on. The crates timed vendors
from netd, resolvd, and trustd, in `vendor/`, are members too, and their
tests run the same way: `netd_core`, `trust_client`, and so on. Further
tests check what the C clients promise, and the owned members'
documentation and lints:

| Test | Check |
|---|---|
| `abi` | A C program that includes the public header, links libtimed, and calls it |
| `resolvd_c_abi`, `trust_c_abi` | The same check of the vendored libresolvd and libtrust |
| `doctests` | Each owned member's documentation tests, as `cargo test --doc` runs them |
| `clippy` | Clippy's checks of every target of every owned member, with every warning denied |

A test whose inputs did not change is found in the store and not run
again. Tests use local fixtures and mocked protocol peers; they do not
configure the host service. The C ABI and Rust wrapper tests exercise the
shared libraries.

For the full contributor check, install the pinned PSC tools into a
directory outside the repository, then run the shared entry point:

```sh
python3 tools/prepare-style-tools.py "$HOME/.cache/timed-style"
export PEIOS_STYLE_BIN="$HOME/.cache/timed-style/bin"
tools/check
```

`tools/check` checks owned source formatting and lint with Ruff,
ShellCheck, shfmt, clang-format, Prettier, and rustfmt. It then checks the
generated interfaces and runs `pekit test`. The style checks use the host's
Rust 1.98.1 formatter through rustup. The tool versions and hashes are
recorded in `tools/style-tools.lock.json`. GitHub's workflow runs the style
checks alone; builds and tests run with pekit.

Set `TRAIL` to the maintained Trail executable and run `tools/check-docs`.
Use `tools/check-docs --context /path/to/learn` to check the complete
publication tree. A standalone component build checks an exact list of
external-link diagnostics; it does not validate those external targets.

## How the build is planned

`build.gcsl` plans the Cargo workspace with the gcslib rust library's
`workspace`: Cargo works out each member's build, unit by unit, and pekit
compiles each unit as a step. Planning reads the manifests, `Cargo.lock`,
and which files exist, never the sources, so editing a source plans nothing
again.

Keep Rust dependency versions in the Cargo manifests and `Cargo.lock`, and
update the lockfile deliberately with Cargo. A package that needs more than
its manifest says is given it in `build.gcsl`:

- `peios-sys` generates its bindings from the SDK's headers with bindgen and
  links libpeios, so it, and every crate that depends on it, is given what
  peios-rs's library says it needs, `crate_settings()`: libpeios and its
  headers;
- `timed`'s build script reads the release epoch in `build/epoch.txt`;
- `timed-client`, `resolvd-client`, and `trust-client` each link their C
  client library, so they, and everything that depends on them, are given
  the library pekit builds;
- `trust-client`'s tests read trust-core's test certificates.

libpeios and its headers are built from the Peios SDK's own files, through
the SDK's GCSL library, which peios-rs's library imports. The commits
`pekit.lock` pins say which SDK and which peios-rs; the rust library fails a
build whose `Cargo.lock` takes peios-rs's crates at another commit than
`pekit.lock` pins its library at, so the crates and the settings they are
built with always agree. The other Peios daemons take the same peios-rs
commit.

## Not built with pekit yet

Packages and builds with the native Peios toolchain, which hardens
programs with control-flow enforcement technology (CET), are not yet built
with pekit. The package definitions and native build settings from the
Bazel build are kept outside this repository until they are. Registry
seeds and the `libexec/prepare-state` hook are package content; building
does not apply them.

## Maintaining generated interfaces

`tools/timed-api.json` owns generated ABI types, views, and wrapper decoding.
Run `python3 tools/generate-api-types.py` after changing its schema, then
run the formatter and the full checks. ABI changes need explicit
compatibility review; passing code generation does not establish ABI
compatibility.

Keep fuzz targets under `fuzz/`. Corpus and artifact directories are local
validation output and are excluded from corresponding-source packages.
