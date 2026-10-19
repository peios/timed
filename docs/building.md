# Building timed

Use Linux, the pinned Rust toolchain in `rust-toolchain.toml`, a C compiler,
libclang, pkg-config, Python 3, and binutils. `./bazel` selects the Bazel
version in `.bazelversion`. Repository rules pin external dependencies;
`Cargo.lock` and `MODULE.bazel.lock` are part of the source inputs.

## Development build

Set `PEIOS_SDK` to a directory containing matched Peios headers and
`lib/libpeios.so.0`. To prepare one from an explicit consolidated SDK
checkout, choose a fresh output directory:

```sh
python3 tools/prepare-dev-sdk.py /path/to/peios-sdk /path/to/dev-sdk
export PEIOS_SDK=/path/to/dev-sdk
./bazel test //...
./bazel build //:packages
```

The helper records the SDK commit, working-tree state, and file hashes.
Tests use local fixtures and mocked protocol peers; they do not configure
the host service. C ABI and Rust wrapper tests exercise the shared library.

For PSC, generator consistency, Bazel tests, packaging, Cargo Clippy, and
Rust documentation tests, prepare the pinned style tools and run:

```sh
python3 tools/prepare-style-tools.py /path/to/style-tools
export PEIOS_STYLE_BIN=/path/to/style-tools/bin
tools/check
```

Set `TRAIL` to the maintained Trail executable and run `tools/check-docs`.
Use `tools/check-docs --context /path/to/learn` to check the complete
publication tree. A standalone component build checks an exact list of
external-link diagnostics; it does not validate those external targets.

## Native and offline builds

Acquire dependencies from the final source and lockfiles while network
access is available:

```sh
tools/offline-build acquire /path/to/frozen-inputs
```

Then run inside a prepared, isolated Peios userspace. It must provide the
Peios Rust compiler and standard library, C toolchain, Python, binutils,
locale data, and a matching native C SDK. Set `PEIOS_RUSTC` and `PEIOS_SDK`;
the caller owns isolation and the compiler/SDK provenance.

```sh
tools/offline-build test /path/to/frozen-inputs /path/to/private-build
```

The native configuration selects the Peios compiler, requires the frozen
module lock, disables dependency downloads, and checks native hardening
when assembling packages. Use a fresh acquisition after lockfile changes.
Passing this userspace build does not qualify boot, service permissions,
registry integration, or actual network behavior in a Peios guest.

## Maintaining generated interfaces

`tools/timed-api.json` owns generated ABI types, views, and wrapper decoding.
Run `python3 tools/generate-api-types.py` after changing its schema, then
run the formatter and the full checks. ABI changes require explicit
compatibility review; passing code generation does not establish ABI
compatibility.

Keep fuzz targets under `fuzz/`. Corpus and artifact directories are local
validation output and are excluded from corresponding-source packages.
