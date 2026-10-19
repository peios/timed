# timed

Peios network time, time-zone management, and the clock command.
The public client library is `libtimed.so.1`, with the safe Rust wrapper
`timed-client`.

- [Build and validate](docs/building.md).
- [Package layout and provenance](docs/packaging.md).
- [User and developer documentation](docs/learn/peios.product).
- [Command and library manuals](docs/man).

Use Bazel as the supported build and packaging interface. Development builds
run on Linux with an explicit Peios C SDK. Native package validation uses an
isolated Peios userspace and its hardened toolchain; a Linux development
build is not a native release qualification.
