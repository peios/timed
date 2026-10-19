# Packaging timed

`./bazel build //:packages` writes `bazel-bin/packages.store`, containing PPK
manifests and content-addressed blobs. `packages/family.json` records the
family version, executable paths, SONAMEs, and required shared-library
relationships. Definitions under `packages/definitions/` own package
metadata, dependencies, and service integration.

The family separates runtime programs, shared-library runtime and development
files, debug symbols, shared debug sources, and corresponding source. The
manifest format remains the maintained PPK format; these outputs are
unsigned build products, not a published repository or an installation.

Development packages record their Linux development toolchain. Native builds
use `--config=peios` in an isolated Peios userspace and validate the expected
hardening and dynamic dependencies. Do not publish development artifacts as
native Peios binaries.

Registry seeds and hooks are inert package content. Building does not apply
service definitions, grant privileges, modify the registry, or start a
daemon. Image composition must select and apply those inputs explicitly.

The package-family tests check blob integrity, source closure, ownership,
symlinks, headers, manuals, and dependency metadata. License material comes
from the locked dependency closure. Generated build output, fuzz corpora,
and historical build recipes are excluded from corresponding source.
