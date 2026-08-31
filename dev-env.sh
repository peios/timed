# Source this for local `cargo` runs outside pekit.
#
#   . ./dev-env.sh && cargo test
#
# pekit's build does this itself (see pekit.toml); this is the same thing
# for the working copy, so that `cargo test` in a checkout does not need a
# libpeios-devel installed in the build root. Nothing here is shipped.
set -e
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
LIBPEIOS="$REPO_ROOT/libpeios"
PKM_UAPI="$REPO_ROOT/pkm/out/build/headers/usr/include"

[ -f "$LIBPEIOS/target/release/libpeios.so" ] || \
  cargo build --release --manifest-path "$LIBPEIOS/Cargo.toml"

PC_DIR="$(mktemp -d)"
cat > "$PC_DIR/peios.pc" <<PC
prefix=$LIBPEIOS
exec_prefix=\${prefix}
libdir=$LIBPEIOS/target/release
includedir=$LIBPEIOS/include

Name: peios
Description: Peios userspace C ABI library (libpeios)
Version: 0.5.0
Libs: -L\${libdir} -lpeios
Cflags: -I\${includedir} -I$PKM_UAPI
PC

export PKG_CONFIG_PATH="$PC_DIR${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export BINDGEN_EXTRA_CLANG_ARGS="-isystem $(gcc -print-file-name=include) ${BINDGEN_EXTRA_CLANG_ARGS:-}"
export LD_LIBRARY_PATH="$LIBPEIOS/target/release${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
set +e
