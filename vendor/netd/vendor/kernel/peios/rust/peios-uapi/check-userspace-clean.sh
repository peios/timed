#!/usr/bin/env bash
# Verify the PKM UAPI headers are userspace-clean.
#
# The headers must compile with an ordinary, non-kernel C compiler — the
# precondition for the cgo -godefs binding generator and for any userspace
# consumer of the PKM ABI. <linux/types.h> / <linux/ioctl.h> resolve to the
# host's /usr/include (the same userspace sysroot cgo builds against), NOT
# the kernel tree; no -D__KERNEL__, no kernel include paths.
#
# Two checks:
#   1. each header compiles standalone — catches a header that only works
#      because some other header was included before it;
#   2. the umbrella <pkm/pkm.h> compiles as a full translation unit, with
#      its internal-consistency assertions (see smoke_test.c).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cc="${CC:-cc}"
root="$(cd "$here/../../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
ln -s "$root/include/uapi/pkm" "$tmp/pkm"
cflags=(-std=c11 -Wall -Wextra -Werror -I "$tmp")

echo "check-userspace-clean: cc=$cc -I $here"

# 1. Each header compiles standalone.
for h in "$here/../../../include/uapi"/pkm/*.h; do
    rel="pkm/$(basename "$h")"
    echo "#include <$rel>" | "$cc" "${cflags[@]}" -fsyntax-only -x c -
    echo "  ok  $rel"
done

# 2. The umbrella header compiles as a translation unit.
"$cc" "${cflags[@]}" -c "$here/smoke_test.c" -o /dev/null
echo "  ok  smoke_test.c (<pkm/pkm.h>)"

# 3. The process-integrity ABI names neither None nor Isolated. The kernel
#    admits only PeiosTcb-trusted signers, so Isolated is unreachable and None
#    is the absence of a label; a constant for either would invite userspace
#    to test for states the ABI does not produce (Kernel TRM section 3.3).
if grep -En '^[[:space:]]*#[[:space:]]*define[[:space:]]+KACS_[A-Z0-9_]*(PIP|PROCESS)[A-Z0-9_]*_(NONE|ISOLATED)\b' "$here/../../../include/uapi"/pkm/*.h; then
    echo "check-userspace-clean: the ABI must not name a None or Isolated PIP state" >&2
    exit 1
fi
echo "  ok  no None/Isolated PIP constant"

# 4. Public and kernel integration headers must cite the live TRM/PCSA
#    books, never the retired PSD series. Internal crate history and README
#    prose are outside this header/ABI gate (PEI-284).
if grep -R -n --include='*.h' 'PSD-' "$root/include/uapi/pkm" \
    "$root/include/linux/kacs_mntns.h" "$root/include/linux/kacs_stratafs.h" \
    "$root/include/linux/peios_ntfe.h"; then
    echo "check-userspace-clean: replace retired PSD citations with live TRM/PCSA references" >&2
    exit 1
else
    status=$?
    [[ "$status" == 1 ]] || exit "$status"
fi
echo "  ok  no retired specification citations in ABI/integration headers"

echo "check-userspace-clean: PASS"
