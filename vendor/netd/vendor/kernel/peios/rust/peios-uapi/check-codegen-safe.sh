#!/usr/bin/env bash
# Verify the PKM UAPI headers stay within the codegen-safe subset of C.
#
# The headers are the single source of truth for the PKM ABI, and they feed
# two binding generators — bindgen (Rust) and `cgo -godefs` (Go). Those
# tools reproduce a C declaration faithfully only when it stays inside a
# disciplined subset. This linter rejects the constructs that break them:
#
#   __attribute__, #pragma pack   packed/aligned layout has no Go
#                                 equivalent; `cgo -godefs` silently emits
#                                 a struct of a different size.
#   union                         overlapping-field layout is not
#                                 reproduced predictably by either tool.
#   enum                          the underlying integer width is
#                                 implementation-defined; use #define.
#   float / double                an ABI carries no floating point.
#   non-fixed-width struct member  bare int/long/pointer widths and
#                                 bitfields are ambiguous; members must be
#                                 __u8..__u64 or __s8..__s64, with at most
#                                 one array dimension.
#
# This is a text lint: it strips comments, then scans declarations. It
# assumes the kernel style the headers already follow — one struct member
# per line, the opening brace on the `struct NAME {` line. Struct *sizes*
# (compiler-inserted padding) are not checked here; smoke_test.c asserts
# those at compile time against each header's size constant.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "check-codegen-safe: scanning pkm/*.h"

status=0
for h in "$here"/../../../include/uapi/pkm/*.h; do
    rel="pkm/$(basename "$h")"
    if awk -v file="$rel" '
	function flag(msg,   line) {
		line = $0
		sub(/^[[:blank:]]+/, "", line)
		printf "  FAIL  %s:%d: %s\n", file, FNR, msg
		printf "        | %s\n", line
		bad++
	}
	{
		# --- strip C comments, keeping per-line correspondence ---
		rest = $0; code = ""
		while (length(rest) > 0) {
			if (in_comment) {
				p = index(rest, "*/")
				if (p == 0) { rest = "" }
				else { rest = substr(rest, p + 2); in_comment = 0 }
			} else {
				b = index(rest, "/*")
				l = index(rest, "//")
				if (l > 0 && (b == 0 || l < b)) {
					code = code substr(rest, 1, l - 1); rest = ""
				} else if (b > 0) {
					code = code substr(rest, 1, b - 1)
					rest = substr(rest, b + 2); in_comment = 1
				} else {
					code = code rest; rest = ""
				}
			}
		}
		if (code ~ /^[[:blank:]]*$/) next

		# --- layout-affecting attributes ---
		if (index(code, "__attribute__") > 0)
			flag("__attribute__ changes struct layout; uapi structs must use natural layout")
		if (code ~ /^[[:blank:]]*#[[:blank:]]*pragma[[:blank:]]+pack/)
			flag("#pragma pack changes struct layout")

		# --- forbidden keywords (tokenise to avoid substring hits) ---
		toks = code
		gsub(/[^A-Za-z0-9_]/, " ", toks)
		n = split(toks, w, " ")
		for (i = 1; i <= n; i++) {
			if (w[i] == "union")
				flag("union has no portable cross-language layout")
			else if (w[i] == "enum")
				flag("enum width is implementation-defined; use #define constants")
			else if (w[i] == "float" || w[i] == "double")
				flag("floating-point types do not belong in an ABI")
		}

		# --- struct-body member discipline ---
		opener = (code ~ /(^|[^A-Za-z0-9_])struct[[:blank:]]+[A-Za-z_][A-Za-z0-9_]*[[:blank:]]*[{]/)
		depth_before = depth
		t = code; ob = gsub(/[{]/, "x", t)
		t = code; cb = gsub(/[}]/, "x", t)

		if (opener && !in_struct) {
			in_struct = 1; struct_depth = depth_before
		} else if (in_struct && !opener && code !~ /^[[:blank:]]*[}]/) {
			if (code !~ /^[[:blank:]]*__[us](8|16|32|64)[[:blank:]]+[A-Za-z_][A-Za-z0-9_]*([[:blank:]]*[[][[:blank:]]*[A-Za-z0-9_]+[[:blank:]]*[]])?[[:blank:]]*;[[:blank:]]*$/)
				flag("struct member must be a fixed-width scalar (__u8..__u64 / __s8..__s64, at most one array dimension)")
		}

		depth = depth + ob - cb
		if (in_struct && depth <= struct_depth) in_struct = 0
	}
	END { exit (bad > 0 ? 1 : 0) }
	' "$h"; then
        echo "  ok    $rel"
    else
        status=1
    fi
done

if [ "$status" -ne 0 ]; then
    echo "check-codegen-safe: FAIL"
    exit 1
fi
echo "check-codegen-safe: PASS"
