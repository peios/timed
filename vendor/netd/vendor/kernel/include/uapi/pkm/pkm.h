/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_PKM_H
#define _UAPI_PKM_H

/*
 * PKM userspace ABI — the published kernel interface to the Peios Kernel
 * Module.
 *
 * PKM is Peios's in-kernel security substrate. Its subsystems —
 *   KACS  tokens, security descriptors, access checks
 *         (<pkm/token.h>, <pkm/socket.h>, <pkm/sd.h>, <pkm/sid.h>,
 *          <pkm/access.h>, <pkm/file.h>, <pkm/process.h>, <pkm/psb.h>,
 *          <pkm/ipc.h>, <pkm/net.h>)
 *   KMES  the kernel-mediated event stream (<pkm/kmes.h>)
 *   LCS   the registry (<pkm/lcs.h>)
 * share one wire-format vocabulary (SIDs, security descriptors, access
 * masks) and are versioned and shipped together as a single kernel module.
 *
 * These headers are the single source of truth for the ABI: the kernel
 * compiles against them and so does userspace, so the two see
 * byte-identical definitions by construction. Each header is
 * userspace-clean — it compiles with an ordinary, non-kernel C compiler.
 *
 * Errno: PKM syscalls return a non-negative result on success and a
 * negated standard Linux errno on failure (e.g. -EACCES). There are no
 * PKM-specific errno values; use <errno.h>.
 *
 * Including this umbrella header pulls in the entire ABI.
 */

#include <pkm/syscall.h>
#include <pkm/sid.h>
#include <pkm/sd.h>
#include <pkm/token.h>
#include <pkm/socket.h>
#include <pkm/ipc.h>
#include <pkm/net.h>
#include <pkm/mntns.h>
#include <pkm/psb.h>
#include <pkm/access.h>
#include <pkm/file.h>
#include <pkm/process.h>
#include <pkm/kmes.h>
#include <pkm/lcs.h>
#include <pkm/trace.h>
#include <pkm/ntfe.h>

#endif /* _UAPI_PKM_H */
