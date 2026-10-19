/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_PKM_MNTNS_H
#define _UAPI_PKM_MNTNS_H

#include <linux/types.h>
#include <pkm/sd.h>

/*
 * KACS mount namespaces — who may change, and who may join, a mount table.
 *
 * A mount namespace is a private copy of the kernel's mount table: the map
 * from directory paths to the filesystems mounted there. Linux answers "who
 * may change this table" with CAP_SYS_ADMIN in the user namespace that owns
 * it, and lets an unprivileged process manufacture that capability by
 * creating a user namespace first. KACS answers from its own privileges and
 * discards the user namespace (see the capability switchboard), so a user
 * namespace grants nothing on Peios.
 *
 * Instead, every mount namespace other than the initial one is a KACS
 * object: it is minted with a security descriptor whose owner is the
 * creating token's user and whose DACL grants that user KACS_MNTNS_ALL_ACCESS.
 * Creating one — unshare(2) or clone(2) with CLONE_NEWNS — needs no privilege.
 *
 * Changing the table is then an access check for KACS_MNTNS_MOUNT against the
 * caller's current namespace, and the initial namespace, which has no
 * descriptor, is reachable only through SeManageVolumePrivilege or
 * SeTcbPrivilege as before. A holder of SeManageVolumePrivilege or
 * SeTcbPrivilege bypasses the descriptor in every namespace.
 *
 * KACS_MNTNS_MOUNT admits only operations that add no kernel parser to the
 * attack surface: a bind mount (MS_BIND, with or without MS_REC), umount2(2)
 * without MNT_FORCE, and pivot_root(2). Mounting a filesystem type, remounting,
 * moving a mount, changing propagation, and the new mount API (open_tree,
 * fsmount, move_mount, mount_setattr) still need the privilege whatever the
 * descriptor grants. A namespace created without the privilege receives its
 * mounts as slaves of the parent's, so nothing mounted inside it propagates
 * back.
 *
 * KACS_MNTNS_ENTER names the right to join the namespace with setns(2). The
 * right is defined so the descriptor's meaning is fixed; setns is not yet
 * widened and still needs the privilege.
 */

/* KACS access rights for mount namespaces. */
#define KACS_MNTNS_MOUNT 0x00000001U /* change the mount table */
#define KACS_MNTNS_ENTER 0x00000002U /* join the namespace with setns(2) */

#define KACS_MNTNS_ALL_ACCESS                                             \
	(KACS_MNTNS_MOUNT | KACS_MNTNS_ENTER | KACS_ACCESS_READ_CONTROL | \
	 KACS_ACCESS_WRITE_DAC | KACS_ACCESS_WRITE_OWNER)

#endif /* _UAPI_PKM_MNTNS_H */
