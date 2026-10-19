/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_PKM_FILE_H
#define _UAPI_PKM_FILE_H

#include <linux/types.h>

/*
 * KACS file ABI — kacs_open (SYS_KACS_OPEN) and the mount-policy syscalls
 * (SYS_KACS_GET_MOUNT_POLICY / SYS_KACS_SET_MOUNT_POLICY).
 *
 * kacs_open is the native, NtCreateFile-shaped open: kacs_open_how
 * describes the desired access, create disposition, create options, and an
 * optional security descriptor applied to a newly-created file.
 *
 * The file-specific right bits below occupy the low 16 bits of an access
 * mask; the standard and generic bits are in <pkm/sd.h>. libp builds the
 * file struct kacs_generic_mapping (see <pkm/sd.h>) from these bits.
 */

/* kacs_open "how" descriptor. __pad must be zero. */
struct kacs_open_how {
	__u32 desired_access;
	__u32 create_disposition;
	__u32 create_options;
	__u32 flags;
	__u64 sd_ptr;
	__u32 sd_len;
	__u32 __pad;
};

/* Argument block for the mount-policy syscalls. __pad fields must be zero. */
struct kacs_mount_policy_args {
	__u32 policy;
	__u32 flags;
	__u32 generation;
	__u32 __pad0;
	__u64 template_sd_ptr;
	__u32 template_sd_len;
	__u32 __pad1;
};

/* Minimum caller-supplied size accepted for each argument block. */
#define KACS_OPEN_HOW_MIN_SIZE 16U
#define KACS_MOUNT_POLICY_ARGS_MIN_SIZE 16U

/* Create dispositions (kacs_open_how.create_disposition). */
#define KACS_DISPOSITION_SUPERSEDE 0U
#define KACS_DISPOSITION_OPEN 1U
#define KACS_DISPOSITION_CREATE 2U
#define KACS_DISPOSITION_OPEN_IF 3U
#define KACS_DISPOSITION_OVERWRITE 4U
#define KACS_DISPOSITION_OVERWRITE_IF 5U

/* Create options (kacs_open_how.create_options). */
#define KACS_CREATE_OPT_DIRECTORY 0x0001U
#define KACS_CREATE_OPT_DELETE_ON_CLOSE 0x0002U

/* kacs_open_how.flags bits. */
#define KACS_BACKUP_INTENT 0x00000001U
#define KACS_RESTORE_INTENT 0x00000002U

/*
 * File and directory object-specific access rights (the low 16 bits of a
 * file access mask). The directory aliases name the same bit as the file
 * right it acts as for a directory object.
 */
#define KACS_FILE_READ_DATA 0x00000001U
#define KACS_FILE_WRITE_DATA 0x00000002U
#define KACS_FILE_APPEND_DATA 0x00000004U
#define KACS_FILE_READ_EA 0x00000008U
#define KACS_FILE_WRITE_EA 0x00000010U
#define KACS_FILE_EXECUTE 0x00000020U
#define KACS_FILE_DELETE_CHILD 0x00000040U
#define KACS_FILE_READ_ATTRIBUTES 0x00000080U
#define KACS_FILE_WRITE_ATTRIBUTES 0x00000100U

#define KACS_FILE_LIST_DIRECTORY KACS_FILE_READ_DATA
#define KACS_FILE_TRAVERSE KACS_FILE_EXECUTE
#define KACS_FILE_ADD_FILE KACS_FILE_WRITE_DATA
#define KACS_FILE_ADD_SUBDIRECTORY KACS_FILE_APPEND_DATA

/* Mount-policy values (kacs_mount_policy_args.policy). */
#define KACS_MOUNT_POLICY_UNMANAGED 1U
#define KACS_MOUNT_POLICY_DENY_MISSING 2U
#define KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL 3U
#define KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT 4U

/* Status word kacs_open writes back, describing what happened to the file. */
#define KACS_STATUS_OPENED 1U
#define KACS_STATUS_CREATED 2U
#define KACS_STATUS_OVERWRITTEN 3U
#define KACS_STATUS_SUPERSEDED 4U

#endif /* _UAPI_PKM_FILE_H */
