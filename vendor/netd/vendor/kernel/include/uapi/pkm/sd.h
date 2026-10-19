/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_PKM_SD_H
#define _UAPI_PKM_SD_H

#include <linux/types.h>

/*
 * Security descriptors, ACLs, and ACEs.
 *
 * PKM uses the Windows self-relative SECURITY_DESCRIPTOR / ACL / ACE wire
 * formats verbatim (MS-DTYP 2.4.5, 2.4.5.1, 2.4.4). These structures are
 * variable-length and self-relative, so they cross the syscall boundary as
 * byte buffers rather than fixed C structs; this header defines the
 * constants needed to build and parse them.
 *
 * Self-relative SECURITY_DESCRIPTOR header (KACS_SD_HEADER_BYTES bytes):
 *   __u8   revision        (always 1)
 *   __u8   sbz1
 *   __le16 control         (KACS_SD_* control bits below)
 *   __le32 owner_offset    (0 = absent, else byte offset to the owner SID)
 *   __le32 group_offset
 *   __le32 sacl_offset
 *   __le32 dacl_offset
 *
 * ACL header (8 bytes): __u8 revision, __u8 sbz1, __le16 size,
 *   __le16 ace_count, __le16 sbz2.
 * ACE header (4 bytes): __u8 ace_type, __u8 ace_flags, __le16 size.
 */

/* Byte length of the self-relative security-descriptor header. */
#define KACS_SD_HEADER_BYTES 20

/*
 * SECURITY_INFORMATION selector bits — which components of a security
 * descriptor a kacs_get_sd / kacs_set_sd call reads or writes.
 */
#define KACS_SECINFO_OWNER 0x00000001U
#define KACS_SECINFO_GROUP 0x00000002U
#define KACS_SECINFO_DACL 0x00000004U
#define KACS_SECINFO_SACL 0x00000008U
#define KACS_SECINFO_LABEL 0x00000010U

/* SECURITY_DESCRIPTOR_CONTROL bits — the SD header `control` field. */
#define KACS_SD_OWNER_DEFAULTED 0x0001U
#define KACS_SD_GROUP_DEFAULTED 0x0002U
#define KACS_SD_DACL_PRESENT 0x0004U
#define KACS_SD_DACL_DEFAULTED 0x0008U
#define KACS_SD_SACL_PRESENT 0x0010U
#define KACS_SD_SACL_DEFAULTED 0x0020U
#define KACS_SD_DACL_TRUSTED 0x0040U
#define KACS_SD_SERVER_SECURITY 0x0080U
#define KACS_SD_DACL_AUTO_INHERIT_REQ 0x0100U
#define KACS_SD_SACL_AUTO_INHERIT_REQ 0x0200U
#define KACS_SD_DACL_AUTO_INHERITED 0x0400U
#define KACS_SD_SACL_AUTO_INHERITED 0x0800U
#define KACS_SD_DACL_PROTECTED 0x1000U
#define KACS_SD_SACL_PROTECTED 0x2000U
#define KACS_SD_RM_CONTROL_VALID 0x4000U
#define KACS_SD_SELF_RELATIVE 0x8000U

/*
 * Access-mask bits — standard rights (bits 16-24) and generic rights
 * (bits 28-31). The low 16 bits of a mask are object-class specific;
 * see <pkm/file.h> and <pkm/token.h> for those.
 */
#define KACS_ACCESS_DELETE 0x00010000U
#define KACS_ACCESS_READ_CONTROL 0x00020000U
#define KACS_ACCESS_WRITE_DAC 0x00040000U
#define KACS_ACCESS_WRITE_OWNER 0x00080000U
#define KACS_ACCESS_SYNCHRONIZE 0x00100000U
#define KACS_ACCESS_ACCESS_SYSTEM_SECURITY 0x01000000U
#define KACS_ACCESS_MAXIMUM_ALLOWED 0x02000000U
#define KACS_ACCESS_GENERIC_ALL 0x10000000U
#define KACS_ACCESS_GENERIC_EXECUTE 0x20000000U
#define KACS_ACCESS_GENERIC_WRITE 0x40000000U
#define KACS_ACCESS_GENERIC_READ 0x80000000U

/*
 * Generic-to-specific access mapping for an object class. An access check
 * folds the four KACS_ACCESS_GENERIC_* bits into object-specific rights
 * using one of these mappings (see <pkm/file.h> and <pkm/token.h> for the
 * per-class right bits each field is built from).
 */
struct kacs_generic_mapping {
	__u32 read;
	__u32 write;
	__u32 execute;
	__u32 all;
};

/* ACE types — the `ace_type` byte of an ACE header (MS-DTYP 2.4.4.1). */
#define KACS_ACE_TYPE_ACCESS_ALLOWED 0x00U
#define KACS_ACE_TYPE_ACCESS_DENIED 0x01U
#define KACS_ACE_TYPE_SYSTEM_AUDIT 0x02U
#define KACS_ACE_TYPE_SYSTEM_ALARM 0x03U
#define KACS_ACE_TYPE_ACCESS_ALLOWED_COMPOUND 0x04U
#define KACS_ACE_TYPE_ACCESS_ALLOWED_OBJECT 0x05U
#define KACS_ACE_TYPE_ACCESS_DENIED_OBJECT 0x06U
#define KACS_ACE_TYPE_SYSTEM_AUDIT_OBJECT 0x07U
#define KACS_ACE_TYPE_SYSTEM_ALARM_OBJECT 0x08U
#define KACS_ACE_TYPE_ACCESS_ALLOWED_CALLBACK 0x09U
#define KACS_ACE_TYPE_ACCESS_DENIED_CALLBACK 0x0AU
#define KACS_ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT 0x0BU
#define KACS_ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT 0x0CU
#define KACS_ACE_TYPE_SYSTEM_AUDIT_CALLBACK 0x0DU
#define KACS_ACE_TYPE_SYSTEM_ALARM_CALLBACK 0x0EU
#define KACS_ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT 0x0FU
#define KACS_ACE_TYPE_SYSTEM_ALARM_CALLBACK_OBJECT 0x10U
#define KACS_ACE_TYPE_SYSTEM_MANDATORY_LABEL 0x11U
#define KACS_ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE 0x12U
#define KACS_ACE_TYPE_SYSTEM_SCOPED_POLICY_ID 0x13U
#define KACS_ACE_TYPE_SYSTEM_PROCESS_TRUST_LABEL 0x14U
#define KACS_ACE_TYPE_SYSTEM_ACCESS_FILTER 0x15U

/* ACE header `ace_flags` byte — inheritance and audit control. */
#define KACS_ACE_FLAG_OBJECT_INHERIT 0x01U
#define KACS_ACE_FLAG_CONTAINER_INHERIT 0x02U
#define KACS_ACE_FLAG_NO_PROPAGATE_INHERIT 0x04U
#define KACS_ACE_FLAG_INHERIT_ONLY 0x08U
#define KACS_ACE_FLAG_INHERITED 0x10U
#define KACS_ACE_FLAG_SUCCESSFUL_ACCESS 0x40U
#define KACS_ACE_FLAG_FAILED_ACCESS 0x80U

/*
 * Mandatory-label policy bits — the __le32 access mask of a
 * KACS_ACE_TYPE_SYSTEM_MANDATORY_LABEL ACE. They control which DACL-granted
 * rights a caller whose integrity level does not dominate the object's label
 * (the "up" direction) is denied. Each bit suppresses the rights mapped from
 * the corresponding generic class; unknown bits MUST be ignored.
 */
#define KACS_SYSTEM_MANDATORY_LABEL_NO_READ_UP 0x00000001U
#define KACS_SYSTEM_MANDATORY_LABEL_NO_WRITE_UP 0x00000002U
#define KACS_SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP 0x00000004U

/*
 * Object-ACE body `Flags` field — the __le32 at object-ACE body offset 8,
 * distinct from the 1-byte `ace_flags` header field above. Indicates which
 * optional GUIDs the object-ACE body carries.
 */
#define KACS_ACE_OBJECT_TYPE_PRESENT 0x00000001U
#define KACS_ACE_INHERITED_OBJECT_TYPE_PRESENT 0x00000002U

#endif /* _UAPI_PKM_SD_H */
