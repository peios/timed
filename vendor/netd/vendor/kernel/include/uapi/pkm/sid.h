/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_PKM_SID_H
#define _UAPI_PKM_SID_H

#include <linux/types.h>

/*
 * Security Identifier (SID) wire format.
 *
 * PKM uses the Windows binary SID layout verbatim (MS-DTYP 2.4.2). A SID
 * is variable-length, so it has no fixed C struct; it is laid out as:
 *
 *   __u8   revision                  (always 1)
 *   __u8   sub_authority_count        (0..KACS_SID_MAX_SUB_AUTHORITIES)
 *   __u8   identifier_authority[6]    (big-endian 48-bit value)
 *   __le32 sub_authority[sub_authority_count]
 *
 * The total encoded length is KACS_SID_BYTE_LEN(sub_authority_count) bytes.
 */

/* Largest sub_authority_count a valid SID may declare. */
#define KACS_SID_MAX_SUB_AUTHORITIES 15

/* Encoded byte length of a SID with the given sub-authority count. */
#define KACS_SID_BYTE_LEN(count) (8 + 4 * (count))

/*
 * SID_AND_ATTRIBUTES "Attributes" bits (MS-DTYP 2.4.4). These describe how
 * a group or restricted SID participates in an access check. MS-DTYP names
 * them for groups; they apply to any SID_AND_ATTRIBUTES entry.
 */
#define KACS_SID_GROUP_MANDATORY 0x00000001U
#define KACS_SID_GROUP_ENABLED_BY_DEFAULT 0x00000002U
#define KACS_SID_GROUP_ENABLED 0x00000004U
#define KACS_SID_GROUP_OWNER 0x00000008U
#define KACS_SID_GROUP_USE_FOR_DENY_ONLY 0x00000010U
#define KACS_SID_GROUP_INTEGRITY 0x00000020U
#define KACS_SID_GROUP_INTEGRITY_ENABLED 0x00000040U
#define KACS_SID_GROUP_RESOURCE 0x20000000U
#define KACS_SID_GROUP_LOGON_ID 0xC0000000U

#endif /* _UAPI_PKM_SID_H */
