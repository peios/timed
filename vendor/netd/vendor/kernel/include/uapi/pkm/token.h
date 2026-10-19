/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_PKM_TOKEN_H
#define _UAPI_PKM_TOKEN_H

#include <linux/ioctl.h>
#include <linux/types.h>

#include <pkm/sd.h>

/*
 * KACS token ABI — token-handle rights, the token-handle ioctl interface,
 * token information classes, and the privilege set.
 *
 * A token handle is an open file descriptor; per-handle rights are checked
 * against the token's security descriptor at open time, and the ioctls
 * below operate on the handle subject to those granted rights.
 */

/* kacs_open_self_token (SYS_KACS_OPEN_SELF_TOKEN) flags. */
#define KACS_TOKEN_OPEN_REAL 0x01U

/* Per-handle token rights (the low 16 bits of a token access mask). */
#define KACS_TOKEN_ASSIGN_PRIMARY 0x0001U
#define KACS_TOKEN_DUPLICATE 0x0002U
#define KACS_TOKEN_IMPERSONATE 0x0004U
#define KACS_TOKEN_QUERY 0x0008U
#define KACS_TOKEN_QUERY_SOURCE 0x0010U
#define KACS_TOKEN_ADJUST_PRIVS 0x0020U
#define KACS_TOKEN_ADJUST_GROUPS 0x0040U
#define KACS_TOKEN_ADJUST_DEFAULT 0x0080U
#define KACS_TOKEN_ADJUST_INTERACTIVITY_SCOPE 0x0100U
#define KACS_TOKEN_ALL_ACCESS 0x000F01FFU

/* Token ioctl interface identifier. */
#define KACS_IOC_MAGIC 0x4BU

/* kacs_priv_entry.attributes bits. */
#define KACS_PRIVILEGE_ATTR_ENABLED 0x00000002U
#define KACS_PRIVILEGE_ATTR_REMOVED 0x00000004U

/* kacs_adjust_privs bulk-reset flag (not a per-entry attribute). */
#define KACS_PRIVILEGE_RESET_ALL_DEFAULTS 0x80000000U

/* kacs_restrict_args.flags bits. */
#define KACS_TOKEN_RESTRICT_WRITE_RESTRICTED 0x00000001U

/* Token type (KACS_TOKEN_CLASS_TYPE). */
#define KACS_TOKEN_TYPE_PRIMARY 0x01U
#define KACS_TOKEN_TYPE_IMPERSONATION 0x02U

/* Impersonation level (KACS_TOKEN_CLASS_IMPERSONATION_LEVEL). */
#define KACS_IMLEVEL_ANONYMOUS 0x00U
#define KACS_IMLEVEL_IDENTIFICATION 0x01U
#define KACS_IMLEVEL_IMPERSONATION 0x02U
#define KACS_IMLEVEL_DELEGATION 0x03U

/* Elevation type (KACS_TOKEN_CLASS_ELEVATION_TYPE). */
#define KACS_ELEVATION_DEFAULT 0x01U
#define KACS_ELEVATION_FULL 0x02U
#define KACS_ELEVATION_LIMITED 0x03U

/* Mandatory-policy bits (KACS_TOKEN_CLASS_MANDATORY_POLICY). */
#define KACS_TOKEN_MANDATORY_POLICY_NO_WRITE_UP 0x00000001U
#define KACS_TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN 0x00000002U

/*
 * Per-token audit-policy bits — the create-token spec `audit_policy` field
 * (KACS_TOKEN_SPEC_OFF_AUDIT_POLICY). They select which access-check outcomes
 * the token's object accesses generate audit events for.
 */
#define KACS_AUDIT_POLICY_OBJECT_ACCESS_SUCCESS 0x00000001U
#define KACS_AUDIT_POLICY_OBJECT_ACCESS_FAILURE 0x00000002U
#define KACS_AUDIT_POLICY_PRIVILEGE_USE_SUCCESS 0x00000004U
#define KACS_AUDIT_POLICY_PRIVILEGE_USE_FAILURE 0x00000008U

/* Logon type (KACS_TOKEN_CLASS_LOGON_TYPE). */
#define KACS_LOGON_TYPE_INTERACTIVE 2
#define KACS_LOGON_TYPE_NETWORK 3
#define KACS_LOGON_TYPE_BATCH 4
#define KACS_LOGON_TYPE_SERVICE 5
#define KACS_LOGON_TYPE_NETWORK_CLEARTEXT 8
#define KACS_LOGON_TYPE_NEW_CREDENTIALS 9
#define KACS_LOGON_TYPE_REMOTE_INTERACTIVE 10

/* Maximum number of groups a token may carry. */
#define KACS_TOKEN_MAX_GROUPS 1024U

/* Number of 64-bit words in a group enabled-state bitmask (KACS_TOKEN_MAX_GROUPS / 64). */
#define KACS_TOKEN_GROUP_MASK_WORDS 16U

/*
 * kacs_create_token (SYS_KACS_CREATE_TOKEN) spec wire format.
 *
 * The (spec, len) buffer the syscall consumes is a fixed
 * KACS_TOKEN_SPEC_HEADER_BYTES-byte header followed by variable-length
 * sections at header-specified byte offsets. An offset/length (or
 * offset/count) pair that is both zero means the section is absent.
 * Sections may appear in any order; every offset+length is validated to
 * fall within the buffer. The header is not a C struct (it carries packed
 * mixed-width fields and crosses the syscall boundary as raw bytes); read
 * each field at its KACS_TOKEN_SPEC_OFF_* offset. Its fields, in order:
 *
 *   __u32  version                 must be KACS_TOKEN_SPEC_VERSION
 *   __u8   token_type              KACS_TOKEN_TYPE_*
 *   __u8   impersonation_level     KACS_IMLEVEL_*
 *   __u8   _reserved0[2]           must be 0
 *   __u32  integrity_rid           integrity-level RID
 *   __u32  mandatory_policy        KACS_TOKEN_MANDATORY_POLICY_* bits
 *   __u64  privs_present           privilege bitmask (KACS_SE_*_PRIVILEGE)
 *   __u64  privs_enabled           initially enabled privileges (subset)
 *   __u32  _reserved1              must be 0 (elevation set only by LINK_TOKENS)
 *   __u32  projected_uid           Linux UID for credential projection
 *   __u32  projected_gid           Linux GID for credential projection
 *   __u32  audit_policy            per-token audit flags
 *   __u64  expiration              expiry timestamp (0 = none)
 *   __u64  logon_session_id              logon session ID (auth_id)
 *   __u32  owner_sid_index         0 = user SID, 1..N = caller group
 *   __u32  primary_group_index     0 = user SID, 1..N = caller group
 *   __u8   source_name[8]          token source name
 *   __u64  source_id               token source LUID
 *   __u32  user_sid_offset         byte offset to the user SID
 *   __u32  groups_offset           byte offset to the groups array
 *   __u32  groups_count            number of group entries
 *   __u32  default_dacl_offset     byte offset to the default DACL (0 = none)
 *   __u32  default_dacl_len        default DACL byte length (0 = none)
 *   __u32  user_claims_offset      byte offset to user claims (0 = none)
 *   __u32  user_claims_len         user claims byte length (0 = none)
 *   __u32  device_claims_offset    byte offset to device claims (0 = none)
 *   __u32  device_claims_len       device claims byte length (0 = none)
 *   __u32  device_groups_offset    byte offset to device groups (0 = none)
 *   __u32  device_groups_count     number of device-group entries (0 = none)
 *   __u32  restricted_sids_offset  byte offset to restricted SIDs (0 = none)
 *   __u32  restricted_sids_count   number of restricted-SID entries (0 = none)
 *   __u32  confinement_sid_offset  byte offset to confinement SID (0 = none)
 *   __u32  confinement_sid_len     confinement SID byte length (0 = none)
 *   __u32  confinement_caps_offset byte offset to confinement caps (0 = none)
 *   __u32  confinement_caps_count  number of confinement-cap entries (0 = none)
 *   __u8   confinement_exempt      1 = exempt from confinement
 *   __u8   write_restricted        1 = write-restricted mode
 *   __u8   user_deny_only          1 = user SID matches deny ACEs only
 *   __u8   isolation_boundary      1 = enable namespace filtering
 *   __u32  supp_gids_offset        byte offset to supplementary GIDs (0 = none)
 *   __u32  supp_gids_count         number of supplementary-GID entries (0 = none)
 *   __u32  restricted_device_groups_offset  byte offset (0 = none)
 *   __u32  restricted_device_groups_count   entry count (0 = none)
 *   __u64  origin                  originating logon-session LUID (0 = none)
 *   __u32  interactivity_scope  interactive session number
 *   __u32  lcs_credentials_offset  byte offset to the LCS extension (0 = none)
 *
 * A group/device-group/restricted-SID/confinement-cap/restricted-device-group
 * entry is [__u32 sid_len][__u8 sid[sid_len]][__u32 attributes]. A
 * supplementary-GIDs section is supp_gids_count little-endian __u32 GIDs. All
 * multi-byte header and section scalars are little-endian.
 */
#define KACS_TOKEN_SPEC_VERSION 2U
#define KACS_TOKEN_SPEC_HEADER_BYTES 192U
#define KACS_TOKEN_SPEC_MIN_BYTES 192U
#define KACS_TOKEN_SPEC_MAX_BYTES 65536U

/* Byte offsets of the fixed token-spec header fields. */
#define KACS_TOKEN_SPEC_OFF_VERSION 0U
#define KACS_TOKEN_SPEC_OFF_TOKEN_TYPE 4U
#define KACS_TOKEN_SPEC_OFF_IMPERSONATION_LEVEL 5U
#define KACS_TOKEN_SPEC_OFF_RESERVED0 6U
#define KACS_TOKEN_SPEC_OFF_INTEGRITY_RID 8U
#define KACS_TOKEN_SPEC_OFF_MANDATORY_POLICY 12U
#define KACS_TOKEN_SPEC_OFF_PRIVS_PRESENT 16U
#define KACS_TOKEN_SPEC_OFF_PRIVS_ENABLED 24U
#define KACS_TOKEN_SPEC_OFF_RESERVED1 32U
#define KACS_TOKEN_SPEC_OFF_PROJECTED_UID 36U
#define KACS_TOKEN_SPEC_OFF_PROJECTED_GID 40U
#define KACS_TOKEN_SPEC_OFF_AUDIT_POLICY 44U
#define KACS_TOKEN_SPEC_OFF_EXPIRATION 48U
#define KACS_TOKEN_SPEC_OFF_LOGON_SESSION_ID 56U
#define KACS_TOKEN_SPEC_OFF_OWNER_SID_INDEX 64U
#define KACS_TOKEN_SPEC_OFF_PRIMARY_GROUP_INDEX 68U
#define KACS_TOKEN_SPEC_OFF_SOURCE_NAME 72U
#define KACS_TOKEN_SPEC_OFF_SOURCE_ID 80U
#define KACS_TOKEN_SPEC_OFF_USER_SID_OFFSET 88U
#define KACS_TOKEN_SPEC_OFF_GROUPS_OFFSET 92U
#define KACS_TOKEN_SPEC_OFF_GROUPS_COUNT 96U
#define KACS_TOKEN_SPEC_OFF_DEFAULT_DACL_OFFSET 100U
#define KACS_TOKEN_SPEC_OFF_DEFAULT_DACL_LEN 104U
#define KACS_TOKEN_SPEC_OFF_USER_CLAIMS_OFFSET 108U
#define KACS_TOKEN_SPEC_OFF_USER_CLAIMS_LEN 112U
#define KACS_TOKEN_SPEC_OFF_DEVICE_CLAIMS_OFFSET 116U
#define KACS_TOKEN_SPEC_OFF_DEVICE_CLAIMS_LEN 120U
#define KACS_TOKEN_SPEC_OFF_DEVICE_GROUPS_OFFSET 124U
#define KACS_TOKEN_SPEC_OFF_DEVICE_GROUPS_COUNT 128U
#define KACS_TOKEN_SPEC_OFF_RESTRICTED_SIDS_OFFSET 132U
#define KACS_TOKEN_SPEC_OFF_RESTRICTED_SIDS_COUNT 136U
#define KACS_TOKEN_SPEC_OFF_CONFINEMENT_SID_OFFSET 140U
#define KACS_TOKEN_SPEC_OFF_CONFINEMENT_SID_LEN 144U
#define KACS_TOKEN_SPEC_OFF_CONFINEMENT_CAPS_OFFSET 148U
#define KACS_TOKEN_SPEC_OFF_CONFINEMENT_CAPS_COUNT 152U
#define KACS_TOKEN_SPEC_OFF_CONFINEMENT_EXEMPT 156U
#define KACS_TOKEN_SPEC_OFF_WRITE_RESTRICTED 157U
#define KACS_TOKEN_SPEC_OFF_USER_DENY_ONLY 158U
#define KACS_TOKEN_SPEC_OFF_ISOLATION_BOUNDARY 159U
#define KACS_TOKEN_SPEC_OFF_SUPP_GIDS_OFFSET 160U
#define KACS_TOKEN_SPEC_OFF_SUPP_GIDS_COUNT 164U
#define KACS_TOKEN_SPEC_OFF_RESTRICTED_DEVICE_GROUPS_OFFSET 168U
#define KACS_TOKEN_SPEC_OFF_RESTRICTED_DEVICE_GROUPS_COUNT 172U
#define KACS_TOKEN_SPEC_OFF_ORIGIN 176U
#define KACS_TOKEN_SPEC_OFF_INTERACTIVITY_SCOPE 184U
#define KACS_TOKEN_SPEC_OFF_LCS_CREDENTIALS_OFFSET 188U

/* Byte length of the fixed token-source-name field. */
#define KACS_TOKEN_SPEC_SOURCE_NAME_BYTES 8U

/*
 * Optional LCS registry-credentials extension, located at the token-spec
 * header's lcs_credentials_offset. The section is a fixed
 * KACS_TOKEN_LCS_EXT_HEADER_BYTES-byte header bounded by the next active
 * variable-section offset or the end of the spec; it is consumed exactly
 * (trailing bytes are malformed). Header fields, in order:
 *
 *   __u32  version              must be KACS_TOKEN_LCS_EXT_VERSION
 *   __u32  _reserved            must be 0
 *   __u32  scope_count          private hive scope GUIDs (<= max)
 *   __u32  private_layer_count  private layer names (<= max)
 *
 * Payload: scope_count raw 16-byte GUIDs, then private_layer_count
 * little-endian __u32 name byte lengths, then the concatenated UTF-8 layer
 * names. Scope GUIDs must be non-nil and unique; layer names must be 1..
 * KACS_TOKEN_LCS_MAX_LAYER_NAME_BYTES bytes, must not contain '\\', '/', or
 * NUL, and must be unique under case-insensitive matching.
 */
#define KACS_TOKEN_LCS_EXT_VERSION 1U
#define KACS_TOKEN_LCS_EXT_HEADER_BYTES 16U
#define KACS_TOKEN_LCS_SCOPE_GUID_BYTES 16U
#define KACS_TOKEN_LCS_MAX_SCOPE_GUIDS 256U
#define KACS_TOKEN_LCS_MAX_PRIVATE_LAYERS 256U
#define KACS_TOKEN_LCS_MAX_LAYER_NAME_BYTES 255U

/* Byte offsets of the fixed LCS-extension header fields. */
#define KACS_TOKEN_LCS_EXT_OFF_VERSION 0U
#define KACS_TOKEN_LCS_EXT_OFF_RESERVED 4U
#define KACS_TOKEN_LCS_EXT_OFF_SCOPE_COUNT 8U
#define KACS_TOKEN_LCS_EXT_OFF_PRIVATE_LAYER_COUNT 12U

/*
 * kacs_create_logon_session (SYS_KACS_CREATE_LOGON_SESSION) spec wire format.
 *
 * The (spec, len) buffer the syscall consumes is, in order:
 *
 *   __u8   logon_type          one of KACS_LOGON_TYPE_* above
 *   __le16 auth_pkg_len        byte length of the auth-package name
 *   __u8   auth_pkg[auth_pkg_len]   auth-package name (valid UTF-8)
 *   __le32 user_sid_len        byte length of the user SID
 *   __u8   user_sid[user_sid_len]   binary SID of the authenticated user
 *
 * The buffer is consumed exactly: 7 + auth_pkg_len + user_sid_len must equal
 * len. The kernel assigns the session ID and derives the logon SID from it.
 */
#define KACS_LOGON_SESSION_SPEC_MIN_BYTES 15U
#define KACS_LOGON_SESSION_SPEC_MAX_BYTES 4096U

/* Byte offsets of the fixed-position session-spec fields. */
#define KACS_LOGON_SESSION_SPEC_OFF_LOGON_TYPE 0U
#define KACS_LOGON_SESSION_SPEC_OFF_AUTH_PKG_LEN 1U
#define KACS_LOGON_SESSION_SPEC_OFF_AUTH_PKG 3U

/* ioctl argument structures. */

struct kacs_query_args {
	__u32 token_class;
	__u32 buf_len;
	__u64 buf_ptr;
};

struct kacs_adjust_privs_args {
	__u32 count;
	__u32 _pad;
	__u64 data_ptr;
	__u64 previous_enabled;
};

struct kacs_priv_entry {
	__u32 luid;
	__u32 attributes;
};

struct kacs_adjust_groups_args {
	__u32 count;
	__u32 _pad;
	__u64 data_ptr;
	__u64 previous_state[16]; /* KACS_TOKEN_GROUP_MASK_WORDS */
};

struct kacs_duplicate_args {
	__u32 access_mask;
	__u32 token_type;
	__u32 impersonation_level;
	__s32 result_fd;
};

struct kacs_group_entry {
	__u32 index;
	__u32 enable;
};

struct kacs_adjust_default_args {
	__u64 dacl_ptr;
	__u32 dacl_len;
	__u16 owner_index;
	__u16 group_index;
};

struct kacs_restrict_args {
	__u64 privs_to_delete;
	__u32 num_deny_indices;
	__u32 num_restrict_sids;
	__u32 data_len;
	__u32 flags;
	__u64 data_ptr;
	__s32 result_fd;
	__u32 _pad;
};

struct kacs_link_tokens_args {
	__s32 elevated_fd;
	__s32 filtered_fd;
	__u64 logon_session_id;
};

struct kacs_get_linked_token_args {
	__s32 result_fd;
};

/* Token-handle ioctls. */
#define KACS_IOC_QUERY _IOWR(KACS_IOC_MAGIC, 0, struct kacs_query_args)
#define KACS_IOC_ADJUST_PRIVS \
	_IOW(KACS_IOC_MAGIC, 1, struct kacs_adjust_privs_args)
#define KACS_IOC_DUPLICATE _IOWR(KACS_IOC_MAGIC, 2, struct kacs_duplicate_args)
#define KACS_IOC_INSTALL _IO(KACS_IOC_MAGIC, 3)
#define KACS_IOC_RESTRICT _IOWR(KACS_IOC_MAGIC, 4, struct kacs_restrict_args)
#define KACS_IOC_LINK_TOKENS \
	_IOW(KACS_IOC_MAGIC, 5, struct kacs_link_tokens_args)
#define KACS_IOC_GET_LINKED_TOKEN \
	_IOWR(KACS_IOC_MAGIC, 6, struct kacs_get_linked_token_args)
#define KACS_IOC_ADJUST_GROUPS \
	_IOW(KACS_IOC_MAGIC, 7, struct kacs_adjust_groups_args)
#define KACS_IOC_IMPERSONATE _IO(KACS_IOC_MAGIC, 8)
#define KACS_IOC_ADJUST_DEFAULT \
	_IOW(KACS_IOC_MAGIC, 9, struct kacs_adjust_default_args)
#define KACS_IOC_ADJUST_INTERACTIVITY_SCOPE _IOW(KACS_IOC_MAGIC, 10, __u32)

/* Token information classes (kacs_query_args.token_class).
 * GUID returns 16 immutable raw bytes in the same order as KMES headers.
 */
#define KACS_TOKEN_CLASS_USER 0x01U
#define KACS_TOKEN_CLASS_GROUPS 0x02U
#define KACS_TOKEN_CLASS_PRIVILEGES 0x03U
#define KACS_TOKEN_CLASS_TYPE 0x04U
#define KACS_TOKEN_CLASS_INTEGRITY_LEVEL 0x05U
#define KACS_TOKEN_CLASS_OWNER 0x06U
#define KACS_TOKEN_CLASS_PRIMARY_GROUP 0x07U
#define KACS_TOKEN_CLASS_INTERACTIVITY_SCOPE 0x08U
#define KACS_TOKEN_CLASS_RESTRICTED_SIDS 0x09U
#define KACS_TOKEN_CLASS_SOURCE 0x0AU
#define KACS_TOKEN_CLASS_STATISTICS 0x0BU
#define KACS_TOKEN_CLASS_ORIGIN 0x0CU
#define KACS_TOKEN_CLASS_ELEVATION_TYPE 0x0DU
#define KACS_TOKEN_CLASS_DEVICE_GROUPS 0x0EU
#define KACS_TOKEN_CLASS_APPCONTAINER_SID 0x0FU
#define KACS_TOKEN_CLASS_CAPABILITIES 0x10U
#define KACS_TOKEN_CLASS_MANDATORY_POLICY 0x11U
#define KACS_TOKEN_CLASS_LOGON_TYPE 0x12U
#define KACS_TOKEN_CLASS_LOGON_SID 0x13U
#define KACS_TOKEN_CLASS_DEFAULT_DACL 0x14U
#define KACS_TOKEN_CLASS_IMPERSONATION_LEVEL 0x15U
#define KACS_TOKEN_CLASS_USER_CLAIMS 0x16U
#define KACS_TOKEN_CLASS_DEVICE_CLAIMS 0x17U
#define KACS_TOKEN_CLASS_PROJECTED_SUPPLEMENTARY_GIDS 0x18U
#define KACS_TOKEN_CLASS_GUID 0x19U

/*
 * Privileges, as single-bit masks within a token's 64-bit privilege word
 * (present / enabled / enabled-by-default / used are each one such word).
 * Named for the Windows privilege identifiers (SeTcbPrivilege, …).
 */
#define KACS_SE_CREATE_TOKEN_PRIVILEGE (1ULL << 2)
#define KACS_SE_ASSIGN_PRIMARY_TOKEN_PRIVILEGE (1ULL << 3)
#define KACS_SE_LOCK_MEMORY_PRIVILEGE (1ULL << 4)
#define KACS_SE_INCREASE_QUOTA_PRIVILEGE (1ULL << 5)
#define KACS_SE_TCB_PRIVILEGE (1ULL << 7)
#define KACS_SE_SECURITY_PRIVILEGE (1ULL << 8)
#define KACS_SE_TAKE_OWNERSHIP_PRIVILEGE (1ULL << 9)
#define KACS_SE_LOAD_DRIVER_PRIVILEGE (1ULL << 10)
#define KACS_SE_SYSTEM_PROFILE_PRIVILEGE (1ULL << 11)
#define KACS_SE_SYSTEMTIME_PRIVILEGE (1ULL << 12)
#define KACS_SE_PROFILE_SINGLE_PROCESS_PRIVILEGE (1ULL << 13)
#define KACS_SE_INCREASE_BASE_PRIORITY_PRIVILEGE (1ULL << 14)
#define KACS_SE_BACKUP_PRIVILEGE (1ULL << 17)
#define KACS_SE_RESTORE_PRIVILEGE (1ULL << 18)
#define KACS_SE_SHUTDOWN_PRIVILEGE (1ULL << 19)
#define KACS_SE_DEBUG_PRIVILEGE (1ULL << 20)
#define KACS_SE_AUDIT_PRIVILEGE (1ULL << 21)
#define KACS_SE_CHANGE_NOTIFY_PRIVILEGE (1ULL << 23)
#define KACS_SE_REMOTE_SHUTDOWN_PRIVILEGE (1ULL << 24)
#define KACS_SE_MANAGE_VOLUME_PRIVILEGE (1ULL << 28)
#define KACS_SE_IMPERSONATE_PRIVILEGE (1ULL << 29)
#define KACS_SE_RELABEL_PRIVILEGE (1ULL << 32)
#define KACS_SE_CREATE_SYMBOLIC_LINK_PRIVILEGE (1ULL << 35)

#endif /* _UAPI_PKM_TOKEN_H */
