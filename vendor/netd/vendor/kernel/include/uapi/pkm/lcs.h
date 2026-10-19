/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_PKM_LCS_H
#define _UAPI_PKM_LCS_H

#include <linux/ioctl.h>
#include <linux/types.h>

/*
 * LCS registry UAPI constants.
 *
 * The structures below use natural C layout with fixed-width fields and
 * explicit padding. Pointer fields are numeric userspace addresses.
 */

/* Registry ioctl type byte. */
#define REG_IOC_TYPE 'R'

/* Source registration ioctl number namespace. */
#define REG_SRC_REGISTER_NR 0U
#define REG_SRC_NEGOTIATE_NR 1U
#define REG_SRC_REQUEST_CONTEXT_NR 2U
#define REG_SRC_RENEW_NR 3U

/* Key-fd and transaction-fd ioctl number namespace. */
#define REG_IOC_QUERY_VALUE_NR 0U
#define REG_IOC_SET_VALUE_NR 1U
#define REG_IOC_DELETE_VALUE_NR 2U
#define REG_IOC_BLANKET_TOMBSTONE_NR 3U
#define REG_IOC_QUERY_VALUES_BATCH_NR 4U
#define REG_IOC_ENUM_VALUES_NR 5U
#define REG_IOC_ENUM_SUBKEYS_NR 6U
#define REG_IOC_QUERY_KEY_INFO_NR 7U
#define REG_IOC_DELETE_KEY_NR 8U
#define REG_IOC_HIDE_KEY_NR 9U
#define REG_IOC_GET_SECURITY_NR 10U
#define REG_IOC_SET_SECURITY_NR 11U
#define REG_IOC_NOTIFY_NR 12U
#define REG_IOC_FLUSH_NR 13U
#define REG_IOC_BACKUP_NR 14U
#define REG_IOC_RESTORE_NR 15U
#define REG_IOC_COMMIT_NR 16U
#define REG_IOC_TXN_STATUS_NR 17U

struct reg_create_key_args {
	__s32 parent_fd;
	__u32 _pad0;
	__u64 path_ptr;
	__u32 desired_access;
	__u32 flags;
	__u64 layer_ptr;
	__s32 txn_fd;
	__u32 _pad1;
	__u64 disposition_ptr;
};

struct reg_query_value_args {
	__u32 name_len;
	__u32 _pad0;
	__u64 name_ptr;
	__u32 type;
	__u32 data_len;
	__s32 txn_fd;
	__u32 layer_buf_len;
	__u64 data_ptr;
	__u64 sequence;
	__u32 layer_len;
	__u32 _pad1;
	__u64 layer_ptr;
};

struct reg_set_value_args {
	__u32 name_len;
	__u32 _pad0;
	__u64 name_ptr;
	__u32 type;
	__u32 data_len;
	__u64 data_ptr;
	__u32 layer_len;
	__u32 _pad1;
	__u64 layer_ptr;
	__s32 txn_fd;
	__u32 _pad2;
	__u64 expected_seq;
};

struct reg_delete_value_args {
	__u32 name_len;
	__u32 _pad0;
	__u64 name_ptr;
	__u32 layer_len;
	__u32 _pad1;
	__u64 layer_ptr;
	__s32 txn_fd;
	__u32 _pad2;
};

struct reg_blanket_tombstone_args {
	__u32 layer_len;
	__u32 _pad0;
	__u64 layer_ptr;
	__u8 set;
	__u8 _pad1[3];
	__s32 txn_fd;
};

struct reg_query_values_batch_args {
	__u32 buf_len;
	__u32 count;
	__u64 buf_ptr;
	__s32 txn_fd;
	__u32 _pad;
};

struct reg_enum_value_args {
	__u32 index;
	__u32 name_len;
	__u64 name_ptr;
	__u32 type;
	__u32 data_len;
	__u64 data_ptr;
	__s32 txn_fd;
	__u32 _pad;
};

struct reg_enum_subkey_args {
	__u32 index;
	__u32 name_len;
	__u64 name_ptr;
	__u64 last_write_time;
	__u32 subkey_count;
	__u32 value_count;
	__s32 txn_fd;
	__u32 _pad;
};

struct reg_query_key_info_args {
	__u32 name_len;
	__u32 _pad0;
	__u64 name_ptr;
	__u64 last_write_time;
	__u32 subkey_count;
	__u32 value_count;
	__u32 max_subkey_name_len;
	__u32 max_value_name_len;
	__u32 max_value_data_size;
	__u32 sd_size;
	__u8 volatile_key;
	__u8 symlink;
	__u8 _pad1[6];
	__u64 hive_generation;
};

struct reg_delete_key_args {
	__u32 layer_len;
	__u32 _pad0;
	__u64 layer_ptr;
	__s32 txn_fd;
	__u32 _pad1;
};

struct reg_hide_key_args {
	__u32 layer_len;
	__u32 _pad0;
	__u64 layer_ptr;
	__s32 txn_fd;
	__u32 _pad1;
};

struct reg_get_security_args {
	__u32 security_info;
	__u32 sd_len;
	__u64 sd_ptr;
};

struct reg_set_security_args {
	__u32 security_info;
	__u32 sd_len;
	__u64 sd_ptr;
	__s32 txn_fd;
	__u32 _pad;
};

struct reg_notify_args {
	__u32 filter;
	__u8 subtree;
	__u8 _pad[3];
};

struct reg_backup_args {
	__s32 output_fd;
};

struct reg_restore_args {
	__s32 input_fd;
};

struct reg_txn_status_args {
	__u32 state;
	__s32 terminal_errno;
};

struct reg_src_register_args {
	__u32 hive_count;
	__u32 _pad;
	__u64 max_sequence;
	__u64 hives_ptr;
};

/* Optional RSI lifetime extension, negotiated before REG_SRC_REGISTER.
 * All timestamps use CLOCK_MONOTONIC nanoseconds. Zero lifetime means an
 * operation-owned transaction with no independent lifetime limit.
 * The session is unique to this open source fd, including across restarts.
 */
#define REG_SRC_LIFETIME_VERSION 1U
struct reg_src_negotiate_args {
	__u32 version;
	__u32 flags; /* must be zero */
	__u64 session; /* output */
};
struct reg_src_request_context_args {
	__u64 session;
	__u64 request_id;
	__u64 request_deadline_ns; /* output, includes queue/admission time */
	__u64 lifetime_deadline_ns; /* output */
	__u64 lease_deadline_ns; /* output; zero means no live transaction */
};
struct reg_src_renew_args {
	__u64 session;
	__u64 transaction_id;
	__u64 lifetime_deadline_ns; /* output */
	__u64 lease_deadline_ns; /* output */
};
#define REG_SRC_NEGOTIATE \
	_IOWR(REG_IOC_TYPE, REG_SRC_NEGOTIATE_NR, struct reg_src_negotiate_args)
#define REG_SRC_REQUEST_CONTEXT                         \
	_IOWR(REG_IOC_TYPE, REG_SRC_REQUEST_CONTEXT_NR, \
	      struct reg_src_request_context_args)
#define REG_SRC_RENEW \
	_IOWR(REG_IOC_TYPE, REG_SRC_RENEW_NR, struct reg_src_renew_args)

struct reg_src_hive_entry {
	__u32 name_len;
	__u32 _pad0;
	__u64 name_ptr;
	__u8 root_guid[16];
	__u32 flags;
	__u32 _pad1;
	__u8 scope_guid[16];
};

/* Syscall and ioctl argument sizes (Kernel TRM section 5.A, LCS ABI). */
#define REG_CREATE_KEY_ARGS_SIZE 48U
#define REG_QUERY_VALUE_ARGS_SIZE 64U
#define REG_SET_VALUE_ARGS_SIZE 64U
#define REG_DELETE_VALUE_ARGS_SIZE 40U
#define REG_BLANKET_TOMBSTONE_ARGS_SIZE 24U
#define REG_QUERY_VALUES_BATCH_ARGS_SIZE 24U
#define REG_ENUM_VALUE_ARGS_SIZE 40U
#define REG_ENUM_SUBKEY_ARGS_SIZE 40U
#define REG_QUERY_KEY_INFO_ARGS_SIZE 64U
#define REG_DELETE_KEY_ARGS_SIZE 24U
#define REG_HIDE_KEY_ARGS_SIZE 24U
#define REG_GET_SECURITY_ARGS_SIZE 16U
#define REG_SET_SECURITY_ARGS_SIZE 24U
#define REG_NOTIFY_ARGS_SIZE 8U
#define REG_BACKUP_ARGS_SIZE 4U
#define REG_RESTORE_ARGS_SIZE 4U
#define REG_TXN_STATUS_ARGS_SIZE 8U
#define REG_SRC_NEGOTIATE_ARGS_SIZE 16U
#define REG_SRC_REQUEST_CONTEXT_ARGS_SIZE 40U
#define REG_SRC_RENEW_ARGS_SIZE 32U
#define REG_SRC_REGISTER_ARGS_SIZE 24U
#define REG_SRC_HIVE_ENTRY_SIZE 56U

/* Source registration ioctl. */
#define REG_SRC_REGISTER \
	_IOW(REG_IOC_TYPE, REG_SRC_REGISTER_NR, struct reg_src_register_args)

/* Key-fd ioctls. */
#define REG_IOC_QUERY_VALUE \
	_IOWR(REG_IOC_TYPE, REG_IOC_QUERY_VALUE_NR, struct reg_query_value_args)
#define REG_IOC_SET_VALUE \
	_IOW(REG_IOC_TYPE, REG_IOC_SET_VALUE_NR, struct reg_set_value_args)
#define REG_IOC_DELETE_VALUE                        \
	_IOW(REG_IOC_TYPE, REG_IOC_DELETE_VALUE_NR, \
	     struct reg_delete_value_args)
#define REG_IOC_BLANKET_TOMBSTONE                        \
	_IOW(REG_IOC_TYPE, REG_IOC_BLANKET_TOMBSTONE_NR, \
	     struct reg_blanket_tombstone_args)
#define REG_IOC_QUERY_VALUES_BATCH                         \
	_IOWR(REG_IOC_TYPE, REG_IOC_QUERY_VALUES_BATCH_NR, \
	      struct reg_query_values_batch_args)
#define REG_IOC_ENUM_VALUES \
	_IOWR(REG_IOC_TYPE, REG_IOC_ENUM_VALUES_NR, struct reg_enum_value_args)
#define REG_IOC_ENUM_SUBKEYS                         \
	_IOWR(REG_IOC_TYPE, REG_IOC_ENUM_SUBKEYS_NR, \
	      struct reg_enum_subkey_args)
/*
 * _IOWR, not _IOR: the kernel reads the caller's name_len and name_ptr out of
 * the argument struct before it writes the result back, so the argument
 * crosses in both directions. It was declared _IOR, which put the wrong
 * direction bits in the encoded number -- and since the kernel dispatches on
 * the whole encoded value, correcting it is a wire break, not a relabelling.
 */
#define REG_IOC_QUERY_KEY_INFO                         \
	_IOWR(REG_IOC_TYPE, REG_IOC_QUERY_KEY_INFO_NR, \
	      struct reg_query_key_info_args)
#define REG_IOC_DELETE_KEY \
	_IOW(REG_IOC_TYPE, REG_IOC_DELETE_KEY_NR, struct reg_delete_key_args)
#define REG_IOC_HIDE_KEY \
	_IOW(REG_IOC_TYPE, REG_IOC_HIDE_KEY_NR, struct reg_hide_key_args)
#define REG_IOC_GET_SECURITY                         \
	_IOWR(REG_IOC_TYPE, REG_IOC_GET_SECURITY_NR, \
	      struct reg_get_security_args)
#define REG_IOC_SET_SECURITY                        \
	_IOW(REG_IOC_TYPE, REG_IOC_SET_SECURITY_NR, \
	     struct reg_set_security_args)
#define REG_IOC_NOTIFY \
	_IOW(REG_IOC_TYPE, REG_IOC_NOTIFY_NR, struct reg_notify_args)
#define REG_IOC_FLUSH _IO(REG_IOC_TYPE, REG_IOC_FLUSH_NR)
#define REG_IOC_BACKUP \
	_IOW(REG_IOC_TYPE, REG_IOC_BACKUP_NR, struct reg_backup_args)
#define REG_IOC_RESTORE \
	_IOW(REG_IOC_TYPE, REG_IOC_RESTORE_NR, struct reg_restore_args)

/* Transaction-fd ioctls. */
#define REG_IOC_COMMIT _IO(REG_IOC_TYPE, REG_IOC_COMMIT_NR)
#define REG_IOC_TXN_STATUS \
	_IOR(REG_IOC_TYPE, REG_IOC_TXN_STATUS_NR, struct reg_txn_status_args)

/* Transaction state codes. */
#define REG_TXN_ACTIVE_UNBOUND 0U
#define REG_TXN_ACTIVE_BOUND 1U
#define REG_TXN_COMMITTED 2U
#define REG_TXN_ABORTED 3U
#define REG_TXN_TIMED_OUT 4U
#define REG_TXN_SOURCE_DOWN 5U

/* Syscall flags and dispositions. */
#define REG_OPEN_LINK 0x01U
#define REG_OPTION_VOLATILE 0x01U
#define REG_OPTION_CREATE_LINK 0x02U
#define REG_CREATED_NEW 1U
#define REG_OPENED_EXISTING 2U

/* Registry key access rights. */
#define KEY_QUERY_VALUE 0x00000001U
#define KEY_SET_VALUE 0x00000002U
#define KEY_CREATE_SUB_KEY 0x00000004U
#define KEY_ENUMERATE_SUB_KEYS 0x00000008U
#define KEY_NOTIFY 0x00000010U
#define KEY_CREATE_LINK 0x00000020U

#define DELETE 0x00010000U
#define READ_CONTROL 0x00020000U
#define WRITE_DAC 0x00040000U
#define WRITE_OWNER 0x00080000U
#define ACCESS_SYSTEM_SECURITY 0x01000000U
#define MAXIMUM_ALLOWED 0x02000000U

#define GENERIC_ALL 0x10000000U
#define GENERIC_EXECUTE 0x20000000U
#define GENERIC_WRITE 0x40000000U
#define GENERIC_READ 0x80000000U

#define KEY_READ 0x00020019U
#define KEY_WRITE 0x00020006U
#define KEY_ALL_ACCESS 0x000F003FU

#define REG_VALID_DESIRED_ACCESS_MASK 0xF30F003FU
#define REG_VALID_MAPPED_ACCESS_MASK 0x010F003FU
#define REG_VALID_ACE_ACCESS_MASK 0xF10F003FU

/* Security information flags for REG_IOC_GET_SECURITY / SET_SECURITY. */
#define OWNER_SECURITY_INFORMATION 0x00000001U
#define GROUP_SECURITY_INFORMATION 0x00000002U
#define DACL_SECURITY_INFORMATION 0x00000004U
#define SACL_SECURITY_INFORMATION 0x00000008U
#define LABEL_SECURITY_INFORMATION 0x00000010U
#define REG_VALID_SECURITY_INFORMATION                             \
	(OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | \
	 DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION |   \
	 LABEL_SECURITY_INFORMATION)

/* Registry value types. */
#define REG_NONE 0U
#define REG_SZ 1U
#define REG_EXPAND_SZ 2U
#define REG_BINARY 3U
#define REG_DWORD 4U
#define REG_DWORD_BIG_ENDIAN 5U
#define REG_LINK 6U
#define REG_MULTI_SZ 7U
#define REG_RESOURCE_LIST 8U
#define REG_FULL_RESOURCE_DESCRIPTOR 9U
#define REG_RESOURCE_REQUIREMENTS_LIST 10U
#define REG_QWORD 11U
#define REG_TOMBSTONE 0xFFFFU

/* Watch event types and filters. */
#define REG_WATCH_VALUE_SET 1U
#define REG_WATCH_VALUE_DELETED 2U
#define REG_WATCH_SUBKEY_CREATED 3U
#define REG_WATCH_SUBKEY_DELETED 4U
#define REG_WATCH_SD_CHANGED 5U
#define REG_WATCH_KEY_DELETED 6U
#define REG_WATCH_OVERFLOW 7U

/* Watch event raw byte layout. */
#define REG_WATCH_EVENT_TOTAL_LEN_OFFSET 0U
#define REG_WATCH_EVENT_TYPE_OFFSET 4U
#define REG_WATCH_EVENT_NAME_LEN_OFFSET 6U
#define REG_WATCH_EVENT_NAME_OFFSET 8U
#define REG_WATCH_EVENT_MIN_SIZE 8U
#define REG_WATCH_SUBTREE_PATH_DEPTH_REL_OFFSET 0U
#define REG_WATCH_SUBTREE_PATH_DEPTH_SIZE 2U
#define REG_WATCH_SUBTREE_PATH_COMPONENTS_REL_OFFSET 2U
#define REG_WATCH_PATH_COMPONENT_LEN_SIZE 2U

#define REG_NOTIFY_VALUE 0x01U
#define REG_NOTIFY_SUBKEY 0x02U
#define REG_NOTIFY_SD 0x04U
#define REG_NOTIFY_ALL 0x07U

/* RSI common wire layout. */
#define RSI_REQUEST_TOTAL_LEN_OFFSET 0U
#define RSI_REQUEST_ID_OFFSET 4U
#define RSI_REQUEST_OP_CODE_OFFSET 12U
#define RSI_REQUEST_TXN_ID_OFFSET 14U
#define RSI_REQUEST_HEADER_SIZE 22U

#define RSI_RESPONSE_TOTAL_LEN_OFFSET 0U
#define RSI_RESPONSE_ID_OFFSET 4U
#define RSI_RESPONSE_OP_CODE_OFFSET 12U
#define RSI_RESPONSE_HEADER_SIZE 14U
#define RSI_RESPONSE_STATUS_OFFSET 14U
#define RSI_STATUS_SIZE 4U
#define RSI_MIN_RESPONSE_SIZE 18U

#define RSI_LENGTH_PREFIX_SIZE 4U
#define RSI_GUID_SIZE 16U
#define RSI_RESPONSE_BIT 0x8000U

/* RSI op codes and response op codes. */
#define RSI_LOOKUP 0x0001U
#define RSI_CREATE_ENTRY 0x0002U
#define RSI_HIDE_ENTRY 0x0003U
#define RSI_DELETE_ENTRY 0x0004U
#define RSI_ENUM_CHILDREN 0x0005U
#define RSI_CREATE_KEY 0x0010U
#define RSI_READ_KEY 0x0011U
#define RSI_WRITE_KEY 0x0012U
#define RSI_DROP_KEY 0x0013U
#define RSI_QUERY_VALUES 0x0020U
#define RSI_SET_VALUE 0x0021U
#define RSI_DELETE_VALUE_ENTRY 0x0022U
#define RSI_SET_BLANKET_TOMBSTONE 0x0023U
#define RSI_BEGIN_TRANSACTION 0x0030U
#define RSI_COMMIT_TRANSACTION 0x0031U
#define RSI_ABORT_TRANSACTION 0x0032U
#define RSI_FLUSH 0x0040U
#define RSI_DELETE_LAYER 0x0050U

#define RSI_LOOKUP_RESPONSE 0x8001U
#define RSI_CREATE_ENTRY_RESPONSE 0x8002U
#define RSI_HIDE_ENTRY_RESPONSE 0x8003U
#define RSI_DELETE_ENTRY_RESPONSE 0x8004U
#define RSI_ENUM_CHILDREN_RESPONSE 0x8005U
#define RSI_CREATE_KEY_RESPONSE 0x8010U
#define RSI_READ_KEY_RESPONSE 0x8011U
#define RSI_WRITE_KEY_RESPONSE 0x8012U
#define RSI_DROP_KEY_RESPONSE 0x8013U
#define RSI_QUERY_VALUES_RESPONSE 0x8020U
#define RSI_SET_VALUE_RESPONSE 0x8021U
#define RSI_DELETE_VALUE_ENTRY_RESPONSE 0x8022U
#define RSI_SET_BLANKET_TOMBSTONE_RESPONSE 0x8023U
#define RSI_BEGIN_TRANSACTION_RESPONSE 0x8030U
#define RSI_COMMIT_TRANSACTION_RESPONSE 0x8031U
#define RSI_ABORT_TRANSACTION_RESPONSE 0x8032U
#define RSI_FLUSH_RESPONSE 0x8040U
#define RSI_DELETE_LAYER_RESPONSE 0x8050U

/* RSI status codes. */
#define RSI_OK 0U
#define RSI_NOT_FOUND 1U
#define RSI_ALREADY_EXISTS 2U
#define RSI_STORAGE_ERROR 3U
#define RSI_NOT_EMPTY 4U
#define RSI_TOO_LARGE 5U
#define RSI_TXN_BUSY 6U
#define RSI_INVALID 7U
#define RSI_CAS_FAILED 8U
#define RSI_TXN_NOT_SUPPORTED 9U

/* RSI path target types. */
#define RSI_PATH_TARGET_GUID 0U
#define RSI_PATH_TARGET_HIDDEN 1U

/* RSI_WRITE_KEY field mask bits. */
#define RSI_WRITE_KEY_FIELD_SD 0x01U
#define RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME 0x02U
#define RSI_WRITE_KEY_FIELD_KNOWN_MASK \
	(RSI_WRITE_KEY_FIELD_SD | RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME)

/* RSI transaction modes and source-registration flags. */
#define RSI_TXN_READ_WRITE 0U
#define RSI_TXN_READ_ONLY 1U
#define RSI_HIVE_PRIVATE 0x01U

/* Backup record types and magic. */
#define REG_BACKUP_HEADER 0x01U
#define REG_BACKUP_LAYER 0x02U
#define REG_BACKUP_KEY 0x03U
#define REG_BACKUP_PATH_ENTRY 0x04U
#define REG_BACKUP_VALUE 0x05U
#define REG_BACKUP_BLANKET_TOMBSTONE 0x06U
#define REG_BACKUP_TRAILER 0xFFU
#define REG_BACKUP_MAGIC "PEIOSREG"

#endif /* _UAPI_PKM_LCS_H */
