/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Userspace-cleanliness smoke test for the PKM UAPI headers.
 *
 * This compiles with an ordinary, non-kernel C compiler — the precondition
 * for the cgo -godefs binding generator and for any userspace consumer of
 * the PKM ABI. It is built by check-userspace-clean.sh.
 */
#include <stddef.h>

#include <pkm/pkm.h>

#define ASSERT_STRUCT_SIZE(type, expected)                \
	_Static_assert(sizeof(struct type) == (expected), \
		       #type " size disagrees with its header constant")

#define ASSERT_FIELD_OFFSET(type, field, expected)                \
	_Static_assert(                                           \
		offsetof(struct type, field) == (expected), #type \
		"." #field                                        \
		" offset disagrees with Kernel TRM section 5.A (LCS ABI)")

#define ASSERT_IOCTL_ENCODING(command, expected_nr, expected_dir,              \
			      expected_size)                                   \
	_Static_assert(                                                        \
		_IOC_TYPE(command) == REG_IOC_TYPE, #command                   \
		" type disagrees with Kernel TRM section 5.A (LCS ABI)");      \
	_Static_assert(                                                        \
		_IOC_NR(command) == (expected_nr), #command                    \
		" number disagrees with Kernel TRM section 5.A (LCS ABI)");    \
	_Static_assert(                                                        \
		_IOC_DIR(command) == (expected_dir), #command                  \
		" direction disagrees with Kernel TRM section 5.A (LCS ABI)"); \
	_Static_assert(                                                        \
		_IOC_SIZE(command) == (expected_size), #command                \
		" size disagrees with Kernel TRM section 5.A (LCS ABI)")

/* The headers must be internally consistent: each declared size constant
 * must agree with the layout of the struct it describes. */
_Static_assert(
	sizeof(struct kacs_access_check_args) == KACS_ACCESS_CHECK_ARGS_SIZE,
	"kacs_access_check_args size disagrees with its header constant");
_Static_assert(
	sizeof(struct kacs_object_type_entry) == KACS_OBJECT_TYPE_ENTRY_SIZE,
	"kacs_object_type_entry size disagrees with its header constant");
/* The KMES event header is offset-defined, not a struct: its field offsets
 * must be contiguous and the base size must be one past the last field. */
_Static_assert(KMES_EVENT_HEADER_SIZE_OFFSET ==
		       KMES_EVENT_SIZE_OFFSET + sizeof(__u32),
	       "KMES event-header offsets are not contiguous");
_Static_assert(KMES_EVENT_TIMESTAMP_NS_OFFSET ==
		       KMES_EVENT_HEADER_SIZE_OFFSET + sizeof(__u32),
	       "KMES event-header offsets are not contiguous");
_Static_assert(KMES_EVENT_SEQUENCE_OFFSET ==
		       KMES_EVENT_TIMESTAMP_NS_OFFSET + sizeof(__u64),
	       "KMES event-header offsets are not contiguous");
_Static_assert(KMES_EVENT_CPU_ID_OFFSET ==
		       KMES_EVENT_SEQUENCE_OFFSET + sizeof(__u64),
	       "KMES event-header offsets are not contiguous");
_Static_assert(KMES_EVENT_ORIGIN_CLASS_OFFSET ==
		       KMES_EVENT_CPU_ID_OFFSET + sizeof(__u16),
	       "KMES event-header offsets are not contiguous");
_Static_assert(KMES_EVENT_EFFECTIVE_TOKEN_GUID_OFFSET ==
		       KMES_EVENT_ORIGIN_CLASS_OFFSET + sizeof(__u8),
	       "KMES event-header offsets are not contiguous");
_Static_assert(KMES_EVENT_TRUE_TOKEN_GUID_OFFSET ==
		       KMES_EVENT_EFFECTIVE_TOKEN_GUID_OFFSET +
			       KMES_EVENT_GUID_SIZE,
	       "KMES event-header offsets are not contiguous");
_Static_assert(KMES_EVENT_PROCESS_GUID_OFFSET ==
		       KMES_EVENT_TRUE_TOKEN_GUID_OFFSET + KMES_EVENT_GUID_SIZE,
	       "KMES event-header offsets are not contiguous");
_Static_assert(KMES_EVENT_TYPE_LEN_OFFSET ==
		       KMES_EVENT_PROCESS_GUID_OFFSET + KMES_EVENT_GUID_SIZE,
	       "KMES event-header offsets are not contiguous");
_Static_assert(KMES_EVENT_HEADER_BASE_SIZE ==
		       KMES_EVENT_TYPE_LEN_OFFSET + sizeof(__u16),
	       "KMES event-header base size disagrees with its field offsets");
_Static_assert(sizeof(struct kmes_emit_entry) == 32,
	       "kmes_emit_entry must be 32 bytes");
_Static_assert(
	KMES_MAPPING_PRODUCER_OFFSET == 0,
	"KMES producer mapping offset disagrees with Kernel TRM section 2.A (KMES ABI)");
_Static_assert(
	KMES_MAPPING_CONSUMER_OFFSET == KMES_METADATA_PAGE_SIZE,
	"KMES consumer mapping offset disagrees with Kernel TRM section 2.A (KMES ABI)");
_Static_assert(
	KMES_MAPPING_DATA_OFFSET == KMES_METADATA_TOTAL_SIZE,
	"KMES data mapping offset disagrees with Kernel TRM section 2.A (KMES ABI)");
_Static_assert(KMES_CONFIG_BUFFER_CAPACITY_TYPE == REG_QWORD,
	       "KMES BufferCapacity type disagrees with LCS REG_QWORD");
_Static_assert(KMES_CONFIG_MAX_EVENT_SIZE_TYPE == REG_DWORD,
	       "KMES MaxEventSize type disagrees with LCS REG_DWORD");
_Static_assert(KMES_CONFIG_MAX_NESTING_DEPTH_TYPE == REG_DWORD,
	       "KMES MaxNestingDepth type disagrees with LCS REG_DWORD");
_Static_assert(KMES_CONFIG_MAX_EMIT_RATE_PER_PROCESS_TYPE == REG_DWORD,
	       "KMES MaxEmitRatePerProcess type disagrees with LCS REG_DWORD");
_Static_assert(
	KMES_CONFIG_BUFFER_CAPACITY_DEFAULT == 4194304ULL &&
		KMES_CONFIG_BUFFER_CAPACITY_MIN == 65536ULL &&
		KMES_CONFIG_BUFFER_CAPACITY_MAX == 268435456ULL,
	"KMES BufferCapacity range disagrees with Kernel TRM section 2.A (KMES ABI)");
_Static_assert(
	KMES_CONFIG_MAX_EVENT_SIZE_DEFAULT == 65536U &&
		KMES_CONFIG_MAX_EVENT_SIZE_MIN == 1024U &&
		KMES_CONFIG_MAX_EVENT_SIZE_MAX == 4194304U,
	"KMES MaxEventSize range disagrees with Kernel TRM section 2.A (KMES ABI)");
_Static_assert(
	KMES_CONFIG_MAX_NESTING_DEPTH_DEFAULT == 32U &&
		KMES_CONFIG_MAX_NESTING_DEPTH_MIN == 4U &&
		KMES_CONFIG_MAX_NESTING_DEPTH_MAX == 256U,
	"KMES MaxNestingDepth range disagrees with Kernel TRM section 2.A (KMES ABI)");
_Static_assert(
	KMES_CONFIG_MAX_EMIT_RATE_PER_PROCESS_DEFAULT == 10000U &&
		KMES_CONFIG_MAX_EMIT_RATE_PER_PROCESS_MIN == 100U &&
		KMES_CONFIG_MAX_EMIT_RATE_PER_PROCESS_MAX == 1000000U,
	"KMES MaxEmitRatePerProcess range disagrees with Kernel TRM section 2.A (KMES ABI)");
_Static_assert(KMES_EMIT_REQUIRED_PRIVILEGE == KACS_SE_AUDIT_PRIVILEGE,
	       "KMES emit privilege disagrees with KACS SeAuditPrivilege");
_Static_assert(KMES_ATTACH_REQUIRED_PRIVILEGE == KACS_SE_SECURITY_PRIVILEGE,
	       "KMES attach privilege disagrees with KACS SeSecurityPrivilege");
_Static_assert(RSI_REQUEST_ID_OFFSET ==
		       RSI_REQUEST_TOTAL_LEN_OFFSET + sizeof(__u32),
	       "RSI request-header offsets are not contiguous");
_Static_assert(RSI_REQUEST_OP_CODE_OFFSET ==
		       RSI_REQUEST_ID_OFFSET + sizeof(__u64),
	       "RSI request-header offsets are not contiguous");
_Static_assert(RSI_REQUEST_TXN_ID_OFFSET ==
		       RSI_REQUEST_OP_CODE_OFFSET + sizeof(__u16),
	       "RSI request-header offsets are not contiguous");
_Static_assert(
	RSI_REQUEST_HEADER_SIZE == RSI_REQUEST_TXN_ID_OFFSET + sizeof(__u64),
	"RSI request-header size disagrees with Kernel TRM section 5.A (LCS ABI)");
_Static_assert(RSI_RESPONSE_ID_OFFSET ==
		       RSI_RESPONSE_TOTAL_LEN_OFFSET + sizeof(__u32),
	       "RSI response-header offsets are not contiguous");
_Static_assert(RSI_RESPONSE_OP_CODE_OFFSET ==
		       RSI_RESPONSE_ID_OFFSET + sizeof(__u64),
	       "RSI response-header offsets are not contiguous");
_Static_assert(
	RSI_RESPONSE_HEADER_SIZE == RSI_RESPONSE_OP_CODE_OFFSET + sizeof(__u16),
	"RSI response-header size disagrees with Kernel TRM section 5.A (LCS ABI)");
_Static_assert(RSI_RESPONSE_STATUS_OFFSET == RSI_RESPONSE_HEADER_SIZE,
	       "RSI response status must be first payload field");
_Static_assert(
	RSI_MIN_RESPONSE_SIZE == RSI_RESPONSE_STATUS_OFFSET + RSI_STATUS_SIZE,
	"RSI minimum response size disagrees with Kernel TRM section 5.A (LCS ABI)");
_Static_assert(RSI_LENGTH_PREFIX_SIZE == sizeof(__u32),
	       "RSI length-prefixed fields use uint32 lengths");
_Static_assert(RSI_GUID_SIZE == 16, "RSI GUID fields must be 16 raw bytes");
_Static_assert(
	RSI_LOOKUP_RESPONSE == (RSI_LOOKUP | RSI_RESPONSE_BIT),
	"RSI response op-code high bit disagrees with Kernel TRM section 5.A (LCS ABI)");
_Static_assert(
	RSI_PATH_TARGET_GUID == 0 && RSI_PATH_TARGET_HIDDEN == 1,
	"RSI path target codes disagree with Kernel TRM section 5.A (LCS ABI)");
_Static_assert(
	RSI_WRITE_KEY_FIELD_KNOWN_MASK ==
		(RSI_WRITE_KEY_FIELD_SD | RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME),
	"RSI_WRITE_KEY field mask disagrees with Kernel TRM section 5.A (LCS ABI)");
_Static_assert(REG_WATCH_EVENT_TYPE_OFFSET ==
		       REG_WATCH_EVENT_TOTAL_LEN_OFFSET + sizeof(__u32),
	       "watch event offsets are not contiguous");
_Static_assert(REG_WATCH_EVENT_NAME_LEN_OFFSET ==
		       REG_WATCH_EVENT_TYPE_OFFSET + sizeof(__u16),
	       "watch event offsets are not contiguous");
_Static_assert(REG_WATCH_EVENT_NAME_OFFSET ==
		       REG_WATCH_EVENT_NAME_LEN_OFFSET + sizeof(__u16),
	       "watch event offsets are not contiguous");
_Static_assert(
	REG_WATCH_EVENT_MIN_SIZE == REG_WATCH_EVENT_NAME_OFFSET,
	"watch event minimum size disagrees with Kernel TRM section 5.A (LCS ABI)");
_Static_assert(
	REG_WATCH_SUBTREE_PATH_DEPTH_SIZE == sizeof(__u16),
	"watch subtree path_depth size disagrees with Kernel TRM section 5.A (LCS ABI)");
_Static_assert(REG_WATCH_SUBTREE_PATH_COMPONENTS_REL_OFFSET ==
		       REG_WATCH_SUBTREE_PATH_DEPTH_REL_OFFSET +
			       REG_WATCH_SUBTREE_PATH_DEPTH_SIZE,
	       "watch subtree extension offsets are not contiguous");
_Static_assert(
	REG_WATCH_PATH_COMPONENT_LEN_SIZE == sizeof(__u16),
	"watch subtree component length size disagrees with Kernel TRM section 5.A (LCS ABI)");

ASSERT_STRUCT_SIZE(reg_create_key_args, REG_CREATE_KEY_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_create_key_args, parent_fd, 0);
ASSERT_FIELD_OFFSET(reg_create_key_args, _pad0, 4);
ASSERT_FIELD_OFFSET(reg_create_key_args, path_ptr, 8);
ASSERT_FIELD_OFFSET(reg_create_key_args, desired_access, 16);
ASSERT_FIELD_OFFSET(reg_create_key_args, flags, 20);
ASSERT_FIELD_OFFSET(reg_create_key_args, layer_ptr, 24);
ASSERT_FIELD_OFFSET(reg_create_key_args, txn_fd, 32);
ASSERT_FIELD_OFFSET(reg_create_key_args, _pad1, 36);
ASSERT_FIELD_OFFSET(reg_create_key_args, disposition_ptr, 40);

ASSERT_STRUCT_SIZE(reg_query_value_args, REG_QUERY_VALUE_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_query_value_args, name_len, 0);
ASSERT_FIELD_OFFSET(reg_query_value_args, _pad0, 4);
ASSERT_FIELD_OFFSET(reg_query_value_args, name_ptr, 8);
ASSERT_FIELD_OFFSET(reg_query_value_args, type, 16);
ASSERT_FIELD_OFFSET(reg_query_value_args, data_len, 20);
ASSERT_FIELD_OFFSET(reg_query_value_args, txn_fd, 24);
ASSERT_FIELD_OFFSET(reg_query_value_args, layer_buf_len, 28);
ASSERT_FIELD_OFFSET(reg_query_value_args, data_ptr, 32);
ASSERT_FIELD_OFFSET(reg_query_value_args, sequence, 40);
ASSERT_FIELD_OFFSET(reg_query_value_args, layer_len, 48);
ASSERT_FIELD_OFFSET(reg_query_value_args, _pad1, 52);
ASSERT_FIELD_OFFSET(reg_query_value_args, layer_ptr, 56);

ASSERT_STRUCT_SIZE(reg_set_value_args, REG_SET_VALUE_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_set_value_args, name_len, 0);
ASSERT_FIELD_OFFSET(reg_set_value_args, _pad0, 4);
ASSERT_FIELD_OFFSET(reg_set_value_args, name_ptr, 8);
ASSERT_FIELD_OFFSET(reg_set_value_args, type, 16);
ASSERT_FIELD_OFFSET(reg_set_value_args, data_len, 20);
ASSERT_FIELD_OFFSET(reg_set_value_args, data_ptr, 24);
ASSERT_FIELD_OFFSET(reg_set_value_args, layer_len, 32);
ASSERT_FIELD_OFFSET(reg_set_value_args, _pad1, 36);
ASSERT_FIELD_OFFSET(reg_set_value_args, layer_ptr, 40);
ASSERT_FIELD_OFFSET(reg_set_value_args, txn_fd, 48);
ASSERT_FIELD_OFFSET(reg_set_value_args, _pad2, 52);
ASSERT_FIELD_OFFSET(reg_set_value_args, expected_seq, 56);

ASSERT_STRUCT_SIZE(reg_delete_value_args, REG_DELETE_VALUE_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_delete_value_args, name_len, 0);
ASSERT_FIELD_OFFSET(reg_delete_value_args, _pad0, 4);
ASSERT_FIELD_OFFSET(reg_delete_value_args, name_ptr, 8);
ASSERT_FIELD_OFFSET(reg_delete_value_args, layer_len, 16);
ASSERT_FIELD_OFFSET(reg_delete_value_args, _pad1, 20);
ASSERT_FIELD_OFFSET(reg_delete_value_args, layer_ptr, 24);
ASSERT_FIELD_OFFSET(reg_delete_value_args, txn_fd, 32);
ASSERT_FIELD_OFFSET(reg_delete_value_args, _pad2, 36);

ASSERT_STRUCT_SIZE(reg_blanket_tombstone_args, REG_BLANKET_TOMBSTONE_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_blanket_tombstone_args, layer_len, 0);
ASSERT_FIELD_OFFSET(reg_blanket_tombstone_args, _pad0, 4);
ASSERT_FIELD_OFFSET(reg_blanket_tombstone_args, layer_ptr, 8);
ASSERT_FIELD_OFFSET(reg_blanket_tombstone_args, set, 16);
ASSERT_FIELD_OFFSET(reg_blanket_tombstone_args, _pad1, 17);
ASSERT_FIELD_OFFSET(reg_blanket_tombstone_args, txn_fd, 20);

ASSERT_STRUCT_SIZE(reg_query_values_batch_args,
		   REG_QUERY_VALUES_BATCH_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_query_values_batch_args, buf_len, 0);
ASSERT_FIELD_OFFSET(reg_query_values_batch_args, count, 4);
ASSERT_FIELD_OFFSET(reg_query_values_batch_args, buf_ptr, 8);
ASSERT_FIELD_OFFSET(reg_query_values_batch_args, txn_fd, 16);
ASSERT_FIELD_OFFSET(reg_query_values_batch_args, _pad, 20);

ASSERT_STRUCT_SIZE(reg_enum_value_args, REG_ENUM_VALUE_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_enum_value_args, index, 0);
ASSERT_FIELD_OFFSET(reg_enum_value_args, name_len, 4);
ASSERT_FIELD_OFFSET(reg_enum_value_args, name_ptr, 8);
ASSERT_FIELD_OFFSET(reg_enum_value_args, type, 16);
ASSERT_FIELD_OFFSET(reg_enum_value_args, data_len, 20);
ASSERT_FIELD_OFFSET(reg_enum_value_args, data_ptr, 24);
ASSERT_FIELD_OFFSET(reg_enum_value_args, txn_fd, 32);
ASSERT_FIELD_OFFSET(reg_enum_value_args, _pad, 36);

ASSERT_STRUCT_SIZE(reg_enum_subkey_args, REG_ENUM_SUBKEY_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_enum_subkey_args, index, 0);
ASSERT_FIELD_OFFSET(reg_enum_subkey_args, name_len, 4);
ASSERT_FIELD_OFFSET(reg_enum_subkey_args, name_ptr, 8);
ASSERT_FIELD_OFFSET(reg_enum_subkey_args, last_write_time, 16);
ASSERT_FIELD_OFFSET(reg_enum_subkey_args, subkey_count, 24);
ASSERT_FIELD_OFFSET(reg_enum_subkey_args, value_count, 28);
ASSERT_FIELD_OFFSET(reg_enum_subkey_args, txn_fd, 32);
ASSERT_FIELD_OFFSET(reg_enum_subkey_args, _pad, 36);

ASSERT_STRUCT_SIZE(reg_query_key_info_args, REG_QUERY_KEY_INFO_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_query_key_info_args, name_len, 0);
ASSERT_FIELD_OFFSET(reg_query_key_info_args, _pad0, 4);
ASSERT_FIELD_OFFSET(reg_query_key_info_args, name_ptr, 8);
ASSERT_FIELD_OFFSET(reg_query_key_info_args, last_write_time, 16);
ASSERT_FIELD_OFFSET(reg_query_key_info_args, subkey_count, 24);
ASSERT_FIELD_OFFSET(reg_query_key_info_args, value_count, 28);
ASSERT_FIELD_OFFSET(reg_query_key_info_args, max_subkey_name_len, 32);
ASSERT_FIELD_OFFSET(reg_query_key_info_args, max_value_name_len, 36);
ASSERT_FIELD_OFFSET(reg_query_key_info_args, max_value_data_size, 40);
ASSERT_FIELD_OFFSET(reg_query_key_info_args, sd_size, 44);
ASSERT_FIELD_OFFSET(reg_query_key_info_args, volatile_key, 48);
ASSERT_FIELD_OFFSET(reg_query_key_info_args, symlink, 49);
ASSERT_FIELD_OFFSET(reg_query_key_info_args, _pad1, 50);
ASSERT_FIELD_OFFSET(reg_query_key_info_args, hive_generation, 56);

ASSERT_STRUCT_SIZE(reg_delete_key_args, REG_DELETE_KEY_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_delete_key_args, layer_len, 0);
ASSERT_FIELD_OFFSET(reg_delete_key_args, _pad0, 4);
ASSERT_FIELD_OFFSET(reg_delete_key_args, layer_ptr, 8);
ASSERT_FIELD_OFFSET(reg_delete_key_args, txn_fd, 16);
ASSERT_FIELD_OFFSET(reg_delete_key_args, _pad1, 20);

ASSERT_STRUCT_SIZE(reg_hide_key_args, REG_HIDE_KEY_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_hide_key_args, layer_len, 0);
ASSERT_FIELD_OFFSET(reg_hide_key_args, _pad0, 4);
ASSERT_FIELD_OFFSET(reg_hide_key_args, layer_ptr, 8);
ASSERT_FIELD_OFFSET(reg_hide_key_args, txn_fd, 16);
ASSERT_FIELD_OFFSET(reg_hide_key_args, _pad1, 20);

ASSERT_STRUCT_SIZE(reg_get_security_args, REG_GET_SECURITY_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_get_security_args, security_info, 0);
ASSERT_FIELD_OFFSET(reg_get_security_args, sd_len, 4);
ASSERT_FIELD_OFFSET(reg_get_security_args, sd_ptr, 8);

ASSERT_STRUCT_SIZE(reg_set_security_args, REG_SET_SECURITY_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_set_security_args, security_info, 0);
ASSERT_FIELD_OFFSET(reg_set_security_args, sd_len, 4);
ASSERT_FIELD_OFFSET(reg_set_security_args, sd_ptr, 8);
ASSERT_FIELD_OFFSET(reg_set_security_args, txn_fd, 16);
ASSERT_FIELD_OFFSET(reg_set_security_args, _pad, 20);

ASSERT_STRUCT_SIZE(reg_notify_args, REG_NOTIFY_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_notify_args, filter, 0);
ASSERT_FIELD_OFFSET(reg_notify_args, subtree, 4);
ASSERT_FIELD_OFFSET(reg_notify_args, _pad, 5);

ASSERT_STRUCT_SIZE(reg_backup_args, REG_BACKUP_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_backup_args, output_fd, 0);

ASSERT_STRUCT_SIZE(reg_restore_args, REG_RESTORE_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_restore_args, input_fd, 0);

ASSERT_STRUCT_SIZE(reg_txn_status_args, REG_TXN_STATUS_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_txn_status_args, state, 0);
ASSERT_FIELD_OFFSET(reg_txn_status_args, terminal_errno, 4);

ASSERT_STRUCT_SIZE(reg_src_negotiate_args, REG_SRC_NEGOTIATE_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_src_negotiate_args, session, 8);
ASSERT_STRUCT_SIZE(reg_src_request_context_args,
		   REG_SRC_REQUEST_CONTEXT_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_src_request_context_args, request_deadline_ns, 16);
ASSERT_FIELD_OFFSET(reg_src_request_context_args, lease_deadline_ns, 32);
ASSERT_STRUCT_SIZE(reg_src_renew_args, REG_SRC_RENEW_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_src_renew_args, lifetime_deadline_ns, 16);
ASSERT_FIELD_OFFSET(reg_src_renew_args, lease_deadline_ns, 24);
ASSERT_IOCTL_ENCODING(REG_SRC_NEGOTIATE, REG_SRC_NEGOTIATE_NR,
		      _IOC_READ | _IOC_WRITE, REG_SRC_NEGOTIATE_ARGS_SIZE);
ASSERT_IOCTL_ENCODING(REG_SRC_REQUEST_CONTEXT, REG_SRC_REQUEST_CONTEXT_NR,
		      _IOC_READ | _IOC_WRITE,
		      REG_SRC_REQUEST_CONTEXT_ARGS_SIZE);
ASSERT_IOCTL_ENCODING(REG_SRC_RENEW, REG_SRC_RENEW_NR, _IOC_READ | _IOC_WRITE,
		      REG_SRC_RENEW_ARGS_SIZE);

ASSERT_STRUCT_SIZE(reg_src_register_args, REG_SRC_REGISTER_ARGS_SIZE);
ASSERT_FIELD_OFFSET(reg_src_register_args, hive_count, 0);
ASSERT_FIELD_OFFSET(reg_src_register_args, _pad, 4);
ASSERT_FIELD_OFFSET(reg_src_register_args, max_sequence, 8);
ASSERT_FIELD_OFFSET(reg_src_register_args, hives_ptr, 16);

ASSERT_STRUCT_SIZE(reg_src_hive_entry, REG_SRC_HIVE_ENTRY_SIZE);
ASSERT_FIELD_OFFSET(reg_src_hive_entry, name_len, 0);
ASSERT_FIELD_OFFSET(reg_src_hive_entry, _pad0, 4);
ASSERT_FIELD_OFFSET(reg_src_hive_entry, name_ptr, 8);
ASSERT_FIELD_OFFSET(reg_src_hive_entry, root_guid, 16);
ASSERT_FIELD_OFFSET(reg_src_hive_entry, flags, 32);
ASSERT_FIELD_OFFSET(reg_src_hive_entry, _pad1, 36);
ASSERT_FIELD_OFFSET(reg_src_hive_entry, scope_guid, 40);

ASSERT_IOCTL_ENCODING(REG_SRC_REGISTER, REG_SRC_REGISTER_NR, _IOC_WRITE,
		      REG_SRC_REGISTER_ARGS_SIZE);
ASSERT_IOCTL_ENCODING(REG_IOC_QUERY_VALUE, REG_IOC_QUERY_VALUE_NR,
		      _IOC_READ | _IOC_WRITE, REG_QUERY_VALUE_ARGS_SIZE);
ASSERT_IOCTL_ENCODING(REG_IOC_SET_VALUE, REG_IOC_SET_VALUE_NR, _IOC_WRITE,
		      REG_SET_VALUE_ARGS_SIZE);
ASSERT_IOCTL_ENCODING(REG_IOC_DELETE_VALUE, REG_IOC_DELETE_VALUE_NR, _IOC_WRITE,
		      REG_DELETE_VALUE_ARGS_SIZE);
ASSERT_IOCTL_ENCODING(REG_IOC_BLANKET_TOMBSTONE, REG_IOC_BLANKET_TOMBSTONE_NR,
		      _IOC_WRITE, REG_BLANKET_TOMBSTONE_ARGS_SIZE);
ASSERT_IOCTL_ENCODING(REG_IOC_QUERY_VALUES_BATCH, REG_IOC_QUERY_VALUES_BATCH_NR,
		      _IOC_READ | _IOC_WRITE, REG_QUERY_VALUES_BATCH_ARGS_SIZE);
ASSERT_IOCTL_ENCODING(REG_IOC_ENUM_VALUES, REG_IOC_ENUM_VALUES_NR,
		      _IOC_READ | _IOC_WRITE, REG_ENUM_VALUE_ARGS_SIZE);
ASSERT_IOCTL_ENCODING(REG_IOC_ENUM_SUBKEYS, REG_IOC_ENUM_SUBKEYS_NR,
		      _IOC_READ | _IOC_WRITE, REG_ENUM_SUBKEY_ARGS_SIZE);
ASSERT_IOCTL_ENCODING(REG_IOC_QUERY_KEY_INFO, REG_IOC_QUERY_KEY_INFO_NR,
		      _IOC_READ | _IOC_WRITE, REG_QUERY_KEY_INFO_ARGS_SIZE);
ASSERT_IOCTL_ENCODING(REG_IOC_DELETE_KEY, REG_IOC_DELETE_KEY_NR, _IOC_WRITE,
		      REG_DELETE_KEY_ARGS_SIZE);
ASSERT_IOCTL_ENCODING(REG_IOC_HIDE_KEY, REG_IOC_HIDE_KEY_NR, _IOC_WRITE,
		      REG_HIDE_KEY_ARGS_SIZE);
ASSERT_IOCTL_ENCODING(REG_IOC_GET_SECURITY, REG_IOC_GET_SECURITY_NR,
		      _IOC_READ | _IOC_WRITE, REG_GET_SECURITY_ARGS_SIZE);
ASSERT_IOCTL_ENCODING(REG_IOC_SET_SECURITY, REG_IOC_SET_SECURITY_NR, _IOC_WRITE,
		      REG_SET_SECURITY_ARGS_SIZE);
ASSERT_IOCTL_ENCODING(REG_IOC_NOTIFY, REG_IOC_NOTIFY_NR, _IOC_WRITE,
		      REG_NOTIFY_ARGS_SIZE);
ASSERT_IOCTL_ENCODING(REG_IOC_FLUSH, REG_IOC_FLUSH_NR, _IOC_NONE, 0);
ASSERT_IOCTL_ENCODING(REG_IOC_BACKUP, REG_IOC_BACKUP_NR, _IOC_WRITE,
		      REG_BACKUP_ARGS_SIZE);
ASSERT_IOCTL_ENCODING(REG_IOC_RESTORE, REG_IOC_RESTORE_NR, _IOC_WRITE,
		      REG_RESTORE_ARGS_SIZE);
ASSERT_IOCTL_ENCODING(REG_IOC_COMMIT, REG_IOC_COMMIT_NR, _IOC_NONE, 0);
ASSERT_IOCTL_ENCODING(REG_IOC_TXN_STATUS, REG_IOC_TXN_STATUS_NR, _IOC_READ,
		      REG_TXN_STATUS_ARGS_SIZE);
_Static_assert(sizeof(REG_BACKUP_MAGIC) - 1 == 8,
	       "REG_BACKUP_MAGIC must be eight bytes");

/*
 * KACS wire-format payloads (kacs_create_token / kacs_create_logon_session /
 * kacs_set_caap specs). These are offset-defined byte layouts, not C structs;
 * pin the documented header byte lengths and the load-bearing field offsets so
 * the uapi mirror cannot drift from the kernel's parser.
 */

/* Token spec: the fixed header is exactly its documented byte length, and the
 * minimum spec is the header alone. The last header field (lcs_credentials_
 * offset, a __u32) ends the header. */
_Static_assert(KACS_TOKEN_SPEC_HEADER_BYTES ==
		       KACS_TOKEN_SPEC_OFF_LCS_CREDENTIALS_OFFSET +
			       sizeof(__u32),
	       "token-spec header length disagrees with its last field offset");
_Static_assert(KACS_TOKEN_SPEC_MIN_BYTES == KACS_TOKEN_SPEC_HEADER_BYTES,
	       "token-spec minimum size must be the header size");
_Static_assert(
	KACS_TOKEN_SPEC_HEADER_BYTES == 192U,
	"token-spec header must be 192 bytes (Kernel TRM section 3.A (KACS ABI))");
_Static_assert(
	KACS_TOKEN_SPEC_VERSION == 2U,
	"token-spec version must be 2 (Kernel TRM section 3.A (KACS ABI))");
_Static_assert(KACS_TOKEN_SPEC_OFF_SOURCE_NAME +
			       KACS_TOKEN_SPEC_SOURCE_NAME_BYTES ==
		       KACS_TOKEN_SPEC_OFF_SOURCE_ID,
	       "token-spec source_name field must abut source_id");

/* Token LCS extension: the fixed header is one past its last field
 * (private_layer_count, a __u32). */
_Static_assert(
	KACS_TOKEN_LCS_EXT_HEADER_BYTES ==
		KACS_TOKEN_LCS_EXT_OFF_PRIVATE_LAYER_COUNT + sizeof(__u32),
	"LCS-extension header length disagrees with its last field offset");
_Static_assert(
	KACS_TOKEN_LCS_EXT_VERSION == 1U,
	"LCS-extension version must be 1 (Kernel TRM section 3.A (KACS ABI))");

/* LogonSession spec: the documented minimum is the empty-auth-package, minimum-SID
 * case (logon_type + auth_pkg_len + user_sid_len + an 8-byte SID). */
_Static_assert(KACS_LOGON_SESSION_SPEC_OFF_AUTH_PKG ==
		       KACS_LOGON_SESSION_SPEC_OFF_AUTH_PKG_LEN + sizeof(__u16),
	       "session-spec auth_pkg must follow the __le16 auth_pkg_len");
_Static_assert(
	KACS_LOGON_SESSION_SPEC_MIN_BYTES == 15U,
	"session-spec minimum size disagrees with Kernel TRM section 3.A (KACS ABI)");

/* CAAP spec: the fixed prefix is version (__u8) + rule_count (__le32). */
_Static_assert(KACS_CAAP_SPEC_OFF_RULE_COUNT ==
		       KACS_CAAP_SPEC_OFF_VERSION + sizeof(__u8),
	       "CAAP rule_count must follow the version byte");
_Static_assert(KACS_CAAP_SPEC_PREFIX_BYTES ==
		       KACS_CAAP_SPEC_OFF_RULE_COUNT + sizeof(__u32),
	       "CAAP prefix length disagrees with its field offsets");
_Static_assert(
	KACS_CAAP_SPEC_VERSION == 1U,
	"CAAP spec version must be 1 (Kernel TRM section 3.A (KACS ABI))");

/*
 * Mandatory-label ACE mask bits (<pkm/sd.h>). These are the policy bits of a
 * KACS_ACE_TYPE_SYSTEM_MANDATORY_LABEL ACE's access mask; pin each value so
 * the uapi mirror cannot drift from the kernel MIC enforcer (Kernel TRM section 3.A (KACS ABI)).
 */
_Static_assert(
	KACS_SYSTEM_MANDATORY_LABEL_NO_READ_UP == 0x00000001U,
	"mandatory-label NO_READ_UP must be bit 0 (Kernel TRM section 3.A (KACS ABI))");
_Static_assert(
	KACS_SYSTEM_MANDATORY_LABEL_NO_WRITE_UP == 0x00000002U,
	"mandatory-label NO_WRITE_UP must be bit 1 (Kernel TRM section 3.A (KACS ABI))");
_Static_assert(
	KACS_SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP == 0x00000004U,
	"mandatory-label NO_EXECUTE_UP must be bit 2 (Kernel TRM section 3.A (KACS ABI))");

/*
 * PSB process-mitigation bits (<pkm/psb.h>). Pin each bit's value and that the
 * ALL mask is exactly the OR of its member bits, so the kacs_set_psb argument
 * encoding cannot drift from the kernel (Kernel TRM section 3.A (KACS ABI)).
 */
_Static_assert(KACS_MIT_WXP == 0x001U,
	       "KACS_MIT_WXP must be 0x001 (Kernel TRM section 3.A (KACS ABI))");
_Static_assert(KACS_MIT_TLP == 0x002U,
	       "KACS_MIT_TLP must be 0x002 (Kernel TRM section 3.A (KACS ABI))");
_Static_assert(KACS_MIT_LSV == 0x004U,
	       "KACS_MIT_LSV must be 0x004 (Kernel TRM section 3.A (KACS ABI))");
_Static_assert(KACS_MIT_CFI == 0x008U,
	       "KACS_MIT_CFI must be 0x008 (Kernel TRM section 3.A (KACS ABI))");
_Static_assert(
	KACS_MIT_UI_ACCESS == 0x010U,
	"KACS_MIT_UI_ACCESS must be 0x010 (Kernel TRM section 3.A (KACS ABI))");
_Static_assert(
	KACS_MIT_NO_CHILD == 0x020U,
	"KACS_MIT_NO_CHILD must be 0x020 (Kernel TRM section 3.A (KACS ABI))");
_Static_assert(
	KACS_MIT_CFIF == 0x040U,
	"KACS_MIT_CFIF must be 0x040 (Kernel TRM section 3.A (KACS ABI))");
_Static_assert(
	KACS_MIT_CFIB == 0x080U,
	"KACS_MIT_CFIB must be 0x080 (Kernel TRM section 3.A (KACS ABI))");
_Static_assert(KACS_MIT_PIE == 0x100U,
	       "KACS_MIT_PIE must be 0x100 (Kernel TRM section 3.A (KACS ABI))");
_Static_assert(KACS_MIT_SML == 0x200U,
	       "KACS_MIT_SML must be 0x200 (Kernel TRM section 3.A (KACS ABI))");
/* The ALL mask is exactly the OR of every individual mitigation bit. The
 * legacy KACS_MIT_CFI alias is included: its value (0x008) is a distinct bit
 * position in the mask even though a request normalizes it to CFIF | CFIB. */
_Static_assert(KACS_MIT_ALL == (KACS_MIT_WXP | KACS_MIT_TLP | KACS_MIT_LSV |
				KACS_MIT_CFI | KACS_MIT_UI_ACCESS |
				KACS_MIT_NO_CHILD | KACS_MIT_CFIF |
				KACS_MIT_CFIB | KACS_MIT_PIE | KACS_MIT_SML),
	       "KACS_MIT_ALL must be the OR of every mitigation bit");
_Static_assert(KACS_MIT_ALL == 0x3FFU,
	       "KACS_MIT_ALL must be 0x3FF (Kernel TRM section 3.A (KACS ABI))");

int main(void)
{
	/* Touch constants and a struct from across the header set so the
	 * compiler resolves real symbols, not merely the #include lines. */
	return (int)(SYS_KACS_OPEN + KACS_TOKEN_QUERY +
		     KACS_SE_BACKUP_PRIVILEGE + KACS_SD_DACL_PRESENT +
		     KMES_ORIGIN_KACS + SYS_REG_OPEN_KEY + REG_OPEN_LINK +
		     KEY_QUERY_VALUE + REG_IOC_QUERY_VALUE + REG_BACKUP_HEADER +
		     sizeof(struct kacs_query_args));
}
