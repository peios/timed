/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_PKM_KMES_H
#define _UAPI_PKM_KMES_H

#include <linux/types.h>

/*
 * KMES — the Kernel-Mediated Event Stream.
 *
 * Events are emitted via SYS_KMES_EMIT / SYS_KMES_EMIT_BATCH and consumed
 * through per-CPU ring buffers. SYS_KMES_ATTACH(cpu_id, capacity) returns one
 * mmap-able fd for a single CPU's ring; a consumer learns how many ring slots
 * exist with KMES_ATTACH_QUERY_SLOTS below and attaches to each in turn. This
 * header defines the emission ABI, the ring-buffer metadata layout, and the
 * on-wire event header a consumer parses.
 */

/* Event origin class — kmes_event_header.origin_class. */
#define KMES_ORIGIN_USERSPACE 0U
#define KMES_ORIGIN_KMES 1U
#define KMES_ORIGIN_KACS 2U
#define KMES_ORIGIN_LCS 3U
#define KMES_ORIGIN_NTFE \
	4U /* net/ntfe: ntfe.verdict.reported, ntfe.policy.published, ntfe.policy.rejected */

/*
 * One descriptor in a SYS_KMES_EMIT_BATCH entry array.
 *
 * event_type and payload hold the address of, respectively, the event-type
 * string and the msgpack payload. They are __u64 (not pointers) because
 * the same structure carries either userspace or kernel addresses
 * depending on the emit path; the consumer interprets them accordingly.
 * The _pad fields make the 32-byte layout explicit and must be zero.
 */
struct kmes_emit_entry {
	__u64 event_type;
	__u16 event_type_len;
	__u8 _pad0[6];
	__u64 payload;
	__u32 payload_len;
	__u8 _pad1[4];
};

/*
 * Ring-slot discovery.
 *
 * Ring slots are indexed by logical CPU id and the array is sized by the
 * kernel's nr_cpu_ids, so a slot inside the array holds no ring when that CPU
 * is not possible. Counting up from 0 until SYS_KMES_ATTACH returns -EINVAL
 * therefore stops at the first hole and misses every ring above it, leaving
 * those CPUs' events permanently unreachable.
 *
 * Call SYS_KMES_ATTACH with cpu_id KMES_ATTACH_QUERY_SLOTS to learn the slot
 * count instead. It writes the count through the capacity argument, returns 0,
 * and opens no descriptor. Enumerate 0 .. count-1 and treat -EINVAL as "this
 * slot holds no ring", not as the end of the array.
 *
 * The sentinel is outside the index space for good: nr_cpu_ids is bounded by
 * CONFIG_NR_CPUS, which cannot reach 2^32-1.
 */
#define KMES_ATTACH_QUERY_SLOTS 0xFFFFFFFFU

/* Largest entry count a single SYS_KMES_EMIT_BATCH call accepts. */
#define KMES_BATCH_MAX_ENTRIES 256U

/*
 * Runtime configuration registry location and keys.
 *
 * Type values match the LCS REG_* constants: REG_DWORD is 4 and REG_QWORD is
 * 11. They are repeated here so <pkm/kmes.h> remains standalone.
 */
#define KMES_CONFIG_ROOT_HIVE "Machine"
#define KMES_CONFIG_ROOT_SYSTEM_KEY "System"
#define KMES_CONFIG_ROOT_KMES_KEY "KMES"
#define KMES_CONFIG_KEY_BUFFER_CAPACITY "BufferCapacity"
#define KMES_CONFIG_KEY_MAX_EVENT_SIZE "MaxEventSize"
#define KMES_CONFIG_KEY_MAX_NESTING_DEPTH "MaxNestingDepth"
#define KMES_CONFIG_KEY_MAX_EMIT_RATE_PER_PROCESS "MaxEmitRatePerProcess"

#define KMES_CONFIG_TYPE_REG_DWORD 4U
#define KMES_CONFIG_TYPE_REG_QWORD 11U

#define KMES_CONFIG_BUFFER_CAPACITY_TYPE KMES_CONFIG_TYPE_REG_QWORD
#define KMES_CONFIG_BUFFER_CAPACITY_DEFAULT 4194304ULL
#define KMES_CONFIG_BUFFER_CAPACITY_MIN 65536ULL
#define KMES_CONFIG_BUFFER_CAPACITY_MAX 268435456ULL

#define KMES_CONFIG_MAX_EVENT_SIZE_TYPE KMES_CONFIG_TYPE_REG_DWORD
#define KMES_CONFIG_MAX_EVENT_SIZE_DEFAULT 65536U
#define KMES_CONFIG_MAX_EVENT_SIZE_MIN 1024U
#define KMES_CONFIG_MAX_EVENT_SIZE_MAX 4194304U

#define KMES_CONFIG_MAX_NESTING_DEPTH_TYPE KMES_CONFIG_TYPE_REG_DWORD
#define KMES_CONFIG_MAX_NESTING_DEPTH_DEFAULT 32U
#define KMES_CONFIG_MAX_NESTING_DEPTH_MIN 4U
#define KMES_CONFIG_MAX_NESTING_DEPTH_MAX 256U

#define KMES_CONFIG_MAX_EMIT_RATE_PER_PROCESS_TYPE KMES_CONFIG_TYPE_REG_DWORD
#define KMES_CONFIG_MAX_EMIT_RATE_PER_PROCESS_DEFAULT 10000U
#define KMES_CONFIG_MAX_EMIT_RATE_PER_PROCESS_MIN 100U
#define KMES_CONFIG_MAX_EMIT_RATE_PER_PROCESS_MAX 1000000U

/*
 * Privilege requirements. Values mirror the corresponding KACS privilege bits
 * while keeping this header standalone.
 */
#define KMES_EMIT_REQUIRED_PRIVILEGE (1ULL << 21)
#define KMES_ATTACH_REQUIRED_PRIVILEGE (1ULL << 8)

/*
 * On-wire event header.
 *
 * Every event in a ring begins with a fixed 77-byte header, followed by
 * event_type_len bytes of type string and then the msgpack payload. Events
 * abut at event_size stride, so a header is not generally aligned; it
 * crosses the ABI as raw bytes, not a C struct. Its fields, in order:
 *
 *   __u32  event_size            total event byte length (header + type + payload)
 *   __u32  header_size           byte offset from the event start to the payload
 *   __u64  timestamp_ns
 *   __u64  sequence
 *   __u16  cpu_id
 *   __u8   origin_class          one of KMES_ORIGIN_* above
 *   __u8   effective_token_guid[16]
 *   __u8   true_token_guid[16]
 *   __u8   process_guid[16]
 *   __u16  event_type_len        length of the type string following the header
 *
 * The three GUIDs are 16-byte Microsoft GUID binary values (Data1/Data2/Data3
 * little-endian, Data4 raw), captured from KACS at emission time; the null GUID
 * (16 zero bytes) means identity was unavailable (KACS not initialised, or no
 * process context). KMES copies them opaquely.
 *
 * Read each field at its KMES_EVENT_*_OFFSET below. header_size locates the
 * payload: it is KMES_EVENT_HEADER_BASE_SIZE + event_type_len. A future
 * revision may grow the header, so consumers must use header_size, not the
 * end of the type string, to find the payload.
 */
#define KMES_EVENT_SIZE_OFFSET 0U
#define KMES_EVENT_HEADER_SIZE_OFFSET 4U
#define KMES_EVENT_TIMESTAMP_NS_OFFSET 8U
#define KMES_EVENT_SEQUENCE_OFFSET 16U
#define KMES_EVENT_CPU_ID_OFFSET 24U
#define KMES_EVENT_ORIGIN_CLASS_OFFSET 26U
#define KMES_EVENT_EFFECTIVE_TOKEN_GUID_OFFSET 27U
#define KMES_EVENT_TRUE_TOKEN_GUID_OFFSET 43U
#define KMES_EVENT_PROCESS_GUID_OFFSET 59U
#define KMES_EVENT_TYPE_LEN_OFFSET 75U

/* Byte width of each identity GUID in the event header. */
#define KMES_EVENT_GUID_SIZE 16U

/* Byte size of the fixed event header — the offset at which the type
 * string begins. */
#define KMES_EVENT_HEADER_BASE_SIZE 77U

/*
 * Ring-buffer metadata layout. An attached ring is mmap'd as:
 *   page 0          producer metadata (read-only to the consumer)
 *   page 1          consumer metadata (read-write)
 *   ring data       the event bytes, mapped twice back-to-back so an event
 *                   that wraps the buffer end is still contiguous.
 * The producer metadata page begins with KMES_RING_MAGIC.
 */
#define KMES_RING_MAGIC "KMESRING"
#define KMES_RING_VERSION 1U
#define KMES_METADATA_PAGE_SIZE 4096U
#define KMES_METADATA_TOTAL_SIZE (2U * KMES_METADATA_PAGE_SIZE)
#define KMES_MAPPING_PRODUCER_OFFSET 0U
#define KMES_MAPPING_CONSUMER_OFFSET KMES_METADATA_PAGE_SIZE
#define KMES_MAPPING_DATA_OFFSET KMES_METADATA_TOTAL_SIZE

/* Field offsets within the producer metadata page. */
#define KMES_PRODUCER_MAGIC_OFFSET 0U
#define KMES_PRODUCER_VERSION_OFFSET 8U
#define KMES_PRODUCER_CPU_ID_OFFSET 12U
#define KMES_PRODUCER_CAPACITY_OFFSET 16U
#define KMES_PRODUCER_DATA_OFFSET_OFFSET 24U
#define KMES_PRODUCER_GENERATION_OFFSET 32U
#define KMES_PRODUCER_WRITE_POS_OFFSET 64U
#define KMES_PRODUCER_TAIL_POS_OFFSET 72U
#define KMES_PRODUCER_FUTEX_COUNTER_OFFSET 128U

/* Field offset within the consumer metadata page. */
#define KMES_CONSUMER_NEED_WAKE_OFFSET 0U

#endif /* _UAPI_PKM_KMES_H */
