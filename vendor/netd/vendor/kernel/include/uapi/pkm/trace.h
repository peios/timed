/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_PKM_TRACE_H
#define _UAPI_PKM_TRACE_H

/*
 * PKM tracing diagnostic ABI.
 *
 * Stable numeric codes carried by PKM's kernel static tracepoints (the
 * `kacs:`, `kmes:`, and `lcs:` trace systems). These are a *diagnostic*
 * contract for ftrace/perf/eBPF consumers — they let an out-of-tree tool
 * decode a `reason` / `op` / `state` field without recompiling against a
 * specific kernel. They are NOT part of any syscall contract; no PKM syscall
 * accepts or returns them.
 *
 * Because they are an ABI for tooling, values are append-only: never renumber
 * or reuse a code. Add new codes at the end of each group.
 *
 * The in-kernel trace headers (include/trace/events/{kacs,kmes,lcs}.h) map
 * these to symbolic names for the tracefs `format` files via __print_symbolic;
 * this header is the single source of truth for the numeric values.
 */

/*
 * kacs_access_decision reason — why a KACS access hook took the return path it
 * did. Emitted by the kacs:kacs_file_access / _file_open / _native_open /
 * _inode_file_access / _inode_permission events. Verdict (allow vs deny) is a
 * separate signal, read from the `ret` field (0 == allow).
 */
#define KACS_TR_DECISION 0U /* resolved allow/deny */
#define KACS_TR_BAD_ARGS 1U /* NULL/zero argument guard */
#define KACS_TR_NO_ISEC 2U /* inode has no i_security blob */
#define KACS_TR_UNMANAGED 3U /* superblock mount policy UNMANAGED */
#define KACS_TR_PIP_CONTEXT 4U /* current PIP context unavailable */
#define KACS_TR_NO_TOKEN 5U /* no effective subject token */
#define KACS_TR_NO_DENTRY_ALIAS 6U /* inode has no dentry alias yet */
#define KACS_TR_DELETE_ON_CLOSE_PENDING 7U /* open of a delete-on-close file */
#define KACS_TR_NATIVE_STAMP 8U /* native-open granted-access stamp */
#define KACS_TR_NATIVE_ARM 9U /* native-open delete-on-close arm */
#define KACS_TR_STAMP 10U /* legacy-open granted-access stamp */
#define KACS_TR_LAZY_DENTRY_RELOOKUP 11U /* native create lazy re-lookup */
#define KACS_TR_NEGATIVE_AFTER_CREATE 12U /* negative dentry after create */
#define KACS_TR_CHANGE_NOTIFY_PRIV 13U /* traverse via CHANGE_NOTIFY priv */
#define KACS_TR_CHANGE_NOTIFY_PRIV_EXHAUSTED \
	14U /* CHANGE_NOTIFY priv use exhausted */

/*
 * kacs_sd_cache reason — the inode security-descriptor cache outcome. The
 * lookup miss codes disambiguate the three cache-absent paths that were
 * previously an indistinguishable NULL return (no cache / stale generation /
 * missing-but-synthesis-required); the corrupt codes name why a stored SD was
 * rejected. Emitted by kacs:kacs_sd_cache_lookup / _corrupt.
 */
#define KACS_SDC_HIT 0U /* current, valid cache present */
#define KACS_SDC_MISS_NONE 1U /* no cache attached */
#define KACS_SDC_MISS_STALE_GEN 2U /* cache present but stale generation */
#define KACS_SDC_MISS_NEEDS_SYNTH 3U /* missing SD requires synthesis */
#define KACS_SDC_CORRUPT_EMPTY_OR_OVERSIZE \
	4U /* stored SD zero-length or oversize */
#define KACS_SDC_CORRUPT_VALIDATE_FAIL 5U /* stored SD failed validation */

/*
 * kacs_process_access reason — the outcome of a cross-process access decision
 * (signal, ptrace, scheduler/attribute, prlimit). The reason distinguishes the
 * paths that all surface as -EACCES: an SD denial, a PIP-based denial, a denial
 * rescued (or not) by SeDebugPrivilege, and a PIP-dominance failure. Emitted by
 * kacs:kacs_process_access.
 */
#define KACS_PA_ALLOW 0U /* access granted */
#define KACS_PA_BAD_ARGS 1U /* NULL subject/target guard */
#define KACS_PA_NO_TARGET 2U /* target has no process state/SD */
#define KACS_PA_NO_SD 3U /* target process SD unavailable */
#define KACS_PA_SD_ERROR 4U /* SD check failed (non-EACCES) */
#define KACS_PA_PIP_DENIED 5U /* denied by process-integrity policy */
#define KACS_PA_DEBUG_RESCUE 6U /* SD denial rescued by SeDebugPrivilege */
#define KACS_PA_DEBUG_DENIED 7U /* denied; no usable SeDebugPrivilege */
#define KACS_PA_PIP_DOMINANCE 8U /* caller PIP does not dominate target */

/*
 * kacs_exec reason — an exec/bprm credential or PIP transition. Distinguishes
 * the uid/gid-change gate outcomes, the exec primary-token derivation paths and
 * their failures, the exec file integrity-label lookup failures, and the two
 * commit-time transitions. Verdict is the `ret` field. Emitted by kacs:kacs_exec.
 */
#define KACS_EXEC_CREDS_ALLOW 0U /* exec cred transition allowed */
#define KACS_EXEC_BAD_ARGS 1U /* NULL cred/token guard */
#define KACS_EXEC_ID_CHANGE_NO_TOKEN 2U /* uid/gid change, no subject token */
#define KACS_EXEC_ID_CHANGE_PRIV_UNSUPPORTED \
	3U /* id change + ASSIGN_PRIMARY_TOKEN priv */
#define KACS_EXEC_TOKEN_NPM_DERIVED \
	4U /* exec token derived via new-process-min */
#define KACS_EXEC_TOKEN_CLONE 5U /* exec token via primary clone fallback */
#define KACS_EXEC_NPM_NO_FILE 6U /* new-process-min needs file, none supplied */
#define KACS_EXEC_NPM_DERIVE_FAIL \
	7U /* new_process_min_exec derivation failed */
#define KACS_EXEC_TOKEN_INSTALL_FAIL \
	8U /* install token ref on new cred failed */
#define KACS_EXEC_TOKEN_CLONE_FAIL 9U /* primary token clone returned NULL */
#define KACS_EXEC_INTEGRITY_NO_ISEC 10U /* exec file inode has no i_security */
#define KACS_EXEC_INTEGRITY_NO_CACHE 11U /* exec file SD cache absent */
#define KACS_EXEC_INTEGRITY_INVALID_SD \
	12U /* exec file cached SD invalid/empty */
#define KACS_EXEC_IMPERSONATION_REVERT_FAIL \
	13U /* bprm impersonation revert failed */
#define KACS_EXEC_PIP_COMMITTED 14U /* pending exec PIP committed at commit */
#define KACS_EXEC_UMH_NOT_TCB 15U /* usermodehelper exec below PeiosTcb trust */
#define KACS_EXEC_SIGNATURE_UNVERIFIABLE \
	16U /* exec refused: signature could not be verified */
#define KACS_EXEC_PIP_CAPPED_UNSAFE \
	17U /* exec PIP label capped at the current one: traced or no_new_privs */

/*
 * kacs_signing reason — code-signature verification outcomes and the distinct
 * reject reasons of the signing-material probe. Only source enum, verified flag,
 * PIP tier codes, file length, reason, and ret are recorded — never key,
 * signature, xattr, or file bytes. Emitted by kacs:kacs_signing_verify /
 * _crypto / _probe.
 */
#define KACS_SIG_UNSIGNED 0U /* material source NONE (unsigned) */
#define KACS_SIG_BAD_KEY_TABLE 1U /* key table malformed / bad args */
#define KACS_SIG_NO_KEY_MATCH 2U /* no key verified the signature */
#define KACS_SIG_VERIFIED 3U /* a key verified; trust assigned */
#define KACS_SIG_CRYPTO_UNAVAILABLE 4U /* mldsa65 tfm allocation failed */
#define KACS_SIG_CRYPTO_MISMATCH 5U /* set-pubkey/verify returned nonzero */
#define KACS_SIG_PROBE_FOUND 6U /* valid signature material committed */
#define KACS_SIG_ELF_MAGIC_READ 7U /* failed reading ELF magic */
#define KACS_SIG_ELF_SHORT_EHDR 8U /* file too short for Elf64_Ehdr */
#define KACS_SIG_ELF_EHDR_READ 9U /* failed reading ELF header */
#define KACS_SIG_ELF_BAD_IDENT 10U /* unsupported e_ident class/data/version */
#define KACS_SIG_ELF_BAD_SHTABLE 11U /* bad shentsize/shstrndx */
#define KACS_SIG_ELF_SHDRS_RANGE \
	12U /* section-header table offset/len out of range */
#define KACS_SIG_ELF_SHSTR_READ 13U /* failed reading shstrtab section header */
#define KACS_SIG_ELF_STRTAB_RANGE 14U /* shstrtab offset/len out of range */
#define KACS_SIG_ELF_SHDR_READ 15U /* failed reading a section header */
#define KACS_SIG_ELF_NAME_READ 16U /* failed reading a section name */
#define KACS_SIG_ELF_BAD_SIG_SECTION 17U /* sig section wrong type/size/range */
#define KACS_SIG_ELF_BAD_BLOB 18U /* sig blob read failed or invalid */
#define KACS_SIG_ELF_HASH_FAIL 19U /* hashing failed for ELF sig */
#define KACS_SIG_XATTR_BAD_BLOB 20U /* xattr sig blob invalid */
#define KACS_SIG_XATTR_HASH_FAIL 21U /* hashing failed for xattr sig */
#define KACS_SIG_SIZE_CHANGED 22U /* file size changed during probe (TOCTOU) */

/*
 * kacs_firmware reason — why a kernel-initiated firmware read was allowed or
 * refused (kacs/firmware.c, PEI-493). Firmware is code that runs on a device
 * with DMA into host memory, so it is held to the PeiosTcb tier: the same
 * bar as a usermodehelper exec. `ret` is the verdict handed to the loader;
 * under log mode it is 0 whatever the reason. Emitted by
 * kacs:kacs_firmware_load. No path, key, or signature bytes are recorded.
 */
#define KACS_FW_ALLOWED 0U /* verified at PeiosTcb */
#define KACS_FW_UNSIGNED 1U /* no signature material on the file */
#define KACS_FW_NO_KEY_MATCH 2U /* signed, but no built-in key verified it */
#define KACS_FW_BELOW_TCB \
	3U /* verified, but the key's tier is below PeiosTcb */
#define KACS_FW_UNVERIFIABLE \
	4U /* verification could not run (crypto unavailable) */
#define KACS_FW_PROBE_FAILED 5U /* reading the signature material failed */

/*
 * kacs_socket reason — the outcome of an AF_UNIX socket SD / impersonation hook.
 * Distinguishes the guard, not-applicable, and verdict paths that otherwise
 * collapse into an indistinguishable -EACCES. Verdict is the `ret` field. No
 * address, pathname, or SD bytes are recorded.
 */
#define KACS_SOCK_BAD_ARGS 0U /* NULL/guard argument rejected */
#define KACS_SOCK_NOT_UNIX 1U /* not AF_UNIX / unsupported type */
#define KACS_SOCK_NO_SECURITY 2U /* sock has no sk_security blob */
#define KACS_SOCK_NO_TOKEN 3U /* no effective subject/client token */
#define KACS_SOCK_BAD_LEVEL 4U /* invalid impersonation level */
#define KACS_SOCK_WRONG_STATE 5U /* socket state forbids the op */
#define KACS_SOCK_NO_PEER_TOKEN 6U /* no captured peer token present */
#define KACS_SOCK_PIP_CONTEXT 7U /* caller PIP context unavailable */
#define KACS_SOCK_SD_DECISION 8U /* socket-SD check produced verdict */
#define KACS_SOCK_NO_SD 9U /* no socket SD; allowed without check */
#define KACS_SOCK_HAVE_SD 10U /* socket SD present; check performed */
#define KACS_SOCK_ALREADY_BOUND 11U /* socket SD already installed */
#define KACS_SOCK_BIND 12U /* abstract-socket SD bind result */
#define KACS_SOCK_CONNECT 13U /* unix_stream_connect result */
#define KACS_SOCK_LEVEL_SET 14U /* impersonation level updated */
#define KACS_SOCK_OPEN_TOKEN 15U /* open peer-token fd result */
/* 16 was KACS_SOCK_IMPERSONATE (kacs_impersonate_peer); retired, not reused. */
#define KACS_SOCK_ATTACH 17U /* identity attached to a send */
#define KACS_SOCK_GATE 18U /* explicit KACS_SCM_TOKEN send-gate verdict */
#define KACS_SOCK_REGISTER 19U /* conveyed-identity register advanced */
#define KACS_SOCK_DELIVER 20U /* KACS_SCM_TOKEN delivered to a receiver */
#define KACS_SOCK_LISTEN 21U /* listener identity captured at listen() */
#define KACS_SOCK_RESTAMP \
	22U /* listener identity replaced by KACS_SO_RESTAMP */
#define KACS_SOCK_PORT_BIND 23U /* inet bind: port reservation SD verdict */
#define KACS_SOCK_PORT_TABLE 24U /* port reservation table load result */
#define KACS_SOCK_OWNER 25U /* governing identity stamped on an inet socket */

/* kacs_ipc reason — a System V IPC object SD decision (ipc.c). */
#define KACS_IPC_ALLOC 0U /* default SD stamped at *get creation */
#define KACS_IPC_PERMISSION \
	1U /* ipc_permission: read/write access to the object */
#define KACS_IPC_CTL 2U /* *ctl command gate (RMID/SET/STAT/...) */
#define KACS_IPC_SD_QUERY 3U /* kacs_get_sd on the object */
#define KACS_IPC_SD_SET 4U /* kacs_set_sd on the object */
#define KACS_IPC_NO_SD 5U /* object carries no SD; fail closed */

/*
 * kacs_namespace stage — which sub-decision of a namespace-mutation hook a
 * record describes. Single-decision ops report PRIMARY; multi-stage ops (link,
 * rename, delete fallback) tag each distinct verdict. Verdict is the `ret`
 * field. Never records a pathname. Emitted by the kacs:kacs_inode_* events.
 */
#define KACS_NS_PRIMARY 0U /* the op's principal decision */
#define KACS_NS_PARENT_FALLBACK 1U /* delete: parent DELETE_CHILD fallback */
#define KACS_NS_SOURCE 2U /* link/rename source-side decision */
#define KACS_NS_DEST 3U /* link/rename destination-parent add */
#define KACS_NS_DELETE_EXISTING 4U /* rename: delete pre-existing dest */

/*
 * kacs_psb reason — which process-security-baseline path an event marks:
 * mitigation activation (apply) or a W^X / LSV / PIE / prctl-lock enforcement
 * denial. The ok-vs-deny verdict is read from `ret`. Emitted by kacs:kacs_psb_*.
 */
#define KACS_PSB_APPLY_OK 0U /* mitigations applied; result_bits set */
#define KACS_PSB_APPLY_NORMALIZE \
	1U /* requested mask bad or unsupported (EINVAL/ENODEV) */
#define KACS_PSB_APPLY_MM_ACQUIRE 2U /* could not acquire target mm (EACCES) */
#define KACS_PSB_APPLY_CFIF 3U /* forward-CFI (IBT) activation failed */
#define KACS_PSB_APPLY_SML \
	4U /* speculative-mitigation-lock activation failed */
#define KACS_PSB_APPLY_CFIB \
	5U /* backward-CFI (shadow stack) activation failed */
#define KACS_PSB_WXP_MMAP 6U /* W^X blocked a W+X mmap */
#define KACS_PSB_WXP_MPROTECT 7U /* W^X blocked an mprotect transition */
#define KACS_PSB_WXP_EXISTING_VMA \
	8U /* W^X activation blocked by an existing W+X vma */
#define KACS_PSB_LSV_PROBE 9U /* LSV signing probe of the image failed */
#define KACS_PSB_LSV_VERIFY 10U /* LSV signature not verified/trusted */
#define KACS_PSB_LSV_PIP_DOMINANCE \
	11U /* LSV image PIP does not dominate process PIP */
#define KACS_PSB_PIE_ET_EXEC 12U /* PIE blocked a non-PIE ET_EXEC image */
#define KACS_PSB_PRCTL_SML 13U /* prctl blocked by SML lock */
#define KACS_PSB_PRCTL_CFIB 14U /* prctl blocked by shadow-stack (CFIB) lock */
#define KACS_PSB_PRCTL_PIP 15U /* prctl set-dumpable blocked by process PIP */

/* ==== KMES trace system (kmes:) — event-substrate machinery health ==== */

/*
 * kmes_drop reason — why the KMES ring machinery lost an event. RING_FULL is a
 * normal overwrite; TAIL_RESYNC is the silent corruption-recovery path that
 * discards ALL pending events; VALIDATE is a kernel-emit size/type reject at the
 * ring boundary; BATCH_STRUCT_INVALID is a per-entry structural reject in the
 * kernel batch path. Emitted by kmes:kmes_drop. No event payload bytes.
 */
#define KMES_DROP_RING_FULL 0U /* capacity overwrite; oldest event dropped */
#define KMES_DROP_TAIL_RESYNC \
	1U /* corrupt ring header; pending events silently discarded */
#define KMES_DROP_VALIDATE 2U /* single kernel-emit size/type reject */
#define KMES_DROP_BATCH_STRUCT_INVALID \
	3U /* kernel-batch entry structurally invalid */

/*
 * kmes_swap reason — a bounded ring capacity swap lifecycle marker. BEGIN and
 * COMPLETE/FAILED are whole-topology (cpu field is U16_MAX); MIGRATE_SKIP is
 * per-CPU and carries the skipped byte count in `ret`. Emitted by kmes:kmes_swap.
 */
#define KMES_SWAP_BEGIN 0U /* capacity change accepted, rings allocating */
#define KMES_SWAP_COMPLETE 1U /* swap committed across all CPUs */
#define KMES_SWAP_MIGRATE_SKIP \
	2U /* shrink: old event too large, skipped (ret=bytes) */
#define KMES_SWAP_FAILED 3U /* swap aborted; ret is the errno */

/*
 * kmes_rate reason — the per-process token-bucket backpressure signal. THROTTLE
 * is an -EAGAIN emit rejection; RECONFIGURE marks an admin rate change clamping
 * all buckets. Emitted by kmes:kmes_rate.
 */
#define KMES_RATE_THROTTLE 0U /* emit denied -EAGAIN; tokens < requested */
#define KMES_RATE_RECONFIGURE \
	1U /* max emit rate reconfigured for all buckets */

/*
 * kmes_wake reason — consumer wakeup machinery. NOTE arms a pending wake; FUTEX
 * is the actual futex wake of blocked consumers. Emitted by kmes:kmes_wake.
 */
#define KMES_WAKE_NOTE 0U /* wake armed; futex counter incremented */
#define KMES_WAKE_FUTEX 1U /* blocked consumers woken */

/*
 * kmes_ring_lifecycle reason — a generation-stable ring object transition.
 * `ret` is the outcome. Emitted by kmes:kmes_ring_lifecycle.
 */
#define KMES_RING_ALLOC 0U /* ring backing allocated (or -ENOMEM) */
#define KMES_RING_FREE 1U /* ring backing released */
#define KMES_RING_PRODUCER_PAGE 2U /* producer shmem/meta page attached */
#define KMES_RING_CONSUMER_FD 3U /* consumer anon-inode fd created */

/*
 * kmes_ingress_reject reason — why an emit request was rejected before the ring.
 * OVER_MAX/OVER_CAP_HALF/SIZE_OVERFLOW are declared-size rejects; EMIT_OVERSIZE
 * is a staged event too large at ring-write time; BATCH_PARTIAL marks a batch
 * that validated fewer entries than requested. Emitted by kmes:kmes_ingress_reject.
 */
#define KMES_INGRESS_OVER_MAX \
	0U /* event_size exceeds configured max_event_size */
#define KMES_INGRESS_OVER_CAP_HALF 1U /* event_size exceeds ring_capacity/2 */
#define KMES_INGRESS_SIZE_OVERFLOW 2U /* declared header/event size overflow */
#define KMES_INGRESS_EMIT_OVERSIZE \
	3U /* staged event exceeds live capacity/2 at emit */
#define KMES_INGRESS_BATCH_PARTIAL \
	4U /* batch staged fewer entries than requested */

/*
 * kmes_validate reason — the C-boundary result of the Rust staged-event
 * validator. The Rust side collapses its structural checks into one nonzero
 * return; only visible type/payload lengths and `ret` are recorded here.
 * Emitted by kmes:kmes_validate.
 */
#define KMES_VAL_EINVAL 0U /* Rust msgpack/structural validation rejected */

/* ==== LCS trace system (lcs:) — registry source RSI path ==== */

/*
 * lcs_rsi_request op — which of the 18 RSI dispatch verbs a source-side request
 * admission record describes. Emitted by lcs:lcs_rsi_request on successful queue
 * admission and on the admission error rungs; the rung is read from `ret`
 * (0 == enqueued, -EAGAIN == in-flight at limit / backpressure, -EIO == source
 * gone / fd closing, -EOVERFLOW == request-id space exhausted, other == build
 * reject). The same op enum tags the round-trip begin marker (lcs_rsi_roundtrip).
 * Never records a pathname, key name, GUID, or frame bytes — only this op code,
 * ids, counts and ret.
 */
#define LCS_OP_LOOKUP 0U /* RSI_LOOKUP */
#define LCS_OP_READ_KEY 1U /* RSI_READ_KEY */
#define LCS_OP_ENUM_CHILDREN 2U /* RSI_ENUM_CHILDREN */
#define LCS_OP_QUERY_VALUES 3U /* RSI_QUERY_VALUES */
#define LCS_OP_SET_VALUE 4U /* RSI_SET_VALUE */
#define LCS_OP_DELETE_VALUE 5U /* RSI_DELETE_VALUE_ENTRY */
#define LCS_OP_BLANKET_TOMBSTONE 6U /* RSI_SET_BLANKET_TOMBSTONE */
#define LCS_OP_DROP_KEY 7U /* RSI_DROP_KEY */
#define LCS_OP_CREATE_ENTRY 8U /* RSI_CREATE_ENTRY */
#define LCS_OP_HIDE_ENTRY 9U /* RSI_HIDE_ENTRY */
#define LCS_OP_DELETE_ENTRY 10U /* RSI_DELETE_ENTRY */
#define LCS_OP_CREATE_KEY 11U /* RSI_CREATE_KEY */
#define LCS_OP_WRITE_KEY 12U /* RSI_WRITE_KEY */
#define LCS_OP_TXN_BEGIN 13U /* RSI_BEGIN_TRANSACTION */
#define LCS_OP_TXN_COMMIT 14U /* RSI_COMMIT_TRANSACTION */
#define LCS_OP_TXN_ABORT 15U /* RSI_ABORT_TRANSACTION */
#define LCS_OP_FLUSH 16U /* RSI_FLUSH */
#define LCS_OP_DELETE_LAYER 17U /* RSI_DELETE_LAYER */

/*
 * lcs_rsi_response reason — the outcome of accepting/validating a source's RSI
 * response frame, and the late-response effects that silently mark a source
 * DOWN. ACCEPTED is the clean path; DESYNC / OP_MISMATCH / UNKNOWN_STATUS are the
 * accept-time rejects that all surface as -EINVAL/-EIO; MALFORMED_PAYLOAD is a
 * per-op body validation reject; the LATE_* codes mark a response whose deferred
 * effect (commit/mutation/begin bookkeeping) failed and took the source DOWN.
 * Verdict/outcome is also in `ret`. Never records name/GUID/frame bytes.
 */
#define LCS_RESP_ACCEPTED 0U /* response matched an in-flight request */
#define LCS_RESP_DESYNC 1U /* no matching delivered/unaccepted record */
#define LCS_RESP_OP_MISMATCH 2U /* response op != request op | RESPONSE_BIT */
#define LCS_RESP_UNKNOWN_STATUS 3U /* rsi_status not a known status code */
#define LCS_RESP_MALFORMED_PAYLOAD \
	4U /* per-op response body failed validation */
#define LCS_RESP_LATE_COMMIT_FAIL \
	5U /* commit late-effect failed; source DOWN */
#define LCS_RESP_LATE_MUTATION_FAIL \
	6U /* mutation late-effect failed; source DOWN */
#define LCS_RESP_LATE_BEGIN_FAIL \
	7U /* begin-txn late-effect failed; source DOWN */

/*
 * lcs_source_fd reason — which source-fd lifecycle transition a record marks.
 * OPEN is a fresh /dev/pkm_registry fd; the remaining codes are the entry points
 * that drive a source to the DOWN/closing state. `source_down_id` is the source
 * id that transitioned DOWN (0 if the call was a no-op). The semantic *cause* of
 * a late-effect-driven DOWN is carried by lcs_rsi_response (LCS_RESP_LATE_*);
 * here EXPLICIT/MARK_BY_ID are the mechanical transitions. No pathname/SD bytes.
 */
#define LCS_SRC_OPEN 0U /* new source fd issued (post-TCB check) */
#define LCS_SRC_RELEASE 1U /* fd .release() teardown */
#define LCS_SRC_MALFORMED 2U /* malformed protocol frame -> mark down */
#define LCS_SRC_EXPLICIT 3U /* explicit mark-down of this fd */
#define LCS_SRC_MARK_BY_ID 4U /* mark-down requested by source id */

/*
 * lcs_in_flight reason — an in-flight RSI request table transition (kept lean;
 * insert on admission, delivered when handed to the source's read(), release on
 * response completion or teardown). `in_flight_count` is the post-transition
 * depth. Emitted by lcs:lcs_in_flight.
 */
#define LCS_IF_INSERT 0U /* request inserted into in-flight table */
#define LCS_IF_DELIVERED 1U /* request delivered to source read() */
#define LCS_IF_RELEASE 2U /* request released from in-flight table */

/* lcs_route op — which resolution the lcs:lcs_route event describes. */
#define LCS_ROUTE_HIVE_NAME 0U /* hive-name -> source/root resolution */
#define LCS_ROUTE_ABSOLUTE_PATH 1U /* absolute-path -> source/root resolution */
#define LCS_ROUTE_SYMLINK_TARGET \
	2U /* symlink-target -> source/root resolution */

/*
 * lcs_registration decision — the source registration path. NEW/RESUME_DOWN are
 * publish verdicts; COPY is the input-copy stage; REPLAY_FAIL/OVERFLOW_FAIL are
 * resume post-publish -EIO paths that mark the resumed source down. Emitted by
 * lcs:lcs_source_register / _registration_publish / _registration_copy.
 */
#define LCS_REG_NEW 0U /* new source slot admitted */
#define LCS_REG_RESUME_DOWN 1U /* down source slot resumed */
#define LCS_REG_COPY 2U /* registration input copied from user */
#define LCS_REG_REPLAY_FAIL 3U /* resume pending-delete replay failed (EIO) */
#define LCS_REG_OVERFLOW_FAIL 4U /* resume overflow dispatch failed (EIO) */

/*
 * lcs_bootstrap stage — the phase of a bootstrap / self-config refresh. Emitted
 * by lcs:lcs_bootstrap_refresh / _self_config_refresh / _self_config_publish.
 */
#define LCS_BOOT_REGISTRY 0U /* registry root discover phase */
#define LCS_BOOT_KMES 1U /* kmes config root discover phase */
#define LCS_BOOT_LAYERS 2U /* layer metadata root discover phase */
#define LCS_BOOT_SELF_WATCH 3U /* self-watch arm phase */
#define LCS_BOOT_COMPLETE 4U /* bootstrap refresh completed */
#define LCS_BOOT_SELF_CONFIG_REFRESH \
	5U /* self-config refresh-from-key outcome */
#define LCS_BOOT_SELF_CONFIG_PARAM_INVALID \
	6U /* self-config publish rejected a parameter */

/*
 * lcs_runtime_limits field_id — which runtime-limit field a validate reject
 * names, or LCS_LIM_ALL for a successful whole-struct publish. Emitted by
 * lcs:lcs_limits_validate (-EINVAL, `value` offending) and lcs:lcs_limits_publish.
 */
#define LCS_LIM_REQUEST_TIMEOUT_MS 0U
#define LCS_LIM_TRANSACTION_TIMEOUT_MS 1U
#define LCS_LIM_NOTIFICATION_QUEUE_SIZE 2U
#define LCS_LIM_SYMLINK_DEPTH_LIMIT 3U
#define LCS_LIM_MAX_VALUE_SIZE 4U
#define LCS_LIM_MAX_KEY_DEPTH 5U
#define LCS_LIM_MAX_PATH_COMPONENT_LENGTH 6U
#define LCS_LIM_MAX_TOTAL_PATH_LENGTH 7U
#define LCS_LIM_MAX_LAYERS_PER_VALUE 8U
#define LCS_LIM_MAX_BOUND_TRANSACTIONS_PER_SOURCE 9U
#define LCS_LIM_MAX_READ_ONLY_TRANSACTIONS_PER_SOURCE 10U
#define LCS_LIM_MAX_TOTAL_LAYERS 11U
#define LCS_LIM_MAX_REGISTERED_SOURCES 12U
#define LCS_LIM_MAX_HIVES_PER_SOURCE 13U
#define LCS_LIM_MAX_CONCURRENT_RSI_REQUESTS 14U
#define LCS_LIM_MAX_SCOPE_GUIDS_PER_TOKEN 15U
#define LCS_LIM_MAX_PRIVATE_LAYERS_PER_TOKEN 16U
#define LCS_LIM_MAX_SUBTREE_WATCH_DEPTH 17U
#define LCS_LIM_MAX_TRANSACTION_WATCH_EVENT_BURST 18U
#define LCS_LIM_ALL 19U /* whole-struct publish (success) */

/*
 * lcs_audit event_type_id — which LCS audit event a record describes. Emitted by
 * lcs:lcs_audit_emit and lcs:lcs_audit_emit_failed. `result_errno` carries the
 * op-specific numeric. No SD or raw GUID bytes; key GUID is a u64 hash.
 */
#define LCS_AUDIT_KEY_OPEN 0U /* key-open SACL audit */
#define LCS_AUDIT_BACKUP_START 1U
#define LCS_AUDIT_BACKUP_COMPLETE 2U
#define LCS_AUDIT_RESTORE_START 3U
#define LCS_AUDIT_RESTORE_COMPLETE 4U
#define LCS_AUDIT_VALIDATION_FAILURE 5U /* source validation-failure audit */
#define LCS_AUDIT_SELF_CONFIG_INVALID 6U /* self-config-invalid audit */

/*
 * lcs_txn state — the transaction-fd state machine state carried in old_state /
 * new_state. Emitted by lcs:lcs_txn_begin / _first_bind / _bind_mutation /
 * _commit / _abort / _timeout / _source_down.
 */
#define LCS_TXN_ST_ACTIVE_UNBOUND 0U /* allocated, not yet source-bound */
#define LCS_TXN_ST_ACTIVE_BOUND 1U /* bound to a source + root guid */
#define LCS_TXN_ST_COMMITTED 2U /* commit round-trip succeeded */
#define LCS_TXN_ST_ABORTED 3U /* aborted (close / layer writer abort) */
#define LCS_TXN_ST_TIMED_OUT 4U /* deadline timer or commit timeout */
#define LCS_TXN_ST_SOURCE_DOWN 5U /* bound source marked down */

/*
 * lcs_key_fd cmd — the key-fd ioctl verb (also stamped on lcs_key_mutation).
 * LCS_KCMD_NONE is used by publish/release/read. Never records key/name/SD bytes.
 * Emitted by lcs:lcs_key_ioctl / _mutation.
 */
#define LCS_KCMD_NONE 0U /* no ioctl verb (publish/release/read) */
#define LCS_KCMD_SET_VALUE 1U
#define LCS_KCMD_DELETE_VALUE 2U
#define LCS_KCMD_BLANKET_TOMBSTONE 3U
#define LCS_KCMD_DELETE_KEY 4U
#define LCS_KCMD_HIDE_KEY 5U
#define LCS_KCMD_QUERY_VALUE 6U
#define LCS_KCMD_QUERY_VALUES_BATCH 7U
#define LCS_KCMD_ENUM_VALUES 8U
#define LCS_KCMD_ENUM_SUBKEYS 9U
#define LCS_KCMD_QUERY_KEY_INFO 10U
#define LCS_KCMD_GET_SECURITY 11U
#define LCS_KCMD_SET_SECURITY 12U
#define LCS_KCMD_FLUSH 13U
#define LCS_KCMD_BACKUP 14U
#define LCS_KCMD_RESTORE 15U
#define LCS_KCMD_NOTIFY 16U

/* ==== KACS token / session diagnostic codes (kacs:) ==== */

/*
 * kacs_token_ioctl cmd — which token-fd ioctl verb a record describes. The
 * verdict (allow vs deny) is read from the `ret` field (0 == allow); the
 * access-mask-gate rejections surface as ret == -EACCES. `token` is an opaque
 * numeric id (never token bytes). Emitted by kacs:kacs_token_ioctl.
 */
#define KACS_TOK_QUERY 0U /* KACS_IOC_QUERY */
#define KACS_TOK_ADJUST_PRIVS 1U /* KACS_IOC_ADJUST_PRIVS */
#define KACS_TOK_ADJUST_GROUPS 2U /* KACS_IOC_ADJUST_GROUPS */
#define KACS_TOK_DUPLICATE 3U /* KACS_IOC_DUPLICATE */
#define KACS_TOK_INSTALL 4U /* KACS_IOC_INSTALL */
#define KACS_TOK_RESTRICT 5U /* KACS_IOC_RESTRICT */
#define KACS_TOK_LINK 6U /* KACS_IOC_LINK_TOKENS */
#define KACS_TOK_GET_LINKED 7U /* KACS_IOC_GET_LINKED_TOKEN */
#define KACS_TOK_IMPERSONATE 8U /* KACS_IOC_IMPERSONATE */
#define KACS_TOK_ADJUST_DEFAULT 9U /* KACS_IOC_ADJUST_DEFAULT */
#define KACS_TOK_ADJUST_INTERACTIVITY_SCOPE \
	10U /* KACS_IOC_ADJUST_INTERACTIVITY_SCOPE */
#define KACS_TOK_UNKNOWN 11U /* unrecognised ioctl verb (-ENOTTY) */

/*
 * kacs_token_ref reason — a token-fd reference lifecycle transition. TO_FD is a
 * token installed into a fresh anon-inode handle; RELEASE is the handle
 * teardown that drops the token ref; BIND clones a token onto an existing file;
 * OPEN is the checked/fixed-access open path that clones the target token.
 * `token` is an opaque numeric id, never token bytes. Emitted by kacs:kacs_token_ref.
 */
#define KACS_TREF_TO_FD 0U /* token installed into a new fd (ret == fd) */
#define KACS_TREF_RELEASE 1U /* token-fd released; ref dropped */
#define KACS_TREF_BIND 2U /* token cloned + bound onto an existing file */
#define KACS_TREF_OPEN 3U /* token cloned for a token-open path */

/*
 * kacs_logon_session reason — a session/token creation-surface outcome. The *_DENIED
 * codes name the privilege-gate rejections (the value); the plain op codes mark
 * the successful op. Verdict is also in `ret`. No token/spec bytes are recorded.
 * Emitted by kacs:kacs_logon_session.
 */
#define KACS_SES_CREATE 0U /* create_logon_session published a session */
#define KACS_SES_CREATE_PRIV_DENIED \
	1U /* create_logon_session: TCB privilege gate denied */
#define KACS_SES_DESTROY 2U /* destroy_empty_logon_session outcome */
#define KACS_SES_DESTROY_PRIV_DENIED 3U /* destroy: TCB privilege gate denied */
#define KACS_SES_CREATE_TOKEN 4U /* create_token issued a token fd */
#define KACS_SES_CREATE_TOKEN_PRIV_DENIED \
	5U /* create_token: CREATE_TOKEN privilege denied */
/*
 * ==== KACS credential / setid / task lifecycle codes (kacs:) ====
 *
 * Never carries token/SD bytes: token/process_state fields are opaque pointer
 * ids (or 0), the rest are enums/flags/ret.
 */

/*
 * kacs_cred reason — a credential-security lifecycle transition: LSM cred
 * prepare/transfer/alloc/free, explicit token-ref install, the clone-time
 * primary-token lifecycle (CLONE_THREAD share vs fork deep-copy), and the
 * project-linux-cred rejection paths. old_token/new_token are opaque token
 * pointer ids (0 when absent); clone_flags is set only on the clone paths.
 * Verdict/outcome is the `ret` field. Emitted by kacs:kacs_cred.
 */
#define KACS_CRED_PREPARE 0U /* cred_prepare token clone */
#define KACS_CRED_TRANSFER 1U /* cred_transfer token clone */
#define KACS_CRED_ALLOC_BLANK 2U /* cred_alloc_blank cleared sec */
#define KACS_CRED_FREE 3U /* cred_free released token/state */
#define KACS_CRED_INSTALL_TOKEN_REF 4U /* install token ref on a cred */
#define KACS_CRED_CLONE_THREAD_SHARE \
	5U /* CLONE_THREAD shares parent primary cred */
#define KACS_CRED_CLONE_FORK_COPY 6U /* fork deep-copies parent primary token */
#define KACS_CRED_PROJECT_UID0_BLOCKED \
	7U /* uid0 projection not allowed by token */
#define KACS_CRED_PROJECT_GROUPS_ALLOC_FAIL \
	8U /* groups_alloc failed (ENOMEM) */
#define KACS_CRED_PROJECT_E2BIG 9U /* supplementary gid count > NGROUPS_MAX */

/*
 * kacs_setid reason — the KACS gate on a Linux setid projection
 * (task_fix_setuid / _setgid / _setgroups). Each op has two distinct denials
 * that otherwise collapse: NO_TOKEN (-EACCES, no effective subject token) and
 * PRIV_GATE (-EOPNOTSUPP, holder of ASSIGN_PRIMARY_TOKEN privilege). `flags` is
 * the LSM_SETID_* mask (0 for setgroups). Emitted by kacs:kacs_setid.
 */
#define KACS_SETID_SETUID_NO_TOKEN 0U /* setuid gate: no subject token */
#define KACS_SETID_SETUID_PRIV_GATE 1U /* setuid gate: ASSIGN_PRIMARY priv */
#define KACS_SETID_SETGID_NO_TOKEN 2U /* setgid gate: no subject token */
#define KACS_SETID_SETGID_PRIV_GATE 3U /* setgid gate: ASSIGN_PRIMARY priv */
#define KACS_SETID_SETGROUPS_NO_TOKEN 4U /* setgroups gate: no subject token */
#define KACS_SETID_SETGROUPS_PRIV_GATE \
	5U /* setgroups gate: ASSIGN_PRIMARY priv */

/*
 * kacs_task reason — a task-security lifecycle transition. task_alloc reports a
 * NO_CHILD-mitigation clone block, a process-state inherit ENOMEM, or success;
 * task_free marks teardown. `process_state` is an opaque process-state pointer
 * id (0 when absent); `clone_flags` is set on the alloc paths. Outcome is `ret`.
 * Emitted by kacs:kacs_task.
 */
#define KACS_TASK_ALLOC_NO_CHILD_BLOCKED \
	0U /* clone blocked by NO_CHILD mitigation */
#define KACS_TASK_ALLOC_INHERIT_ENOMEM \
	1U /* process-state inherit failed (ENOMEM) */
#define KACS_TASK_ALLOC 2U /* task_alloc completed */
#define KACS_TASK_FREE 3U /* task_free teardown */

/*
 * kacs_primary_install reason — a primary-token / impersonation credential
 * transition. Distinguishes the install commit, the user-SID-change process-SD
 * reallocation and its ENOMEM, the commit_creds apply, the impersonation
 * override/revert, and the sibling-thread taskwork requeue/failure. old_primary
 * and new_primary are opaque token identity ids (never token bytes). Verdict is
 * the `ret` field. Emitted by kacs:kacs_primary_install.
 */
#define KACS_PRIM_INSTALL_OK 0U /* primary token install committed */
#define KACS_PRIM_SD_REALLOC 1U /* user-SID changed; process SD reallocated */
#define KACS_PRIM_SD_ALLOC_FAIL 2U /* process SD realloc failed (ENOMEM) */
#define KACS_PRIM_APPLY_COMMIT 3U /* new real creds committed (commit_creds) */
#define KACS_PRIM_IMPERSONATE_INSTALL \
	4U /* impersonation token installed (override_creds) */
#define KACS_PRIM_IMPERSONATE_REVERT \
	5U /* impersonation reverted (revert_creds) */
#define KACS_PRIM_SIBLING_REQUEUE \
	6U /* queued sibling install re-queued on ENOMEM */
#define KACS_PRIM_SIBLING_FAILED \
	7U /* queued sibling install failed after apply */

/*
 * kacs_process_token_open reason — the outcome of opening a process/thread
 * primary or effective token (kacs_open_process_token / _thread_token and the
 * proc inspection files). Distinguishes the bad access-mask reject, the
 * no-target-token path, the process access-check denial, the self vs cross
 * inspection verdicts, and the successful open. subject_token/target_token are
 * opaque token identity ids (0 when unknown at the emit site); access_mask is
 * the requested mask. Verdict is `ret` (>=0 fd == allow). Emitted by
 * kacs:kacs_process_token_open.
 */
#define KACS_PTO_OPEN_OK 0U /* token fd opened */
#define KACS_PTO_BAD_ARGS 1U /* NULL subject/state/task guard */
#define KACS_PTO_NO_TARGET 2U /* target has no token */
#define KACS_PTO_BAD_ACCESS 3U /* invalid access mask rejected */
#define KACS_PTO_ACCESS_DENIED 4U /* process access check denied */
#define KACS_PTO_SELF 5U /* self-target inspection allowed */
#define KACS_PTO_CROSS 6U /* cross-process inspection authorized */

/*
 * kacs_process_state reason — a process-state / process-SD lifecycle or PIP
 * transition. Covers process-state alloc/free, the CLONE_THREAD share vs fork
 * inheritance split, the no-child clone block, the pending-exec-PIP stage/commit
 * and dumpable hardening, and the process-SD alloc/wrap/replace primitives.
 * process_state is an opaque state-object id (0 when none in scope, e.g. the
 * process-SD primitives); pip_type/pip_trust carry the PIP tier. `ret` is the
 * outcome (0 == ok). No token or SD bytes. Emitted by kacs:kacs_process_state.
 */
#define KACS_PST_ALLOC 0U /* process state allocated */
#define KACS_PST_ALLOC_FAIL 1U /* process state alloc failed (ENOMEM) */
#define KACS_PST_FREE 2U /* process state freed (refcount hit 0) */
#define KACS_PST_INHERIT_SHARE 3U /* CLONE_THREAD: parent state shared */
#define KACS_PST_INHERIT_FORK 4U /* fork: new state allocated from parent */
#define KACS_PST_EXEC_PIP_STAGE 5U /* pending exec PIP staged */
#define KACS_PST_EXEC_PIP_COMMIT 6U /* pending exec PIP committed to state */
#define KACS_PST_DUMPABLE 7U /* exec dumpable hardened by PIP */
#define KACS_PST_CLONE_BLOCKED_NOCHILD \
	8U /* clone blocked by NO_CHILD mitigation */
#define KACS_PST_SD_ALLOC 9U /* default process SD allocated */
#define KACS_PST_SD_ALLOC_FAIL 10U /* process/socket SD alloc failed */
#define KACS_PST_SD_WRAP_FAIL 11U /* process SD wrapper alloc failed (ENOMEM) */
#define KACS_PST_SD_REPLACE 12U /* process SD replaced on state */
#define KACS_PST_SOCKET_SD_ALLOC 13U /* default socket SD allocated */

/*
 * ==== KACS mount-policy / SD-syscall / AccessCheck ingress codes (kacs:) ====
 *
 * These records never carry SD bytes, token bytes, or pathnames — only
 * security_info, access masks, a target-kind enum, sd_len, sb_magic, policy
 * values, generations, reason, and ret.
 */

/*
 * kacs_mount_policy reason — the outcome of a mount-policy set (TCB-gated) or
 * get. SET_OK marks a committed policy change (generation bumped); the guard
 * codes name the pre-commit rejects that otherwise collapse into a bare
 * -EINVAL/-EOPNOTSUPP/-EPERM. GET_OK/GET_NO_SECURITY are the snapshot paths.
 * Verdict is also in `ret`. Emitted by kacs:kacs_mount_policy_set / _get.
 */
#define KACS_MP_SET_OK 0U /* policy committed; generation bumped */
#define KACS_MP_BAD_ARGS 1U /* NULL subject/sb/args guard (EINVAL) */
#define KACS_MP_NO_SECURITY 2U /* superblock has no s_security (EOPNOTSUPP) */
#define KACS_MP_UNMANAGED \
	3U /* magic-derived UNMANAGED; not settable (EOPNOTSUPP) */
#define KACS_MP_VALIDATE 4U /* mount-policy args validation failed (EINVAL) */
#define KACS_MP_TEMPLATE_INVALID \
	5U /* template SD bytes failed validation (EINVAL) */
#define KACS_MP_TCB_DENIED 6U /* SeTcbPrivilege gate denied (EPERM) */
#define KACS_MP_GET_OK 7U /* policy snapshot returned */
#define KACS_MP_GET_NO_SECURITY \
	8U /* get: no s_security; magic-derived policy returned */
#define KACS_MP_FIXED_POLICY \
	9U /* filesystem fixes its policy class (EOPNOTSUPP) */

/*
 * kacs_sd_syscall target_kind — which SD-bearing object a query/set record
 * describes, resolved by the get_sd/set_sd syscall target-kind fallthrough.
 * ACCESS_CHECK tags the AccessCheck ingress events (kacs_access_check*), whose
 * other scalar fields are 0 at the ingress boundary.
 */
#define KACS_SDS_KIND_TOKEN 0U /* token-fd target */
#define KACS_SDS_KIND_FILE 1U /* file/inode target */
#define KACS_SDS_KIND_PROCESS 2U /* pidfd process target */
#define KACS_SDS_KIND_PATH 3U /* path-resolved file target */
#define KACS_SDS_KIND_ACCESS_CHECK \
	4U /* AccessCheck ingress (not an SD get/set) */

/*
 * kacs_sd_syscall reason — the outcome of an SD query/set core. QUERY_OK/SET_OK
 * are the success paths; the remaining codes name the guard / denial paths that
 * otherwise surface as an indistinguishable -EINVAL/-EACCES/-EOPNOTSUPP.
 * Verdict is also in `ret`. Emitted by kacs:kacs_sd_query / _set.
 */
#define KACS_SDS_QUERY_OK 0U /* SD subset extracted and returned */
#define KACS_SDS_SET_OK 1U /* SD merged/replaced */
#define KACS_SDS_BAD_ARGS 2U /* NULL/zero argument guard (EINVAL) */
#define KACS_SDS_UNMANAGED 3U /* superblock UNMANAGED (EOPNOTSUPP) */
#define KACS_SDS_ACCESS_DENIED 4U /* SD access check denied (EACCES) */
#define KACS_SDS_NO_SD 5U /* target has no usable SD (EACCES) */
#define KACS_SDS_RESTORE_BYPASS 6U /* set via SeRestorePrivilege bypass */
#define KACS_SDS_QUERY_FAIL 7U /* subset extraction failed after auth */

/*
 * kacs_access_check reason — the AccessCheck kernel-ingress outcome, above the
 * closed Slice 15 ABI bridge. OK is a completed ingress; the remaining codes
 * name the ingress-time rejects (token-eval-context gate, token resolution, and
 * caap-cache lock acquisition). Verdict is also in `ret`. Emitted by
 * kacs:kacs_access_check / _list.
 */
#define KACS_ACK_OK 0U /* ingress dispatched to the ABI bridge */
#define KACS_ACK_EVAL_CONTEXT 1U /* token-eval-context gate denied (EACCES) */
#define KACS_ACK_TOKEN_RESOLVE 2U /* token/args resolution failed */
#define KACS_ACK_CAAP_LOCK_FAIL 3U /* caap-cache lock acquisition failed */

/*
 * ==== KACS file-metadata / file-snapshot / native-open codes (kacs:) ====
 *
 * No pathname / SD bytes are ever carried by the events these annotate — only
 * ino, sb_magic, access masks, op/reason enums, and ret.
 */

/*
 * kacs_file_snapshot op — which snapshot-grant file operation an event marks.
 * The allow-vs-deny verdict is read from `ret`; `reason` names why a deny path
 * was taken. Emitted by kacs:kacs_file_snapshot (file_access.c).
 */
#define KACS_FSOP_ACCESS 0U /* generic snapshot-grant access check */
#define KACS_FSOP_PERMISSION 1U /* file_permission hook */
#define KACS_FSOP_IOCTL 2U /* file ioctl snapshot */
#define KACS_FSOP_LOCK 3U /* file lock snapshot */
#define KACS_FSOP_FCNTL 4U /* file fcntl snapshot */
#define KACS_FSOP_TRUNCATE 5U /* file truncate snapshot */
#define KACS_FSOP_FALLOCATE 6U /* file fallocate snapshot */
#define KACS_FSOP_MMAP 7U /* file mmap snapshot */
#define KACS_FSOP_MPROTECT 8U /* file mprotect snapshot */
#define KACS_FSOP_WRITE_INTENT 9U /* write-intent snapshot */
#define KACS_FSOP_SYSFS_WRITE_GATE 10U /* unmanaged sysfs write gate */

/*
 * kacs_file_snapshot reason — why a snapshot-grant op took its return path.
 * DECISION is the resolved allow/deny (verdict in `ret`); the remaining codes
 * name the distinct deny causes. Emitted by kacs:kacs_file_snapshot.
 */
#define KACS_FSR_DECISION 0U /* resolved allow/deny (grant compare) */
#define KACS_FSR_SIGNED_EXEC 1U /* signed-exec content mutation denied */
#define KACS_FSR_GRANT_DENY 2U /* granted access lacked required right */
#define KACS_FSR_APPEND_DENY 3U /* append/write intent lacked write grant */
#define KACS_FSR_UNMANAGED_SYSFS 4U /* unmanaged fd: sysfs write gate applied */
#define KACS_FSR_AUDIT_EMIT_FAIL 5U /* kacs.audit.handle.used emit failed */

/*
 * kacs_metadata reason — the file-metadata (getattr/setattr/xattr/getsecurity)
 * decision path. DECISION/CONSUME_HIT/BEGIN_BUSY mark the begin/consume decision
 * lifecycle; the remaining codes name the distinct deny reasons of the xattr /
 * setattr hooks. `op_class` carries the internal PKM_KACS_METADATA_OP_* value;
 * `matched` is the consume match flag. Emitted by kacs:kacs_metadata
 * (file_metadata.c).
 */
#define KACS_META_DECISION 0U /* generic metadata decision */
#define KACS_META_CONSUME_HIT 1U /* consumed a pre-staged decision */
#define KACS_META_BEGIN_BUSY 2U /* begin failed: a decision already active */
#define KACS_META_CANONICAL_SD 3U /* canonical SD xattr access denied */
#define KACS_META_CAPS_XATTR 4U /* capability xattr mutation denied (EPERM) */
#define KACS_META_ACL 5U /* POSIX ACL xattr denied */
#define KACS_META_SIGNED_EXEC 6U /* signed-exec xattr/size mutation denied */
#define KACS_META_BAD_ARGS 7U /* NULL name / dentry guard */
#define KACS_META_INTERNAL_SD 8U /* internal SD read/write re-entry allowed */
#define KACS_META_GETSECURITY 9U /* inode_getsecurity outcome */

/*
 * kacs_native_open_ext reason — a widening decision inside the native
 * (kacs_open) create/open machinery. The PREPARE_* codes name the arg-validation
 * reject buckets of pkm_kacs_prepare_native_open; RESOLVE / BUILD_CREATED_SD /
 * DELETE_ON_CLOSE_ARM name the later stage outcomes (verdict in `ret`). Emitted
 * by kacs:kacs_native_open_ext (native_open.c).
 */
#define KACS_NOX_PREPARE_OK 0U /* prepare accepted the request */
#define KACS_NOX_PREPARE_BAD_FLAGS 1U /* flags/create_options/__pad rejected */
#define KACS_NOX_PREPARE_BAD_SD_ARGS \
	2U /* sd_ptr/sd_len/disposition-sd combo bad */
#define KACS_NOX_PREPARE_BAD_DISPOSITION \
	3U /* create_disposition out of range */
#define KACS_NOX_PREPARE_BAD_ACCESS 4U /* desired-access mask invalid/empty */
#define KACS_NOX_PREPARE_UNSUPPORTED 5U /* valid but unsupported combination */
#define KACS_NOX_RESOLVE 6U /* resolve-existing-path outcome */
#define KACS_NOX_BUILD_CREATED_SD 7U /* build-created-file-SD outcome */
#define KACS_NOX_DELETE_ON_CLOSE_ARM 8U /* delete-on-close arm outcome */

/*
 * ==== KACS object / securityfs / caap / capability / privilege / tlp (kacs:) ====
 *
 * No pathname, prefix, SD, key or token bytes are ever recorded by the events
 * that carry these codes — only lengths, counts, cap numbers, privilege
 * bitmasks, inode numbers, reason codes and ret.
 */

/*
 * kacs_object reason — which object-lifecycle verdict a record marks. Only the
 * high-value transitions are traced (pure inode/file/sb alloc/free are not).
 * `ret` is the outcome (0 == ok). Emitted by kacs:kacs_object.
 */
#define KACS_OBJ_DELETE_ON_CLOSE_UNLINK \
	0U /* file_release delete-on-close unlink attempt */
#define KACS_OBJ_SIGNED_EXEC_PIN \
	1U /* inode pinned as signed-exec (immutable) */
#define KACS_OBJ_SIGNED_EXEC_MUTATION_BLOCKED \
	2U /* content mutation of a signed-exec-pinned inode denied */

/*
 * kacs_securityfs reason — which securityfs endpoint path a record marks. The
 * sessions_read codes disambiguate the deny rungs that otherwise collapse into
 * an errno; open_self / init report the endpoint outcome. Verdict is `ret`.
 * Emitted by kacs:kacs_securityfs.
 */
#define KACS_SFS_LOGON_SESSIONS_NO_TOKEN \
	0U /* sessions read: no effective subject token */
#define KACS_SFS_LOGON_SESSIONS_PIP_CONTEXT \
	1U /* sessions read: caller PIP context unavailable */
#define KACS_SFS_LOGON_SESSIONS_ACCESS_CHECK \
	2U /* sessions read: rust access check denied */
#define KACS_SFS_OPEN_SELF 3U /* open of kacs/self self-token file outcome */
#define KACS_SFS_INIT 4U /* securityfs kacs/ endpoint init outcome */

/*
 * kacs_caap reason — which CAAP policy-cache path a record marks. SET carries
 * the post-set cache_len (an insert grows it; an evict/replace may shrink it);
 * INIT/DESTROY are cache lifecycle; TCB_GATE is the SeTcbPrivilege gate deny.
 * Emitted by kacs:kacs_caap. No SID or spec bytes — lengths only.
 */
#define KACS_CAAP_TCB_GATE 0U /* SeTcbPrivilege gate denied the caller */
#define KACS_CAAP_SET \
	1U /* cache set (insert/evict); cache_len is post-set count */
#define KACS_CAAP_INIT 2U /* CAAP cache created */
#define KACS_CAAP_DESTROY 3U /* CAAP cache destroyed */

/*
 * kacs_capability reason — the capability->privilege gate verdicts and the
 * capability LSM-hook outcomes. ALLOW_GRANT is an auto-granted allow-cap;
 * HARD_DENY is the SETPCAP/SETFCAP/MAC_OVERRIDE hard block; PRIV_NOT_ENABLED /
 * USE_MARK_FAIL are the mapped-privilege gate failures; CAPSET / PRCTL_GUARD /
 * CAPABLE / CAPGET report the corresponding hook outcome. Emitted by
 * kacs:kacs_capability. Verdict is `ret`.
 */
#define KACS_CAP_ALLOW_GRANT \
	0U /* allow-cap auto-granted (no privilege needed) */
#define KACS_CAP_HARD_DENY 1U /* SETPCAP/SETFCAP/MAC_OVERRIDE hard-denied */
#define KACS_CAP_PRIV_NOT_ENABLED 2U /* mapped privilege not enabled on token */
#define KACS_CAP_USE_MARK_FAIL 3U /* privilege use-mark failed */
#define KACS_CAP_CAPSET 4U /* capset core outcome */
#define KACS_CAP_PRCTL_GUARD 5U /* prctl capability-guard outcome */
#define KACS_CAP_CAPABLE 6U /* capable() hook guard-deny outcome */
#define KACS_CAP_CAPGET 7U /* capget for-task outcome */

/*
 * kacs_privilege reason — the require_enabled_privilege gate rungs plus two
 * standalone privilege-path markers. NULL_OR_ZERO is a null-token/zero-mask
 * guard; NOT_ENABLED / USE_MARK_FAIL are the gate failures; CHANGE_NOTIFY marks
 * the open_by_handle_at SeChangeNotifyPrivilege check outcome; RCU_ENOMEM_
 * FALLBACK marks the deferred-free ENOMEM synchronize_rcu fallback. Emitted by
 * kacs:kacs_privilege. Verdict is `ret`.
 */
#define KACS_PRIV_NULL_OR_ZERO 0U /* null token or zero privilege mask */
#define KACS_PRIV_NOT_ENABLED 1U /* privilege not enabled on token */
#define KACS_PRIV_USE_MARK_FAIL 2U /* privilege use-mark failed */
#define KACS_PRIV_CHANGE_NOTIFY \
	3U /* open_by_handle_at CHANGE_NOTIFY gate outcome */
#define KACS_PRIV_RCU_ENOMEM_FALLBACK \
	4U /* deferred-free kmalloc failed; sync-rcu fallback */

/*
 * kacs_tlp reason — the trusted-launch-path decisions. CHECK_PATH marks a
 * no-prefix-match executable-transition deny (path_len + prefix_count only,
 * NEVER path or prefix bytes); REPLACE marks a prefix-table replacement.
 * Emitted by kacs:kacs_tlp. Verdict is `ret`.
 */
#define KACS_TLP_CHECK_PATH \
	0U /* executable transition denied: no prefix match */
#define KACS_TLP_REPLACE 1U /* TLP prefix table replaced */

/*
 * kacs_mntns reason — mount-namespace object lifecycle and the mount gate.
 * SD_ALLOC / SD_ALLOC_FAIL mark a namespace minted with (or without) its
 * creator descriptor; the gate reasons say which rung admitted or refused a
 * mount-table change: PRIVILEGE is SeManageVolume / SeTcb, NO_SD is a
 * namespace with no descriptor (the initial one), OP_NOT_ADMITTED is an
 * operation the descriptor can never grant, SD_DECISION is the access check
 * against the namespace descriptor, PIP_CONTEXT a failure to read the
 * caller's PIP state. Emitted by kacs:kacs_mntns. Verdict is `ret`.
 */
#define KACS_MNTNS_SD_ALLOC 0U /* namespace minted with a creator descriptor */
#define KACS_MNTNS_SD_ALLOC_FAIL 1U /* descriptor could not be built */
#define KACS_MNTNS_GATE_PRIVILEGE 2U /* admitted by SeManageVolume / SeTcb */
#define KACS_MNTNS_GATE_NO_SD 3U /* namespace has no descriptor; refused */
#define KACS_MNTNS_GATE_OP_NOT_ADMITTED \
	4U /* op needs the privilege whatever the SD says */
#define KACS_MNTNS_GATE_SD_DECISION \
	5U /* access check against the namespace SD */
#define KACS_MNTNS_GATE_PIP_CONTEXT 6U /* caller PIP context unavailable */
#define KACS_MNTNS_GATE_FS_NOT_ADMITTED \
	7U /* filesystem type not on the unprivileged allowlist */
#define KACS_MNTNS_SB_STAMP \
	8U /* unprivileged tmpfs stamped synth-ephemeral, creator template */
#define KACS_MNTNS_SB_STAMP_FAIL 9U /* creator template could not be built */
#endif /* _UAPI_PKM_TRACE_H */
