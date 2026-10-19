/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_PKM_IPC_H
#define _UAPI_PKM_IPC_H

#include <linux/types.h>
#include <pkm/sd.h>

/*
 * KACS access rights for System V IPC objects — message queues, shared
 * memory segments and semaphore arrays.
 *
 * Every SysV object carries a security descriptor, created from the
 * creator's token at *get time and enforced through the LSM IPC hooks; the
 * nine-bit ipc_perm mode is never consulted (CAP_IPC_OWNER is in KACS's
 * always-allow set). The key namespace is claim-on-create: the descriptor
 * protects the object, nothing protects the name.
 *
 * Object-specific rights (low 16 bits); the standard rights (DELETE,
 * READ_CONTROL, WRITE_DAC, WRITE_OWNER — <pkm/access.h>) apply as on every
 * KACS object.
 */
#define KACS_IPC_READ \
	0x00000001U /* msgrcv, shmat read-only, semop without alter, GETVAL/GETALL */
#define KACS_IPC_WRITE \
	0x00000002U /* msgsnd, shmat read-write, semop with alter, SETVAL/SETALL */
#define KACS_IPC_QUERY_INFORMATION \
	0x00000004U /* IPC_STAT and the *_STAT variants */
#define KACS_IPC_SET_INFORMATION 0x00000008U /* SHM_LOCK / SHM_UNLOCK */

#define KACS_IPC_ALL_ACCESS                                            \
	(KACS_IPC_READ | KACS_IPC_WRITE | KACS_IPC_QUERY_INFORMATION | \
	 KACS_IPC_SET_INFORMATION | KACS_ACCESS_DELETE |               \
	 KACS_ACCESS_READ_CONTROL | KACS_ACCESS_WRITE_DAC |            \
	 KACS_ACCESS_WRITE_OWNER)

/*
 * ipcctl gates: IPC_RMID needs DELETE; IPC_SET needs WRITE_DAC and
 * WRITE_OWNER (one command carries mode, uid and gid); the mode, uid and gid
 * it writes are informational (ipcs, IPC_STAT) and never decide access.
 *
 * Addressing a SysV object's descriptor with kacs_get_sd / kacs_set_sd:
 * pass one of these in `flags`, the object id in `dirfd`, and a NULL path.
 * The object is looked up in the caller's IPC namespace.
 */
#define KACS_SD_AT_SYSV_SHM 0x01000000U
#define KACS_SD_AT_SYSV_MSG 0x02000000U
#define KACS_SD_AT_SYSV_SEM 0x04000000U
#define KACS_SD_AT_SYSV_MASK \
	(KACS_SD_AT_SYSV_SHM | KACS_SD_AT_SYSV_MSG | KACS_SD_AT_SYSV_SEM)

#endif /* _UAPI_PKM_IPC_H */
