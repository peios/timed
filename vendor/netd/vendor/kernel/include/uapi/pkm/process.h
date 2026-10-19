/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_PKM_PROCESS_H
#define _UAPI_PKM_PROCESS_H

/*
 * KACS process object-specific access rights (the low 16 bits of a process
 * access mask). Named for the Windows process rights; an access check folds
 * the generic bits (<pkm/sd.h>) into these via the process generic mapping.
 */
#define KACS_PROCESS_TERMINATE 0x00000001U
#define KACS_PROCESS_SIGNAL 0x00000002U
#define KACS_PROCESS_VM_READ 0x00000010U
#define KACS_PROCESS_VM_WRITE 0x00000020U
#define KACS_PROCESS_DUP_HANDLE 0x00000040U
#define KACS_PROCESS_SET_INFORMATION 0x00000200U
#define KACS_PROCESS_QUERY_INFORMATION 0x00000400U
#define KACS_PROCESS_SUSPEND_RESUME 0x00000800U
#define KACS_PROCESS_QUERY_LIMITED 0x00001000U

#endif /* _UAPI_PKM_PROCESS_H */
