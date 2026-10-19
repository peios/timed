/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_PKM_PSB_H
#define _UAPI_PKM_PSB_H

#include <linux/types.h>

/*
 * Process Security Block (PSB) process-mitigation bits.
 *
 * The `mitigations` argument of kacs_set_psb (SYS_KACS_SET_PSB) is a bitmask
 * of these flags. Setting a bit is activation-backed: KACS either places the
 * target process in the protected state (or verifies it already satisfies the
 * invariant) before committing, and rejects later operations that would
 * disable the protection. Each mitigation is enforced at its own enforcement
 * point and persists across exec. See Kernel TRM section 3.3 (Process Security Block).
 *
 * Only the bits in KACS_MIT_ALL are valid; any other bit set in the request
 * is rejected. KACS_MIT_CFI is a legacy alias: requesting it sets both
 * KACS_MIT_CFIF and KACS_MIT_CFIB, and the alias bit itself is not retained.
 */
#define KACS_MIT_WXP 0x001U /* Write-XOR-Execute protection */
#define KACS_MIT_TLP 0x002U /* Trusted Library Paths */
#define KACS_MIT_LSV 0x004U /* Library Signature Verification */
#define KACS_MIT_CFI 0x008U /* legacy alias: CFIF | CFIB */
#define KACS_MIT_UI_ACCESS 0x010U /* UI interaction (reserved) */
#define KACS_MIT_NO_CHILD 0x020U /* cannot fork (one-way) */
#define KACS_MIT_CFIF 0x040U /* forward-edge CFI (Intel IBT) */
#define KACS_MIT_CFIB 0x080U /* backward-edge CFI (shadow stack) */
#define KACS_MIT_PIE 0x100U /* reject non-PIE binaries at exec */
#define KACS_MIT_SML 0x200U /* speculation mitigation lock */

/* All valid mitigation bits OR'd together — the accepted-request mask. */
#define KACS_MIT_ALL 0x3FFU

#endif /* _UAPI_PKM_PSB_H */
