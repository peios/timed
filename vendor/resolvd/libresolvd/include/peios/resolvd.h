/* ABI 1. Inputs are borrowed for each call. All non-null pointers must be
 * aligned, initialized and valid for their lengths. Text is UTF-8 without a
 * terminating NUL. Null/zero denotes absent optional text; non-null/zero is
 * present empty text. Results own all their views until result_free.
 * Handles are library-specific. Mutation/free require exclusive access.
 * Operations are never automatically replayed after uncertain I/O errors.
 * timeout_ms is positive and covers connect, send and receive together.
 * Result errors are POSIX codes; diagnostic wording is not stable. */
#ifndef PEIOS_RESOLVD_H
#define PEIOS_RESOLVD_H
#include "resolvd-types.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct peios_resolvd_result peios_resolvd_result;
uint32_t peios_resolvd_abi_version(void);
void peios_resolvd_result_free(peios_resolvd_result *result);
int32_t peios_resolvd_result_error(const peios_resolvd_result *result);
peios_resolvd_bytes peios_resolvd_result_message(const peios_resolvd_result *result);
const peios_resolvd_answer *peios_resolvd_result_answer(const peios_resolvd_result *result);
const peios_resolvd_addresses *peios_resolvd_result_addresses(const peios_resolvd_result *result);
const peios_resolvd_status_report *
peios_resolvd_result_status_report(const peios_resolvd_result *result);
/* Read the daemon status. */
peios_resolvd_result *peios_resolvd_get_status(peios_resolvd_bytes path, uint64_t timeout_ms);
/* Look up addresses and their provenance. */
peios_resolvd_result *peios_resolvd_lookup(peios_resolvd_bytes path, uint64_t timeout_ms,
                                           peios_resolvd_bytes name, uint32_t family);
/* Resolve a DNS record type. */
peios_resolvd_result *peios_resolvd_resolve(peios_resolvd_bytes path, uint64_t timeout_ms,
                                            peios_resolvd_bytes name, uint16_t record_type,
                                            uint32_t no_cache);
/* Look up the names of an IP address. */
peios_resolvd_result *peios_resolvd_reverse(peios_resolvd_bytes path, uint64_t timeout_ms,
                                            peios_resolvd_bytes address);
/* Flush the cache using the caller's existing control rights. */
peios_resolvd_result *peios_resolvd_flush(peios_resolvd_bytes path, uint64_t timeout_ms);
#ifdef __cplusplus
}
#endif
#endif
