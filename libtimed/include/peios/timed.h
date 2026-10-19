/* ABI 1. Inputs are borrowed for each call. All non-null pointers must be
 * aligned, initialized and valid for their lengths. Text is UTF-8 without a
 * terminating NUL. Null/zero denotes absent optional text; non-null/zero is
 * present empty text. Results own all their views until result_free.
 * Handles are library-specific. Mutation/free require exclusive access.
 * Operations are never automatically replayed after uncertain I/O errors.
 * timeout_ms is positive and covers connect, send and receive together.
 * Result errors are POSIX codes; diagnostic wording is not stable. */
#ifndef PEIOS_TIMED_H
#define PEIOS_TIMED_H
#include "timed-types.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct peios_timed_result peios_timed_result;
uint32_t peios_timed_abi_version(void);
void peios_timed_result_free(peios_timed_result *result);
int32_t peios_timed_result_error(const peios_timed_result *result);
peios_timed_bytes peios_timed_result_message(const peios_timed_result *result);
const peios_timed_status *peios_timed_result_status(const peios_timed_result *result);
const peios_timed_snapshot *peios_timed_result_snapshot(const peios_timed_result *result);
const peios_timed_server_spec *peios_timed_result_server_spec(const peios_timed_result *result);
const peios_timed_source_info_list *
peios_timed_result_source_info_list(const peios_timed_result *result);
const peios_timed_listed_list *peios_timed_result_listed_list(const peios_timed_result *result);
/* Read the daemon status. */
peios_timed_result *peios_timed_get_status(peios_timed_bytes path, uint64_t timeout_ms);
/* Read the complete source list. */
peios_timed_result *peios_timed_sources(peios_timed_bytes path, uint64_t timeout_ms);
/* Reload time policy using the caller's existing rights. */
peios_timed_result *peios_timed_reload(peios_timed_bytes path, uint64_t timeout_ms);
/* Set manual time; the daemon enforces authorization and mode. */
peios_timed_result *peios_timed_set(peios_timed_bytes path, uint64_t timeout_ms, int64_t seconds,
                                    uint32_t nanos);
/* Parse a server configuration entry. */
peios_timed_result *peios_timed_parse_server(peios_timed_bytes entry);
/* Check the syntax of a time-zone name. */
peios_timed_result *peios_timed_check_zone(peios_timed_bytes name);
/* Check that a named time zone is installed. */
peios_timed_result *peios_timed_installed_zone(peios_timed_bytes name);
/* List installed time-zone metadata. */
peios_timed_result *peios_timed_zones(void);
const peios_timed_country_list *peios_timed_result_country_list(const peios_timed_result *result);
peios_timed_bytes peios_timed_result_bytes(const peios_timed_result *result);
/* Country names from the installed database. Empty if tzdata is absent. */
peios_timed_result *peios_timed_countries(void);
/* Validated database path; does not check existence. Read result_bytes. */
peios_timed_result *peios_timed_zone_path(peios_timed_bytes name);
/* Subscriptions are exclusively owned. Timeout preserves partial input.
 * Other transport/protocol errors close the stream. Free each handle once. */
typedef struct peios_timed_subscription peios_timed_subscription;
peios_timed_result *peios_timed_subscribe(peios_timed_bytes path, uint64_t timeout_ms,
                                          peios_timed_subscription **out);
peios_timed_result *peios_timed_subscription_next(peios_timed_subscription *subscription,
                                                  uint64_t timeout_ms);
void peios_timed_subscription_free(peios_timed_subscription *subscription);
#ifdef __cplusplus
}
#endif
#endif
