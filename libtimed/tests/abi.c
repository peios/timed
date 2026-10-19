#include <assert.h>
#include <errno.h>
#include <peios/timed.h>
int main(void) {
    assert(peios_timed_abi_version() == 1);
    peios_timed_bytes absent = {0};
    peios_timed_result *result = peios_timed_get_status(absent, 10);
    assert(result != 0);
    assert(peios_timed_result_error(result) == EINVAL);
    assert(peios_timed_result_message(result).len != 0);
    assert(peios_timed_result_status(result) == 0);
    peios_timed_result_free(result);
    peios_timed_result_free(0);
    return 0;
}
