#include <assert.h>
#include <errno.h>
#include <peios/trust.h>
int main(void) {
    assert(peios_trust_abi_version() == 1);
    peios_trust_bytes absent = {0};
    peios_trust_result *result = peios_trust_get_status(absent, 10);
    assert(result != 0);
    assert(peios_trust_result_error(result) == EINVAL);
    assert(peios_trust_result_message(result).len != 0);
    assert(peios_trust_result_status(result) == 0);
    peios_trust_result_free(result);
    peios_trust_result_free(0);
    return 0;
}
