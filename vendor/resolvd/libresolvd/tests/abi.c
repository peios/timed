#include <assert.h>
#include <errno.h>
#include <peios/resolvd.h>
int main(void) {
    assert(peios_resolvd_abi_version() == 1);
    peios_resolvd_bytes absent = {0};
    peios_resolvd_result *result = peios_resolvd_get_status(absent, 10);
    assert(result != 0);
    assert(peios_resolvd_result_error(result) == EINVAL);
    assert(peios_resolvd_result_message(result).len != 0);
    assert(peios_resolvd_result_status_report(result) == 0);
    peios_resolvd_result_free(result);
    peios_resolvd_result_free(0);
    return 0;
}
