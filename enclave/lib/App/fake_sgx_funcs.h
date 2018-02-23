#ifndef FAKE_SGX_FUNCS_H
#define FAKE_SGX_FUNCS_H

#include <errno.h>
#include <stddef.h>

#include "sgx_eid.h"
#include "sgx_error.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int errno_t;
errno_t memset_s(void *s, size_t smax, int c, size_t n);

sgx_status_t sgx_read_rand(unsigned char *rand, size_t length_in_bytes);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // FAKE_SGX_FUNCS_H
