#ifndef COMMPACT_TEST_H
#define COMMPACT_TEST_H

#include "../include/status.h"

// API Exposed Functions
commpact_status_t init_crypto_enclave(uint64_t *enclave_id,
                                      const char *enclave_filename);
commpact_status_t enclave_status(uint64_t enclave_id);

#endif // COMMPACT_TEST_H
