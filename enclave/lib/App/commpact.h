#ifndef COMMPACT_APP_H
#define COMMPACT_APP_H

#include "../include/commpact_status.h"

// API Exposed Functions
commpact_status_t init_crypto_enclave(uint64_t *enclave_id,
                                      const char *enclave_filename);
commpact_status_t enclave_status(uint64_t enclave_id);

#endif // COMMPACT_APP_H
