#ifndef COMMPACT_APP_H
#define COMMPACT_APP_H

#define ENCLAVE_FILENAME "/tmp/enclave.signed.so"

#include "../include/commpact_types.h"

// API Exposed Functions
commpact_status_t initEnclave(uint64_t *enclave_id);
commpact_status_t setInitialPosition(uint64_t enclave_id, int position);
commpact_status_t initializeKeys(uint64_t enclave_id,
                                 cp_ec256_public_t *pubkey);
commpact_status_t checkAllowedSpeed(uint64_t enclave_id, double speed,
                                    bool *verdict);

// Private (static) functions

static commpact_status_t
setInitialPubKeys(uint64_t enclave_id, cp_ec256_public_t *pubkeys, int nkeys);

#endif // COMMPACT_APP_H
