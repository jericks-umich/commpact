#ifndef COMMPACT_APP_H
#define COMMPACT_APP_H

#define ENCLAVE_FILENAME "/tmp/enclave.signed.so"

#include "../include/commpact_types.h"

// API Exposed Functions
commpact_status_t initEnclave(uint64_t *enclave_id);
commpact_status_t setInitialPosition(uint64_t enclave_id, int position);
commpact_status_t initializeKeys(uint64_t enclave_id,
                                 cp_ec256_public_t *pubkey);
commpact_status_t setInitialSpeedBounds(uint64_t enclave_id, double lower,
                                        double upper);
commpact_status_t setInitialRecoveryPhaseTimeout(uint64_t enclave_id,
                                                 double timeout);
commpact_status_t checkAllowedSpeed(uint64_t enclave_id, double speed,
                                    bool *verdict);

// Private (static) functions

#endif // COMMPACT_APP_H
