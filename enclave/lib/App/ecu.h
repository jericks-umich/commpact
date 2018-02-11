#include "../include/commpact_types.h"
#ifndef COMMPACT_ECU_H
#define COMMPACT_ECU_H

#include "sgx_tcrypto.h"

#include "../include/commpact_types.h"

// setters
commpact_status_t initializeKeysECU(cp_ec256_public_t *pubkey);
commpact_status_t setInitialPositionECU(cp_ec256_signature_t *signature,
                                        int position);
commpact_status_t setInitialSpeedBoundsECU(cp_ec256_signature_t *signature,
                                           double lower, double upper);
commpact_status_t
setInitialRecoveryPhaseTimeoutECU(cp_ec256_signature_t *signature,
                                  double timeout);

#endif // COMMPACT_ECU_H
