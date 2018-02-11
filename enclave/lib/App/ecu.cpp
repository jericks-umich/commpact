#include "ecu.h"

int position = 0;
int platoon_len = 0;

commpact_status_t initializeKeysECU(cp_ec256_public_t *pubkey) {
  return CP_SUCCESS;
}

commpact_status_t setInitialPositionECU(cp_ec256_signature_t *signature,
                                        int position) {
  return CP_SUCCESS;
}

commpact_status_t setInitialSpeedBoundsECU(cp_ec256_signature_t *signature,
                                           double lower, double upper) {
  return CP_SUCCESS;
}

commpact_status_t
setInitialRecoveryPhaseTimeoutECU(cp_ec256_signature_t *signature,
                                  double timeout) {
  return CP_SUCCESS;
}
