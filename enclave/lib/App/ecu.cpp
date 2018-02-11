#include "ecu.h"

///////////////////////
// GLOBAL PARAMETERS //
///////////////////////
ecu_message_t ecu_parameters;
cp_ec256_public_t enclave_pub_key;
>>>>>>> 171c433c9f72610dea6c90ef936dca172622fe25

commpact_status_t setParameters(cp_ec256_signature_t *signature,
                                ecu_message_t *message) {
  uint8_t verify_result = 0;
  sgx_ecc_state_handle_t handle;
  sgx_ecdsa_verify((uint8_t *)message, sizeof(ecu_message_t),
                   (sgx_ec256_public_t *)&enclave_pub_key,
                   (sgx_ec256_signature_t *)signature, &verify_result, handle);
  memcpy(&ecu_parameters, message, sizeof(ecu_message_t));
  return CP_SUCCESS;
}
