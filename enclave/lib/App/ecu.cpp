#include "ecu.h"

///////////////////////
// GLOBAL PARAMETERS //
///////////////////////
ecu_message_t ecu_parameters;
cp_ec256_public_t enclave_pub_key;
cp_ec256_private_t ecu_priv_key;
cp_ec256_public_t ecu_pub_key;
commpact_status_t setEnclavePubKey(cp_ec256_public_t *pub_key) {
  memcpy(&enclave_pub_key, pub_key, sizeof(cp_ec256_public_t));
  return CP_SUCCESS;
}

commpact_status_t setParametersECU(cp_ec256_signature_t *signature,
                                   ecu_message_t *message) {
  uint8_t verify_result = 0;
  sgx_ecc_state_handle_t handle;
  sgx_ecdsa_verify((uint8_t *)message, sizeof(ecu_message_t),
                   (sgx_ec256_public_t *)&enclave_pub_key,
                   (sgx_ec256_signature_t *)signature, &verify_result, handle);
  memcpy(&ecu_parameters, message, sizeof(ecu_message_t));
  return CP_SUCCESS;
}

commpact_status_t generateKeyPair(cp_ec256_public_t *pub_key) {
  int retval = 0;
  commpact_status_t status = CP_SUCCESS;
  sgx_ecc_state_handle_t ecc_handle;

  status = (commpact_status_t)sgx_ec256_open_context(&ecc_handle);
  if (status != CP_SUCCESS) {
    printf("ERROR: ecu open ec256 context failed");
    return status;
  }

  status = (commpact_status_t)sgx_ecc256_create_key_pair(
      (sgx_ec256_private_t *)&ecu_priv_key, (sgx_ec256_public_t *)&ecu_pub_key,
      ecc_handle);
  if (status != CP_SUCCESS) {
    printf("ERROR: ecu generate ec256 key pair failed");
    return status;
  }

  status = (commpact_status_t)sgx_ecc256_close_context(ecc_handle);
  if (status != CP_SUCCESS) {
    printf("ERROR: ecu close ec256 context failed");
    return status;
  }

  memcpy(pub_key, &ecu_pub_key, sizeof(cp_ec256_public_t));
  return status;
}
