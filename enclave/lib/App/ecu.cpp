#include "ecu.h"
#include "cp_crypto.h"

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

commpact_status_t setParametersECU(cp_ec256_signature_t *enclave_signature,
                                   ecu_message_t *message,
                                   cp_ec256_signature_t *ecu_signature) {

  uint8_t verify_result = 0;
  void *handle;
  cp_ecdsa_verify((uint8_t *)message, sizeof(ecu_message_t), &enclave_pub_key,
                  enclave_signature, &verify_result, handle);

  if (verify_result != CP_EC_VALID) {
    memset(ecu_signature, 0, sizeof(cp_ec256_signature_t));
    return CP_SUCCESS;
  }
  memcpy(&ecu_parameters, message, sizeof(ecu_message_t));

  // Sign the message
  signMessage(message, ecu_signature);

  return CP_SUCCESS;
}

commpact_status_t generateKeyPair(cp_ec256_public_t *pub_key) {

  int retval = 0;
  commpact_status_t status = CP_SUCCESS;
  void *ecc_handle;

  status = cp_ecc256_open_context(&ecc_handle);
  if (status != CP_SUCCESS) {
    printf("ERROR: ecu open ec256 context failed");
    return status;
  }

  status = cp_ecc256_create_key_pair(&ecu_priv_key, &ecu_pub_key, ecc_handle);
  if (status != CP_SUCCESS) {
    printf("ERROR: ecu generate ec256 key pair failed");
    return status;
  }

  status = cp_ecc256_close_context(ecc_handle);
  if (status != CP_SUCCESS) {
    printf("ERROR: ecu close ec256 context failed");
    return status;
  }

  memcpy(pub_key, &ecu_pub_key, sizeof(cp_ec256_public_t));
  return status;
}

commpact_status_t signMessage(ecu_message_t *message,
                              cp_ec256_signature_t *signature) {
  int retval = 0;
  void *handle;
  commpact_status_t status = CP_SUCCESS;

  // Open ecc256 context
  status = cp_ecc256_open_context(&handle);
  if (status != CP_SUCCESS) {
    printf("ERROR: open ecc256 context failed");
    return status;
  }

  status = (commpact_status_t)cp_ecdsa_sign((uint8_t *)message,
                                            sizeof(ecu_message_t),
                                            &ecu_priv_key, signature, handle);
  if (status != CP_SUCCESS) {
    printf("ERROR: Signing failed");
    return status;
  }

  status = cp_ecc256_close_context(handle);
  if (status != CP_SUCCESS) {
    printf("ERROR: close ecc256 context failed");
    return status;
  }

  return CP_SUCCESS;
}
