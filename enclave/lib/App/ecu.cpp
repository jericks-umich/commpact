#include "ecu.h"
#include "initialsetup.h"

#include "sgx_tcrypto.h"

///////////////////////
// GLOBAL PARAMETERS //
///////////////////////

// ecu_message_t ecu_parameters;
// cp_ec256_public_t enclave_pub_key;
// cp_ec256_private_t ecu_priv_key;
// cp_ec256_public_t ecu_pub_key;

// map index is platoon position
// std::unordered_map<uint64_t, ecu_t> ecus;
ecu_t ecus[COMMPACT_MAX_ENCLAVES];

commpact_status_t setEnclavePubKey(int position, cp_ec256_public_t *pub_key) {
  ecu_t *ecu = &ecus[position];
  memcpy(&(ecu->enclave_pub_key), pub_key, sizeof(cp_ec256_public_t));
  return CP_SUCCESS;
}

commpact_status_t setParametersECU(int position,
                                   cp_ec256_signature_t *enclave_signature,
                                   ecu_message_t *message,
                                   cp_ec256_signature_t *ecu_signature) {

  uint8_t verify_result = 0;
  void *handle;
  ecu_t *ecu = &ecus[position];
  sgx_ecdsa_verify((uint8_t *)message, sizeof(ecu_message_t),
                   (sgx_ec256_public_t *)&(ecu->enclave_pub_key),
                   (sgx_ec256_signature_t *)enclave_signature, &verify_result,
                   handle);

  if (verify_result != CP_EC_VALID) {
    memset(ecu_signature, 0, sizeof(cp_ec256_signature_t));
    return CP_SUCCESS;
  }
  memcpy(&(ecu->ecu_parameters), message, sizeof(ecu_message_t));

  // Sign the message
  signMessage(ecu, message, ecu_signature);

  return CP_SUCCESS;
}

commpact_status_t generateKeyPair(int position, cp_ec256_public_t *pub_key) {

  int retval = 0;
  sgx_status_t status = SGX_SUCCESS;
  void *ecc_handle;
  ecu_t *ecu = &ecus[position];

  status = sgx_ecc256_open_context(&ecc_handle);
  if (status != SGX_SUCCESS) {
    printf("ERROR: ecu open ec256 context failed");
    return CP_ERROR;
  }

  status = sgx_ecc256_create_key_pair(
      (sgx_ec256_private_t *)&(ecu->ecu_priv_key),
      (sgx_ec256_public_t *)&(ecu->ecu_pub_key), ecc_handle);
  if (status != SGX_SUCCESS) {
    printf("ERROR: ecu generate ec256 key pair failed");
    return CP_ERROR;
  }

  status = sgx_ecc256_close_context(ecc_handle);
  if (status != SGX_SUCCESS) {
    printf("ERROR: ecu close ec256 context failed");
    return CP_ERROR;
  }

  memcpy(pub_key, &(ecu->ecu_pub_key), sizeof(cp_ec256_public_t));
  return CP_SUCCESS;
}

commpact_status_t signMessage(ecu_t *ecu, ecu_message_t *message,
                              cp_ec256_signature_t *signature) {
  int retval = 0;
  void *handle;
  sgx_status_t status = SGX_SUCCESS;

  // Open ecc256 context
  status = sgx_ecc256_open_context(&handle);
  if (status != SGX_SUCCESS) {
    printf("ERROR: open ecc256 context failed");
    return CP_ERROR;
  }

  status = sgx_ecdsa_sign((uint8_t *)message, sizeof(ecu_message_t),
                          (sgx_ec256_private_t *)&(ecu->ecu_priv_key),
                          (sgx_ec256_signature_t *)signature, handle);
  if (status != SGX_SUCCESS) {
    printf("ERROR: Signing failed");
    return CP_ERROR;
  }

  status = sgx_ecc256_close_context(handle);
  if (status != SGX_SUCCESS) {
    printf("ERROR: close ecc256 context failed");
    return CP_ERROR;
  }

  return CP_SUCCESS;
}
