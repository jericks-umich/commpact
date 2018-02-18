#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sgx_error.h"
#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"

#include "Enclave.h"
#include "Enclave_t.h"

// GLOBAL VARIABLES
////////////////////////////////////////////////////////////////////////////////
ec256_key_pair_t *key_pair = NULL; // Global EC256 cache
sgx_ec256_public_t *pub_keys = NULL;
sgx_ec256_public_t *ecu_pub_key = NULL;
int position;
contract_chain_t enclave_parameters;
////////////////////////////////////////////////////////////////////////////////

// PUBLIC
////////////////////////////////////////////////////////////////////////////////
// This is the function to generate a ecc256 key pair.
// When called, generate a key-pair and return the pub_key
sgx_status_t initialEc256KeyPair(sgx_ec256_public_t *pub) {
  int retval = 0;
  sgx_status_t status = SGX_SUCCESS;
  sgx_ecc_state_handle_t ecc_handle;

  // Check if key_pair available
  if (key_pair == NULL) {
    key_pair = (ec256_key_pair_t *)calloc(1, sizeof(ec256_key_pair_t));
    if (key_pair == NULL) {
      char msg[] = "ERROR: allocate memory for key_pair failed.";
      ocallPrints(&retval, msg);
      return SGX_ERROR_OUT_OF_MEMORY;
    }
  }

  // Open ecc256 context
  status = sgx_ecc256_open_context(&ecc_handle);
  if (status != SGX_SUCCESS) {
    char msg[] = "ERROR: open ecc256 context failed";
    ocallPrints(&retval, msg);
    return status;
  }

  // Generating key pair with eec256 context
  status = sgx_ecc256_create_key_pair(&(key_pair->priv), &(key_pair->pub),
                                      ecc_handle);
  if (status != SGX_SUCCESS) {
    char msg[] = "ERROR: generate ecc256 key pair failed";
    ocallPrints(&retval, msg);
    return status;
  }

  // Close ecc256 context
  status = sgx_ecc256_close_context(ecc_handle);
  if (status != SGX_SUCCESS) {
    char msg[] = "ERROR: close ecc256 context failed";
    ocallPrints(&retval, msg);
    return status;
  }

  // Copy pub key to the outside
  memcpy(pub, &(key_pair->pub), sizeof(sgx_ec256_public_t));

  ocallECUSetEnclavePubKey(&retval, &(key_pair->pub));
  return SGX_SUCCESS;
}

// This is the function to set vehicle's position
// It returns signature of this flag|data
sgx_status_t setPosition(int *pos, sgx_ec256_signature_t *sig) {

  int retval = 0;

  memcpy(&position, pos, sizeof(int));
  if (key_pair == NULL) {
    char msg[] = "ERROR: public key has not been generated";
    ocallPrints(&retval, msg);
    return SGX_ERROR_UNEXPECTED;
  }
  return SGX_SUCCESS;
}

// This is the function to set all pubkeys of vehicles in the platoon
// It takes 2 parameters
// pubkeys : sgx_ec256_public_t pubkeys*
//	A pointer to an array of pubkeys to be set, ordered by position in
// platoon
// platoon_len : uint8_t
//	The length of platoon
sgx_status_t setPubKeys(sgx_ec256_public_t *pub_keys_in,
                        uint8_t platoon_len_in) {
  int retval = 0;

  // Free the memory if it has been allocated previously
  if (pub_keys != NULL) {
    free(pub_keys);
    pub_keys = NULL;
  }

  // Allocate new memory
  pub_keys =
      (sgx_ec256_public_t *)calloc(platoon_len_in, sizeof(sgx_ec256_public_t));
  if (pub_keys == NULL) {
    char msg[] = "ERROR: allocate memory for public keys failed";
    ocallPrints(&retval, msg);
    return SGX_ERROR_INVALID_STATE;
  }

  // Copy the public keys into the inside memory
  memcpy(pub_keys, pub_keys_in, platoon_len_in * sizeof(sgx_ec256_public_t));

  // Set the length of the platoon
  enclave_parameters.chain_length = platoon_len_in;

  return SGX_SUCCESS;
}

sgx_status_t setInitialSpeedBounds(double lower, double upper) {
  enclave_parameters.lower_speed = lower;
  enclave_parameters.upper_speed = upper;
  return SGX_SUCCESS;
}

sgx_status_t setInitialRecoveryPhaseTimeout(double timeout) {
  enclave_parameters.recovery_phase_timeout = timeout;
  sendECUMessage();
  return SGX_SUCCESS;
}

sgx_status_t checkAllowedSpeed(double speed, bool *verdict) {
  if (!(enclave_parameters.lower_speed <= speed &&
        speed <= enclave_parameters.upper_speed)) {
    *verdict = false;
  } else {
    *verdict = true;
  }
  return SGX_SUCCESS;
}

sgx_status_t setECUPubKey(sgx_ec256_public_t *ecu_pub_key_in) {
  memcpy(ecu_pub_key, ecu_pub_key_in, sizeof(sgx_ec256_public_t));
  return SGX_SUCCESS;
}

sgx_status_t validateSignatures(contract_chain_t *contract,
                                sgx_ec256_signature_t *signatures,
                                uint8_t num_signatures) {
  return SGX_SUCCESS;
}

sgx_status_t checkParameters(contract_chain_t *contract) { return SGX_SUCCESS; }

sgx_status_t updateParameters(contract_chain_t *contract) {
  return SGX_SUCCESS;
}

sgx_status_t signContract(contract_chain_t *contract,
                          sgx_ec256_signature_t *return_signature) {
  return SGX_SUCCESS;
}
////////////////////////////////////////////////////////////////////////////////

// PRIVATE
////////////////////////////////////////////////////////////////////////////////
sgx_status_t sendECUMessage() {
  sgx_ec256_signature_t signature;
  ecu_message_t message;
  return sendECUMessage(&signature, &message);
}

sgx_status_t sendECUMessage(sgx_ec256_signature_t *signature,
                            ecu_message_t *message) {
  message->position = position;
  message->recovery_phase_timeout = enclave_parameters.recovery_phase_timeout;
  message->chain_length = enclave_parameters.chain_length;
  message->upper_speed = enclave_parameters.upper_speed;
  message->lower_speed = enclave_parameters.lower_speed;
  message->upper_accel = enclave_parameters.upper_accel;
  message->lower_accel = enclave_parameters.lower_accel;
  message->max_decel = enclave_parameters.max_decel;

  int retval = 0;
  sgx_ecc_state_handle_t handle;
  sgx_status_t status = SGX_SUCCESS;

  // Open ecc256 context
  status = sgx_ecc256_open_context(&handle);
  if (status != SGX_SUCCESS) {
    char msg[] = "ERROR: open ecc256 context failed";
    ocallPrints(&retval, msg);
    return status;
  }

  status = sgx_ecdsa_sign((uint8_t *)message, sizeof(ecu_message_t),
                          &key_pair->priv, signature, handle);
  if (status != SGX_SUCCESS) {
    char msg[] = "ERROR: Signing failed";
    ocallPrints(&retval, msg);
    return status;
  }

  status = sgx_ecc256_close_context(handle);
  if (status != SGX_SUCCESS) {
    char msg[] = "ERROR: close ecc256 context failed";
    ocallPrints(&retval, msg);
    return status;
  }

  retval = 0;
  sgx_ec256_signature_t ecu_signature;
  // Make the ocall
  ocallECUMessage(&retval, signature, message, &ecu_signature);
  uint8_t verify_result = SGX_EC_INVALID_SIGNATURE;
  verifyMessageSignature(message, &ecu_signature, ecu_pub_key, &verify_result);
  if (verify_result == SGX_EC_VALID) { // TODO
  }

  return SGX_SUCCESS;
}

sgx_status_t verifyMessageSignature(ecu_message_t *message,
                                    sgx_ec256_signature_t *signature,
                                    sgx_ec256_public_t *pub_key,
                                    uint8_t *result) {
  int retval = 0;
  sgx_ecc_state_handle_t handle;
  sgx_status_t status = SGX_SUCCESS;

  // Open ecc256 context
  status = sgx_ecc256_open_context(&handle);
  if (status != SGX_SUCCESS) {
    char msg[] = "ERROR: open ecc256 context failed";
    ocallPrints(&retval, msg);
    return status;
  }

  status = sgx_ecdsa_verify((uint8_t *)message, sizeof(ecu_message_t), pub_key,
                            signature, result, handle);
  if (status != SGX_SUCCESS) {
    char msg[] = "ERROR: Verifying failed";
    ocallPrints(&retval, msg);
    return status;
  }

  status = sgx_ecc256_close_context(handle);
  if (status != SGX_SUCCESS) {
    char msg[] = "ERROR: close ecc256 context failed";
    ocallPrints(&retval, msg);
    return status;
  }

  return SGX_SUCCESS;
}

sgx_status_t validateSignaturesHelper(contract_chain_t *contract,
                                      sgx_ec256_signature_t *signatures,
                                      uint8_t num_signatures) {
  return SGX_SUCCESS;
}

sgx_status_t checkParametersHelper(contract_chain_t *contract) {
  return SGX_SUCCESS;
}

sgx_status_t updateParametersHelper(contract_chain_t *contract) {
  return SGX_SUCCESS;
}

sgx_status_t signContractHelper(contract_chain_t *contract,
                                sgx_ec256_signature_t *return_signature) {
  return SGX_SUCCESS;
}
////////////////////////////////////////////////////////////////////////////////

// PUBLIC DEBUG
////////////////////////////////////////////////////////////////////////////////
sgx_status_t enclave_status() {
  int rand[1] = {0};
  sgx_read_rand((unsigned char *)rand, sizeof(unsigned int));
  int passfail = *rand % 2;
  return passfail ? SGX_SUCCESS : SGX_ERROR_INVALID_STATE;
}

// Get position of the enclave
sgx_status_t getPosition(int *pos) {
  memcpy(pos, &position, sizeof(int));
  return SGX_SUCCESS;
}
////////////////////////////////////////////////////////////////////////////////
