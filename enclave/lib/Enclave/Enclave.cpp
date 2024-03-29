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
uint8_t num_vehicles = 0;
sgx_ec256_public_t *ecu_pub_key = NULL;
uint8_t position;
uint64_t id;
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

  // get the ecu pubkey
  ecu_pub_key = (sgx_ec256_public_t *)calloc(1, sizeof(sgx_ec256_public_t));
  ocallECUSetGetEnclavePubKey(&retval, id, &(key_pair->pub), ecu_pub_key);

  // Copy pub key to the outside
  memcpy(pub, &(key_pair->pub), sizeof(sgx_ec256_public_t));

  return SGX_SUCCESS;
}

// This is the function to set vehicle's position
// It returns signature of this flag|data
sgx_status_t setPosition(uint8_t pos) {

  position = pos;
  // memcpy(&position, pos, sizeof(int));
  // if (key_pair == NULL) {
  //  char msg[] = "ERROR: public key has not been generated";
  //  ocallPrints(&retval, msg);
  //  return SGX_ERROR_UNEXPECTED;
  //}
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
  num_vehicles = platoon_len_in;
  if (pub_keys == NULL) {
    char msg[] = "ERROR: allocate memory for public keys failed";
    ocallPrints(&retval, msg);
    return SGX_ERROR_INVALID_STATE;
  }

  // Copy the public keys into the inside memory
  memcpy(pub_keys, pub_keys_in, platoon_len_in * sizeof(sgx_ec256_public_t));

  return SGX_SUCCESS;
}

sgx_status_t setInitialSpeedBoundsEnclave(double lower, double upper) {
  enclave_parameters.lower_speed = lower;
  enclave_parameters.upper_speed = upper;
  return SGX_SUCCESS;
}

sgx_status_t setInitialRecoveryPhaseTimeoutEnclave(double timeout) {
  enclave_parameters.recovery_phase_timeout = timeout;
  sendECUMessage();
  return SGX_SUCCESS;
}

sgx_status_t checkAllowedSpeedEnclave(double speed, bool *verdict) {
  if (!(enclave_parameters.lower_speed <= speed &&
        speed <= enclave_parameters.upper_speed)) {
    *verdict = false;
  } else {
    *verdict = true;
  }
  return SGX_SUCCESS;
}

sgx_status_t newContractChainGetSignatureEnclave(
    contract_chain_t *contract, sgx_ec256_signature_t *return_signature,
    sgx_ec256_signature_t *signatures, uint8_t num_signatures) {
  uint8_t verify_result = 0;
  uint8_t should_update_ecu = true;
  sgx_status_t status = SGX_SUCCESS;
  memset(return_signature, 0, sizeof(sgx_ec256_signature_t));
  status = validateSignaturesHelper(contract, signatures, num_signatures);
  if (status != SGX_SUCCESS) {
    return status;
  }
  status = checkParametersHelper(contract, &should_update_ecu);
  if (status != SGX_SUCCESS) {
    return status;
  }
  status = updateParametersHelper(contract);
  if (status != SGX_SUCCESS) {
    return status;
  }
  if (should_update_ecu) {
    sendECUMessage();
    if (status != SGX_SUCCESS) {
      return status;
    }
  }
  status = signContractHelper(contract, return_signature);
  if (status != SGX_SUCCESS) {
    memset(return_signature, 0, sizeof(sgx_ec256_signature_t));
    return status;
  }
  return SGX_SUCCESS;
}

sgx_status_t setEnclaveId(uint64_t enclave_id) {
  id = enclave_id;
  return SGX_SUCCESS;
}
////////////////////////////////////////////////////////////////////////////////

// PRIVATE
////////////////////////////////////////////////////////////////////////////////
sgx_status_t sendECUMessage() {
  sgx_ec256_signature_t signature;
  ecu_message_t message;

  memset(&message, 0, sizeof(ecu_message_t));
  message.position = position;
  message.num_vehicles = num_vehicles;
  message.recovery_phase_timeout = enclave_parameters.recovery_phase_timeout;
  message.upper_speed = enclave_parameters.upper_speed;
  message.lower_speed = enclave_parameters.lower_speed;
  message.upper_accel = enclave_parameters.upper_accel;
  message.lower_accel = enclave_parameters.lower_accel;
  message.max_decel = enclave_parameters.max_decel;

  return sendECUMessage(&signature, &message);
}

sgx_status_t sendECUMessage(sgx_ec256_signature_t *signature,
                            ecu_message_t *message) {

  int retval = 0;
  sgx_ecc_state_handle_t handle;
  sgx_status_t status = SGX_SUCCESS;
  sgx_status_t ret = SGX_SUCCESS;

  // Open ecc256 context
  status = sgx_ecc256_open_context(&handle);
  if (status != SGX_SUCCESS) {
    char msg[] = "ERROR: open ecc256 context failed";
    ocallPrints(&retval, msg);
    return status;
  }

  // char msg[] = "Signing with pubkey for position";
  // ocallPrints(&retval, msg);
  // ocallPrintU(&retval, (unsigned int)position);
  // ocallPrintX(&retval, *(unsigned int *)&key_pair->pub);
  status = sgx_ecdsa_sign((uint8_t *)message, sizeof(ecu_message_t),
                          &key_pair->priv, signature, handle);
  if (status != SGX_SUCCESS) {
    char msg[] = "ERROR: Signing failed";
    ocallPrints(&retval, msg);
    ret = status;
  }

  status = sgx_ecc256_close_context(handle);
  if (status != SGX_SUCCESS) {
    char msg[] = "ERROR: close ecc256 context failed";
    ocallPrints(&retval, msg);
    return status;
  }
  if (ret != SGX_SUCCESS) {
    return ret;
  }

  retval = 0;
  sgx_ec256_signature_t ecu_signature;
  // Make the ocall
  ocallECUMessage(&retval, id, signature, message, &ecu_signature);
  uint8_t verify_result = SGX_EC_INVALID_SIGNATURE;
  verifyMessageSignature((uint8_t *)message, sizeof(ecu_message_t),
                         &ecu_signature, ecu_pub_key, &verify_result);
  if (verify_result != SGX_EC_VALID) {
    char msg[] = "ERROR: could not verify ECU signature";
    ocallPrints(&retval, msg);
    return SGX_ERROR_UNEXPECTED;
  }

  return SGX_SUCCESS;
}

sgx_status_t verifyMessageSignature(uint8_t *message, uint64_t message_size,
                                    sgx_ec256_signature_t *signature,
                                    sgx_ec256_public_t *pub_key,
                                    uint8_t *result) {
  int retval = 0;
  sgx_ecc_state_handle_t handle;
  sgx_status_t status = SGX_SUCCESS;
  sgx_status_t ret = SGX_SUCCESS;

  // Open ecc256 context
  status = sgx_ecc256_open_context(&handle);
  if (status != SGX_SUCCESS) {
    char msg[] = "ERROR: open ecc256 context failed";
    ocallPrints(&retval, msg);
    return status;
  }

  status = sgx_ecdsa_verify((uint8_t *)message, message_size, pub_key,
                            signature, result, handle);
  if (status != SGX_SUCCESS) {
    char msg[] = "ERROR: Verifying failed";
    ocallPrints(&retval, msg);
    ret = status;
  }

  status = sgx_ecc256_close_context(handle);
  if (status != SGX_SUCCESS) {
    char msg[] = "ERROR: close ecc256 context failed";
    ocallPrints(&retval, msg);
    return status;
  }

  return ret;
}

sgx_status_t validateSignaturesHelper(contract_chain_t *contract,
                                      sgx_ec256_signature_t *signatures,
                                      uint8_t num_signatures) {
  uint8_t result = SGX_EC_INVALID_SIGNATURE;
  if (num_signatures == 0) { // if we have no signatures to verify
    return SGX_SUCCESS;
  }
  int retval = 0;
  for (int i = 0; i < contract->chain_length; ++i) {
    // i is the position in the chain_order
    uint8_t pos = contract->chain_order[i];
    if (pos == position) { // if we've reached our own vehicle
                           // then we're done verifying signatures
      // if we're the leader and just received a contract chain with > 0
      // signatures, then we shouldn't break
      if (!(i == 0 && position == 0 && num_signatures > 0)) {
        break;
      }
      // TODO: fix this for other types of contract chains
    }
    if (num_signatures < pos) { // sanity check
      ocallPrintI(&retval, (int)num_signatures);
      ocallPrintI(&retval, pos);
      char msg[] = "Not enough signatures provided";
      ocallPrints(&retval, msg);
      return SGX_ERROR_UNEXPECTED;
    }
    verifyMessageSignature((uint8_t *)contract, sizeof(contract_chain_t),
                           &signatures[pos], &pub_keys[pos], &result);
    if (result != SGX_EC_VALID) {
      ocallPrintI(&retval, (int)num_signatures);
      ocallPrintI(&retval, i);
      ocallPrintI(&retval, pos);
      ocallPrintX(&retval, *(unsigned int *)&signatures[pos]);
      ocallPrintX(&retval, *(unsigned int *)&pub_keys[pos]);
      char msg[] = "Invalid signature";
      ocallPrints(&retval, msg);
      return SGX_ERROR_UNEXPECTED;
    }
  }
  return SGX_SUCCESS;
}

sgx_status_t checkParametersHelper(contract_chain_t *contract,
                                   uint8_t *should_update_ecu) {
  // should we update the ecu?
  // Yes, unless (we are the leader && this is a deceleration/reverse chain)
  *should_update_ecu = true;

  // timeout is being extended
  if (contract->recovery_phase_timeout >
      enclave_parameters.recovery_phase_timeout) {
    for (int i = 0; i < contract->chain_length; ++i) {
      if ((i == 0 || i == contract->chain_length - 1) &&
          contract->chain_order[i] != 0) {
        int retval = 0;
        char msg[] = "checkParametersHelper: timeout is being extended but "
                     "leader isn't first and last in chain order";
        ocallPrints(&retval, msg);
        return SGX_ERROR_UNEXPECTED;
      } else {
        if (contract->chain_order[i] != i) {
          int retval = 0;
          char msg[] = "checkParametersHelper: timeout is being extended but "
                       "vehicle positions aren't ascending in chain order";
          ocallPrints(&retval, msg);
          return SGX_ERROR_UNEXPECTED;
        }
      }
      return SGX_SUCCESS;
    }
  }

  // if contract bounds are staying the same
  if (contract->upper_speed == enclave_parameters.upper_speed &&
      contract->lower_speed == enclave_parameters.lower_speed) {
    // we don't need to enforce any particular ordering on the chain
    return SGX_SUCCESS;
  }
  // deceleration
  else if (contract->upper_speed < enclave_parameters.upper_speed) {
    // check position 0
    if (contract->chain_order[0] != 0) {
      int retval = 0;
      char msg[] = "checkParametersHelper: deceleration but leader isn't first "
                   "in chain order";
      ocallPrints(&retval, msg);
      return SGX_ERROR_UNEXPECTED;
    }

    // check position 1
    if (contract->chain_order[1] != num_vehicles - 1) {
      int retval = 0;
      char msg[] = "checkParametersHelper: deceleration but last vehicle isn't "
                   "second in chain order";
      ocallPrints(&retval, msg);
      ocallPrintD(&retval, enclave_parameters.upper_speed);
      ocallPrintD(&retval, contract->upper_speed);
      return SGX_ERROR_UNEXPECTED;
    }

    // check position 2 and beyond
    for (int i = 2; i < contract->chain_length; ++i) {
      if (contract->chain_order[i] != contract->chain_order[i - 1] - 1) {
        int retval = 0;
        char msg[] = "checkParametersHelper: deceleration but vehicle "
                     "positions aren't decending in chain order";
        ocallPrints(&retval, msg);
        return SGX_ERROR_UNEXPECTED;
      }
      // if we get here, this is a deceleration chain
      if (position == 0) {          // and we're the leader
        *should_update_ecu = false; // so we shouldn't update the ECU
        // TODO: needs another check to see if every other vehicle has already
        // started decelerating, and if so, send it to the ECU
        // As is, it just means that the *next* contract chain will cause the
        // leader to begin decelerating, which should be okay
      }
      return SGX_SUCCESS;
    }
  }

  // acceleration
  else if (contract->lower_speed > enclave_parameters.lower_speed) {

    for (int i = 0; i < contract->chain_length; ++i) {
      if ((i == 0 || i == contract->chain_length - 1) &&
          contract->chain_order[i] != 0) {
        int retval = 0;
        char msg[] = "checkParametersHelper: acceleration but leader isn't"
                     "first and last in chain order";
        ocallPrints(&retval, msg);
        return SGX_ERROR_UNEXPECTED;
      } else {
        if (contract->chain_order[i] != i) {
          int retval = 0;
          char msg[] = "checkParametersHelper: acceleration but vehicle "
                       "positions aren't ascending in chain order";
          ocallPrints(&retval, msg);
          return SGX_ERROR_UNEXPECTED;
        }
      }
      return SGX_SUCCESS;
    }
  }

  // unaccounted for scenarios
  else {
    int retval = 0;
    char msg[] = "checkParametersHelper: we have an unaccounted scenario";
    ocallPrints(&retval, msg);
    return SGX_ERROR_UNEXPECTED;
  }
}

sgx_status_t updateParametersHelper(contract_chain_t *contract) {
  enclave_parameters = *contract;
  // for (int i = 0; i < enclave_parameters.chain_length; ++i) {
  //  enclave_parameters.chain_order[i] = contract->chain_order[i];
  //}
  // return sendECUMessage();
  return SGX_SUCCESS;
}

sgx_status_t signContractHelper(contract_chain_t *contract,
                                sgx_ec256_signature_t *return_signature) {

  int retval = 0;
  sgx_ecc_state_handle_t handle;
  sgx_status_t status = SGX_SUCCESS;
  sgx_status_t ret = SGX_SUCCESS;

  // Open ecc256 context
  status = sgx_ecc256_open_context(&handle);
  if (status != SGX_SUCCESS) {
    char msg[] = "ERROR: open ecc256 context failed";
    ocallPrints(&retval, msg);
    return status;
  }

  status = sgx_ecdsa_sign((uint8_t *)contract, sizeof(contract_chain_t),
                          &key_pair->priv, return_signature, handle);
  if (status != SGX_SUCCESS) {
    char msg[] = "ERROR: Signing failed";
    ocallPrints(&retval, msg);
    ret = status;
  }

  status = sgx_ecc256_close_context(handle);
  if (status != SGX_SUCCESS) {
    char msg[] = "ERROR: close ecc256 context failed";
    ocallPrints(&retval, msg);
    return status;
  }

  return ret;
}
////////////////////////////////////////////////////////////////////////////////
// PUBLIC DEBUG
////////////////////////////////////////////////////////////////////////////////
#ifdef COMMPACT_DEBUG
sgx_status_t enclave_status() {
  int rand[1] = {0};
  sgx_read_rand((unsigned char *)rand, sizeof(unsigned int));
  int passfail = *rand % 2;
  return passfail ? SGX_SUCCESS : SGX_ERROR_INVALID_STATE;
}

// Get position of the enclave
sgx_status_t getPosition(uint8_t *pos) {
  memcpy(pos, &position, sizeof(int));
  return SGX_SUCCESS;
}

sgx_status_t validateSignatures(contract_chain_t *contract,
                                sgx_ec256_signature_t *signatures,
                                uint8_t num_signatures) {
  return validateSignaturesHelper(contract, signatures, num_signatures);
}

sgx_status_t checkParameters(contract_chain_t *contract) {
  uint8_t ignore;
  return checkParametersHelper(contract, &ignore);
}

sgx_status_t updateParameters(contract_chain_t *contract) {
  return updateParametersHelper(contract);
}

sgx_status_t signContract(contract_chain_t *contract,
                          sgx_ec256_signature_t *return_signature) {
  return signContractHelper(contract, return_signature);
}
#endif
////////////////////////////////////////////////////////////////////////////////
