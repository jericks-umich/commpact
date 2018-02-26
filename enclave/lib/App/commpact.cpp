#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "sgx_eid.h"
#include "sgx_error.h"
#include "sgx_tcrypto.h"
#include "sgx_urts.h"

#include "../include/ecu_types.h"

#include "Enclave_u.h"
#include "commpact.h"
#include "ecu.h"
#include "initialsetup.h"
#define INITIAL_SETUP InitialSetup::getInstance()
#define GET_POSITION InitialSetup::getInstance().getPosition

// https://software.intel.com/en-us/articles/intel-software-guard-extensions-developing-a-sample-enclave-application

///////////////////////////
// API Exposed Functions //
///////////////////////////
// Initialize instance of crypto enclave
commpact_status_t initEnclave(uint64_t *e_id) {
  return initEnclaveWithFilename(e_id, DEFAULT_ENCLAVE_FILENAME);
}

// Initialize instance of crypto enclave
commpact_status_t initEnclaveWithFilename(uint64_t *e_id,
                                          const char *enclave_filename) {
  sgx_enclave_id_t *enclave_id =
      (sgx_enclave_id_t *)e_id; // casting it to the correct type -- we don't
                                // want to require sgx types outside of the .so
  int ret;
  int updated; // flag for whether the launch token is updated or not (it should
               // be, since we don't pass it a valid one)
  sgx_launch_token_t token = {0};

  // create new enclave
  // https://software.intel.com/sites/products/sgx-sdk-users-guide-windows/Content/sgx_create_enclave.htm
  // https://software.intel.com/en-us/node/709072
  ret = sgx_create_enclave(enclave_filename, SGX_DEBUG_FLAG, &token, &updated,
                           enclave_id, NULL);
  if (ret != SGX_SUCCESS) {
    printf("ERROR: failed (%x) to initialize SGX crypto enclave.\n", ret);
    return CP_ERROR;
  }

  sgx_status_t retval = SGX_SUCCESS;
  ret = setEnclaveId(*enclave_id, &retval, *enclave_id);

  return CP_SUCCESS;
}

// This position in the platoon is set when the vehicle is initialized.
// Use this function to set the position of this vehicle in the platoon during
// the initial setup
commpact_status_t setInitialPosition(uint64_t enclave_id, int position) {
  printf("Position: %d\n", position);
  // validate position is between 0 and COMMPACT_MAX_ENCLAVES-1
  if (position < 0 or position >= COMMPACT_MAX_ENCLAVES) {
    return CP_INVALID_PARAMETER;
  }
  sgx_status_t retval = SGX_SUCCESS;
  sgx_status_t status = SGX_SUCCESS;
  status = setPosition(enclave_id, &retval, position);
  if (status != SGX_SUCCESS) {
    printf("failed set position: enclave : %lu, position : %d\n", enclave_id,
           position);
    return CP_ERROR;
  }

  // Part of InitialSetup hack
  // record the enclave_id for this vehicle
  INITIAL_SETUP.enclave_id_list[position] = enclave_id;
  INITIAL_SETUP.used_list[position] = true;
  INITIAL_SETUP.n_vehicles++;

  return CP_SUCCESS;
}

// This function will be called immediately after setting the enclave position
// and should generate a keypair. The private key should remain in the enclave,
// but the public key should be returned.
// The pubkey should also be stored in the InitialSetup singleton.
// Later calls to sign messages should use this private key.
// The public keys for each vehicle will be gathered and then passed to the
// enclave using setInitialPubKeys() below. Verification of these messages
// should use these public keys.
// The cp_ec256_public_t type should be identical to the _sgx_ec256_public_t
// type. You should be able to simply cast it.
commpact_status_t initializeKeys(uint64_t enclave_id,
                                 cp_ec256_public_t *pubkey) {
  printf("Initializing keys for vehicle %d, enclave %lu\n",
         GET_POSITION(enclave_id), enclave_id);

  sgx_status_t retval = SGX_SUCCESS;
  sgx_status_t status = SGX_SUCCESS;

  // Generate a key pair in enclave, the key will also be passed to ecu
  status =
      initialEc256KeyPair(enclave_id, &retval, (sgx_ec256_public_t *)pubkey);

  if (status != SGX_SUCCESS) {
    printf("Failed initialize keys\n");
    return CP_ERROR;
  }

  // Generate a key pair in ecu and pass the key to enclave
  cp_ec256_public_t ecu_pub_key;
  status = (sgx_status_t)generateKeyPair(INITIAL_SETUP.getPosition(enclave_id),
                                         &ecu_pub_key);
  if (status != SGX_SUCCESS) {
    printf("Ecu failed generate keys\n");
    return CP_ERROR;
  }
  status =
      setECUPubKey(enclave_id, &retval, (sgx_ec256_public_t *)&ecu_pub_key);
  if (status != SGX_SUCCESS) {
    printf("Failed pass ecu's pub key into enclave\n");
    return CP_ERROR;
  }

  // Part of InitialSetup hack
  // record the enclave_id for this vehicle
  int position = GET_POSITION(enclave_id);
  if (position != -1) {
    memcpy(&INITIAL_SETUP.pubkey_list[position], pubkey,
           sizeof(cp_ec256_public_t));
  }

  // Since we've updated the list of public keys, we should update each enclave
  // with the new list
  for (int i = 0; i < COMMPACT_MAX_ENCLAVES; i++) {
    if (INITIAL_SETUP.used_list[i]) {
      // We're making an assumption here that the first N positions in this
      // list are filled. If this assumption doesn't hold true for the first
      // few vehicles, that should be okay. When we add the last vehicle, it
      // should be a contiguous list of pubkeys and should overwrite and
      // previous sparse list we told the enclave about.
      status = setPubKeys(INITIAL_SETUP.enclave_id_list[i], &retval,
                          (sgx_ec256_public_t *)INITIAL_SETUP.pubkey_list,
                          INITIAL_SETUP.n_vehicles);
      if (retval != SGX_SUCCESS) {
        printf("Error setting initial pubkeys. retval = %d\n", retval);
        return CP_ERROR;
      }
      if (status != SGX_SUCCESS) {
        printf("Error setting initial pubkeys. status = %d\n", status);
        return CP_ERROR;
      }
    }
  }

  return CP_SUCCESS;
}

// Called during initialization, passes a pair of initial speed bounds to the
// enclave for later use in checkAllowedSpeed()
commpact_status_t setInitialSpeedBounds(uint64_t enclave_id, double lower,
                                        double upper) {
  sgx_status_t retval = SGX_SUCCESS;
  sgx_status_t status = SGX_SUCCESS;

  // bool lower_verdict = false;
  // bool upper_verdict = false;
  // checkAllowedSpeed(enclave_id, lower, &lower_verdict);
  // checkAllowedSpeed(enclave_id, upper, &upper_verdict);

  // if (!(lower_verdict && upper_verdict)) {
  //  return CP_INVALID_PARAMETER;
  //}

  status = setInitialSpeedBoundsEnclave(enclave_id, &retval, lower, upper);
  if (status != SGX_SUCCESS) {
    printf("ERROR: setInitialSpeedBounds(), status: %d, enclave: %lu\n", status,
           enclave_id);
    return CP_ERROR;
  }

  return CP_SUCCESS;
}

// Called during initialization, passes the current simulation time + recovery
// phase duration to the enclave so it can set the initial recovery phase
// timeout
commpact_status_t setInitialRecoveryPhaseTimeout(uint64_t enclave_id,
                                                 double timeout) {
  sgx_status_t retval = SGX_SUCCESS;
  sgx_status_t status = SGX_SUCCESS;

  status = setInitialRecoveryPhaseTimeoutEnclave(enclave_id, &retval, timeout);
  if (status != SGX_SUCCESS) {
    printf("ERROR: setInitialRecoveryPhaseTimeout(), enclave: %lu\n",
           enclave_id);
    return CP_ERROR;
  }

  return CP_SUCCESS;
}

// This is the main purpose of the enclave -- to check whether a given speed
// is
// approved, and to deny speed changes if it is not.
// Return true to approve the speed change, and false to reject it.
commpact_status_t checkAllowedSpeed(uint64_t enclave_id, double speed,
                                    bool *verdict) {
  sgx_status_t retval = SGX_SUCCESS;
  sgx_status_t status = SGX_SUCCESS;

  status = checkAllowedSpeedEnclave(enclave_id, &retval, speed, verdict);
  if (status != SGX_SUCCESS) {
    printf("ERROR: checkAllowedSpeed(), enclave: %lu\n", enclave_id);
    return CP_ERROR;
  }

  return CP_SUCCESS;
}

// This function is called when the vehicle sends a contract (either
// newly-created or passed from another vehicle) to the enclave.
// Signatures is an array of length num_signatures of the signatures that have
// already signed the contract.
// If the contract is valid and accepted, it should be signed by this enclave
// and the new signature should be returned by setting return_signature

commpact_status_t newContractChainGetSignatureCommpact(
    uint64_t enclave_id, contract_chain_t contract,
    cp_ec256_signature_t *return_signature, uint8_t num_signatures,
    cp_ec256_signature_t *signatures) {
  sgx_status_t retval = SGX_SUCCESS;
  sgx_status_t status = SGX_SUCCESS;

  printf("commpact: got contract, sending to enclave\n");
  status = newContractChainGetSignatureEnclave(
      enclave_id, &retval, &contract, (sgx_ec256_signature_t *)return_signature,
      (sgx_ec256_signature_t *)signatures, num_signatures);
  printf("commpact: hopefully got signature from enclave %x\n",
         *(unsigned int *)return_signature);
  if (status != SGX_SUCCESS) {
    printf("ERROR: newContractChainGetSignature status = 0x%x\n", status);
    return CP_ERROR;
  }
  if (retval != SGX_SUCCESS) {
    printf("ERROR: newContractChainGetSignature retval = 0x%x\n", retval);
    return CP_ERROR;
  }
  return CP_SUCCESS;
}

// private (static) functions

// debug functions
////////////////////////////////////////////////////////////////////////////////
#ifdef COMMPACT_DEBUG
commpact_status_t validateSignaturesHelper(uint64_t enclave_id,
                                           contract_chain_t *contract,
                                           cp_ec256_signature_t *signatures,
                                           uint8_t num_signatures) {
  sgx_status_t retval = SGX_SUCCESS;
  sgx_status_t status = SGX_SUCCESS;

  status =
      validateSignatures(enclave_id, &retval, contract,
                         (sgx_ec256_signature_t *)signatures, num_signatures);
  if (status != SGX_SUCCESS) {
    printf("ERROR: validateSignaturesHelper(), enclave: %lu\n", enclave_id);
    return CP_ERROR;
  }

  return CP_SUCCESS;
}

commpact_status_t checkParametersHelper(uint64_t enclave_id,
                                        contract_chain_t *contract) {
  sgx_status_t retval = SGX_SUCCESS;
  sgx_status_t status = SGX_SUCCESS;

  status = checkParameters(enclave_id, &retval, contract);
  if (status != SGX_SUCCESS) {
    printf("ERROR: checkParametersHelper(), enclave: %lu\n", enclave_id);
    return CP_ERROR;
  }

  return CP_SUCCESS;
}

commpact_status_t updateParametersHelper(uint64_t enclave_id,
                                         contract_chain_t *contract) {
  sgx_status_t retval = SGX_SUCCESS;
  sgx_status_t status = SGX_SUCCESS;

  status = updateParameters(enclave_id, &retval, contract);
  if (status != SGX_SUCCESS) {
    printf("ERROR: updateParametersHelper(), enclave: %lu\n", enclave_id);
    return CP_ERROR;
  }

  return CP_SUCCESS;
}

commpact_status_t signContractHelper(uint64_t enclave_id,
                                     contract_chain_t *contract,
                                     cp_ec256_signature_t *return_signature) {
  sgx_status_t retval = SGX_SUCCESS;
  sgx_status_t status = SGX_SUCCESS;

  status = signContract(enclave_id, &retval, contract,
                        (sgx_ec256_signature_t *)return_signature);
  if (status != SGX_SUCCESS) {
    printf("ERROR: signContractHelper(), enclave: %lu\n", enclave_id);
    return CP_ERROR;
  }

  return CP_SUCCESS;
}
#endif

////////////////////////////////////////////////////////////////////////////////

// ocalls in enclave
////////////////////////////////////////////////////////////////////////////////
int ocallPrints(const char *str) { printf("%s\n", str); }

int ocallPrintD(double dub) { printf("%f\n", dub); }

int ocallECUMessage(uint64_t enclave_id,
                    sgx_ec256_signature_t *enclave_signature,
                    ecu_message_t *message,
                    sgx_ec256_signature_t *ecu_signature) {
  setParametersECU(INITIAL_SETUP.getPosition(enclave_id),
                   (cp_ec256_signature_t *)enclave_signature, message,
                   (cp_ec256_signature_t *)ecu_signature);
}

int ocallECUSetEnclavePubKey(uint64_t enclave_id,
                             sgx_ec256_public_t *enclave_pub_key) {
  setEnclavePubKey(INITIAL_SETUP.getPosition(enclave_id),
                   (cp_ec256_public_t *)enclave_pub_key);
}
////////////////////////////////////////////////////////////////////////////////
