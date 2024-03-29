#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
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

#ifdef TIME_ECU
FILE *latencyfd;
#endif
#ifdef TIME_ENCLAVE
FILE *latencyfd2;
#endif
uint32_t start_time() {
  volatile uint32_t time;
  asm __volatile__("  mfence       \n"
                   "  lfence       \n"
                   "  rdtsc        \n"
                   "  lfence       \n"
                   : "=a"(time));
  return time;
}
uint32_t end_time() {
  volatile uint32_t time;
  asm __volatile__("  lfence       \n"
                   "  rdtsc        \n"
                   : "=a"(time));
  return time;
}

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

  // setup socket to talk to ECU
  setupSocket();

#ifdef TIME_ECU
  latencyfd = fopen(DEBUG_ECU_LATENCY_FILENAME, "w");
  if (latencyfd == NULL) {
    printf("error: can't open latency file\n");
    exit(1);
  }
#endif
#ifdef TIME_ENCLAVE
  latencyfd2 = fopen(DEBUG_ENCLAVE_LATENCY_FILENAME, "w");
  if (latencyfd2 == NULL) {
    printf("error: can't open latency file\n");
    exit(1);
  }
#endif

  return CP_SUCCESS;
}

// This position in the platoon is set when the vehicle is initialized.
// Use this function to set the position of this vehicle in the platoon during
// the initial setup
commpact_status_t setInitialPosition(uint64_t enclave_id, uint8_t position) {
  // validate position is between 0 and COMMPACT_MAX_ENCLAVES-1
  if (position >= COMMPACT_MAX_ENCLAVES) {
    return CP_INVALID_PARAMETER;
  }
  sgx_status_t retval = SGX_SUCCESS;
  sgx_status_t status = SGX_SUCCESS;
  status = setPosition(enclave_id, &retval, position);
  if (status != SGX_SUCCESS) {
    printf("failed set position: enclave : %lu, position : %u\n", enclave_id,
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
  // ecu key will be returned to enclave
  status =
      initialEc256KeyPair(enclave_id, &retval, (sgx_ec256_public_t *)pubkey);

  if (status != SGX_SUCCESS) {
    printf("Failed initialize keys\n");
    return CP_ERROR;
  }

  // Part of InitialSetup hack
  // record the enclave_id for this vehicle
  uint8_t position = GET_POSITION(enclave_id);
  if (position != 255) {
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
    cp_ec256_signature_t *signatures, double *compute_time) {
  sgx_status_t retval = SGX_SUCCESS;
  sgx_status_t status = SGX_SUCCESS;

  uint32_t start, end, diff;
  start = start_time();
  status = newContractChainGetSignatureEnclave(
      enclave_id, &retval, &contract, (sgx_ec256_signature_t *)return_signature,
      (sgx_ec256_signature_t *)signatures, num_signatures);
  if (status != SGX_SUCCESS) {
    printf("ERROR: newContractChainGetSignature status = 0x%x\n", status);
    return CP_ERROR;
  }
  if (retval != SGX_SUCCESS) {
    printf("ERROR: newContractChainGetSignature retval = 0x%x\n", retval);
    return CP_ERROR;
  }
  end = end_time();
  if (end < start) {
    diff = end + (1 << 31) - start + (1 << 31);
    *compute_time = ((double)diff) / CPU_TICKS_PER_SEC;
  } else {
    diff = end - start;
    *compute_time = ((double)diff) / CPU_TICKS_PER_SEC;
  }
#ifdef TIME_ENCLAVE
  fprintf(latencyfd2, "%lu: %f\n", enclave_id - 2, *compute_time);
  fflush(latencyfd2);
#endif
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
int ocallPrintI(int i) { printf("%d\n", i); }
int ocallPrintU(unsigned int i) { printf("%u\n", i); }
int ocallPrintX(unsigned int i) { printf("%x\n", i); }

int ocallECUMessage(uint64_t enclave_id,
                    sgx_ec256_signature_t *enclave_signature,
                    ecu_message_t *message,
                    sgx_ec256_signature_t *ecu_signature) {
#ifdef TIME_ECU
  uint32_t start, end, diff;
  double compute_time;
#endif
  if (USING_REAL_ECU) {
#ifdef TIME_ECU
    start = start_time();
#endif
    setParametersRealECU(INITIAL_SETUP.getPosition(enclave_id),
                         (cp_ec256_signature_t *)enclave_signature, message,
                         (cp_ec256_signature_t *)ecu_signature);
#ifdef TIME_ECU
    end = end_time();
#endif
  } else {
#ifdef TIME_ECU
    start = start_time();
#endif
    setParametersECU(INITIAL_SETUP.getPosition(enclave_id),
                     (cp_ec256_signature_t *)enclave_signature, message,
                     (cp_ec256_signature_t *)ecu_signature);
#ifdef TIME_ECU
    end = end_time();
#endif
  }
#ifdef TIME_ECU
  if (end < start) {
    diff = end + (1 << 31) - start + (1 << 31);
    compute_time = ((double)diff) / CPU_TICKS_PER_SEC;
  } else {
    diff = end - start;
    compute_time = ((double)diff) / CPU_TICKS_PER_SEC;
  }
  fprintf(latencyfd, "%f\n", compute_time);
  fflush(latencyfd);
#endif
}

int ocallECUSetGetEnclavePubKey(uint64_t enclave_id,
                                sgx_ec256_public_t *enclave_pub_key,
                                sgx_ec256_public_t *ecu_pub_key) {
  if (USING_REAL_ECU) {
    // printf("Sending pubkey to real ECU\n");
    setGetEnclavePubKeyRealECU(INITIAL_SETUP.getPosition(enclave_id),
                               (cp_ec256_public_t *)enclave_pub_key,
                               (cp_ec256_public_t *)ecu_pub_key);
  } else {
    // printf("Sending pubkey to fake ECU\n");
    setGetEnclavePubKey(INITIAL_SETUP.getPosition(enclave_id),
                        (cp_ec256_public_t *)enclave_pub_key,
                        (cp_ec256_public_t *)ecu_pub_key);
  }
  // TODO: handle ecu communications errors in this function
}

////////////////////////////////////////////////////////////////////////////////
