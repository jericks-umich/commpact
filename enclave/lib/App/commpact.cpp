#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "sgx_eid.h"
#include "sgx_error.h"
#include "sgx_tcrypto.h"
#include "sgx_urts.h"

#include "Enclave_u.h"
#include "commpact.h"
#include "initialsetup.h"

// https://software.intel.com/en-us/articles/intel-software-guard-extensions-developing-a-sample-enclave-application

///////////////////////////
// API Exposed Functions //
///////////////////////////
// Initialize instance of crypto enclave
commpact_status_t initEnclave(uint64_t *e_id) {
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
  ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated,
                           enclave_id, NULL);
  if (ret != SGX_SUCCESS) {
    printf("ERROR: failed (%x) to initialize SGX crypto enclave.\n", ret);
    return CP_ERROR;
  }

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

  // Part of InitialSetup hack
  // record the enclave_id for this vehicle
  InitialSetup::getInstance().enclave_id_list[position] = enclave_id;
  InitialSetup::getInstance().used_list[position] = true;
  InitialSetup::getInstance().n_vehicles++;

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
  // generate keypair in enclave here

  // Part of InitialSetup hack
  // record the enclave_id for this vehicle
  for (int i = 0; i < COMMPACT_MAX_ENCLAVES; i++) {
    // iterate over enclave_ids to find position (index i)
    if (InitialSetup::getInstance().enclave_id_list[i] == enclave_id) {
      // store a copy of the pubkey in the i'th position of the pubkey_list
      memcpy(&InitialSetup::getInstance().pubkey_list[i], pubkey,
             sizeof(cp_ec256_public_t));
      break;
    }
  }

  // Since we've updated the list of public keys, we should update each enclave
  // with the new list
  for (int i = 0; i < COMMPACT_MAX_ENCLAVES; i++) {
    if (InitialSetup::getInstance().used_list[i]) {
      // We're making an assumption here that the first N positions in this
      // list are filled. If this assumption doesn't hold true for the first
      // few vehicles, that should be okay. When we add the last vehicle, it
      // should be a contiguous list of pubkeys and should overwrite and
      // previous sparse list we told the enclave about.
      setInitialPubKeys(enclave_id, InitialSetup::getInstance().pubkey_list,
                        InitialSetup::getInstance().n_vehicles);
    }
  }

  return CP_SUCCESS;
}

// This is the main purpose of the enclave -- to check whether a given speed
// is
// approved, and to deny speed changes if it is not.
// Return true to approve the speed change, and false to reject it.
commpact_status_t checkAllowedSpeed(uint64_t enclave_id, double speed,
                                    bool *verdict) {
  *verdict = true;
  return CP_SUCCESS;
}

///////////////////////
// Private Functions //
///////////////////////

// pass a list of pubkeys to the enclave for all the other vehicles in the
// platoon.
// the enclave's own pubkey will be present in the list, but can be ignored.
static commpact_status_t
setInitialPubKeys(uint64_t enclave_id, cp_ec256_public_t *pubkeys, int nkeys) {
  return CP_SUCCESS;
}
