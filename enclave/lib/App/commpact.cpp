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

#define INITIAL_SETUP InitialSetup::getInstance()
#define GET_POSITION InitialSetup::getInstance().getPosition

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
  sgx_status_t retval = SGX_SUCCESS;
  sgx_status_t status = SGX_SUCCESS;

  status = setPosition(enclave_id, &retval, &position);
  if(status != SGX_SUCCESS){
	printf("failed set position: enclave : %u, position : %d\n", enclave_id, position);
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
	
	status = initialEc256KeyPair(enclave_id, &retval, (sgx_ec256_public_t*)pubkey);
	
	if(status != SGX_SUCCESS){
		printf("Failed initialize keys\n");
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
      setInitialPubKeys(INITIAL_SETUP.enclave_id_list[i],
                        INITIAL_SETUP.pubkey_list, INITIAL_SETUP.n_vehicles);
    }
  }

  return CP_SUCCESS;
}

// Called during initialization, passes a pair of initial speed bounds to the
// enclave for later use in checkAllowedSpeed()
commpact_status_t setInitialSpeedBounds(uint64_t enclave_id, double lower,
                                        double upper) {
  return CP_SUCCESS;
}

// Called during initialization, passes the current simulation time + recovery
// phase duration to the enclave so it can set the initial recovery phase
// timeout
commpact_status_t setInitialRecoveryPhaseTimeout(uint64_t enclave_id,
                                                 double timeout) {
  return CP_SUCCESS;
}

// This is the main purpose of the enclave -- to check whether a given speed
// is
// approved, and to deny speed changes if it is not.
// Return true to approve the speed change, and false to reject it.
commpact_status_t checkAllowedSpeed(uint64_t enclave_id, double speed,
                                    bool *verdict) {
  // TODO
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
	sgx_status_t status = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

  	status = setPubKeys(enclave_id, &retval, (sgx_ec256_public_t*)pubkeys, nkeys);

	if(status != SGX_SUCCESS){
		printf("Set public keys failed\n");
		return CP_ERROR;
	}
	return CP_SUCCESS;
}


//////////////////////
//Ocalls in Enclave///
//////////////////////
int ocallPrints(const char* str){
	printf("The enclave encountered issues: %s\n", str);
}
