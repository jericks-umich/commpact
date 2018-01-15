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

// https://software.intel.com/en-us/articles/intel-software-guard-extensions-developing-a-sample-enclave-application

///////////////////////////
// API Exposed Functions //
///////////////////////////
// Initialize instance of crypto enclave
commpact_status_t init_crypto_enclave(uint64_t *e_id,
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
  return CP_SUCCESS;
}

commpact_status_t enclave_status(uint64_t e_id) {
  sgx_enclave_id_t enclave_id = (sgx_enclave_id_t)e_id;
  sgx_status_t status = SGX_SUCCESS;
  sgx_status_t retval = SGX_SUCCESS;
  status = enclave_status(enclave_id, &retval);
  if (status != SGX_SUCCESS) {
    printf("ERROR: failed to check status of SGX crypto enclave.\n");
    return CP_ERROR;
  }
  if (retval != SGX_SUCCESS) {
    printf("WARN: bad status of SGX crypto enclave.\n");
    return CP_WARN;
  }
  return CP_SUCCESS;
}
