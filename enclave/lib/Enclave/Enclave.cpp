#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sgx_error.h"
#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"

#include "Enclave.h"
#include "Enclave_t.h"

////////////
// PUBLIC //
////////////

/////////////
// PRIVATE //
/////////////

//////////////////
// PUBLIC DEBUG //
//////////////////

sgx_status_t enclave_status() {
  int rand[1] = {0};
  sgx_read_rand((unsigned char *)rand, sizeof(unsigned int));
  int passfail = *rand % 2;
  return passfail ? SGX_SUCCESS : SGX_ERROR_INVALID_STATE;
}
