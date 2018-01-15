#include <cstdint>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "commpact.h"
#include "include/commpact_status.h"

#include "commpact_test.h"

int main(int argc, char *argv[]) {
  uint64_t enclave_id = 0;
  commpact_status_t cp_status = CP_SUCCESS;

  // Init Crypto SGX Enclave
  cp_status = init_crypto_enclave(&enclave_id, ENCLAVE_FILENAME);
  printf("init status = %s, enclave_id = %lu\n",
         cp_status == CP_SUCCESS ? "success" : "fail", enclave_id);

  // check status (dummy function)
  cp_status = enclave_status(enclave_id);
  printf("check status = %s\n", cp_status == CP_SUCCESS ? "success" : "fail");

  return 0;
}
