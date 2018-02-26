#include <assert.h>
#include <cstdint>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "commpact.h"
#include "commpact_test.h"
#include "include/commpact_types.h"

#define TEST_ROUNDS_FOR_KENGEN                                                 \
  10 // We generate kys for a several rounds to ensure nothing goes wrong

/*
Test initializeKeys() in commpact and print pubkey
Parameters
----------
enclave_id : unit64_t
        the ID of an already initialized enclave
pubkey : cp_ec256_public_t*
        the pointer to a pubkey

Returns
-------
retval : commpact_status_t
*/
commpact_status_t testInitializeKeys(uint64_t e_id, cp_ec256_public_t *pubkey) {

  cp_ec256_public_t pub_keys_generated[TEST_ROUNDS_FOR_KENGEN];

  commpact_status_t status = CP_SUCCESS;
  memset(pub_keys_generated, 0,
         TEST_ROUNDS_FOR_KENGEN * sizeof(cp_ec256_public_t));
  for (int i = 0; i < TEST_ROUNDS_FOR_KENGEN; ++i) {
    status = initializeKeys(e_id, &pub_keys_generated[i]);
    if (status != CP_SUCCESS) {
      return status;
    }

    // If success, print out the pubkey
    printf("<--%d%s ecc256 key pair generated successfully-->", i + 1,
           i > 2 ? "th" : (i > 1 ? "rd" : (i > 0 ? "nd" : "st")));
    printf("<--Public key value-->\n");
    for (int j = 0; j < CP_ECP256_KEY_SIZE; ++j) {
      printf("x: %hhu\n", (pub_keys_generated + i)->gx[j]);
      printf("y: %hhu\n", (pub_keys_generated + i)->gy[j]);
    }
    fflush(stdout);
  }
  memcpy(pubkey, &pub_keys_generated[TEST_ROUNDS_FOR_KENGEN - 1],
         sizeof(cp_ec256_public_t));
  return CP_SUCCESS;
}

/*
Test initEnclave
Parameters
----------
e_id: uint64_t*
        the pointer to a e_id
Returns
-------
retval : commpact_status_t
*/
commpact_status_t testInitEnclave(uint64_t *e_id) {
  commpact_status_t status = initEnclaveWithFilename(e_id, ENCLAVE_FILENAME);
  return status;
}

int main(int argc, char *argv[]) {
  // uint64_t enclave_id = 0;
  // int test_status = 1;
  // cp_ec256_public_t pubkey;
  // Test Enclave Initiation
  // printf("<------TESTING ENCLAVE INITIATION------>\n");
  // test_status = testInitEnclave(&enclave_id);
  // assert(test_status == CP_SUCCESS);
  // printf("<------ENCLAVE INITIATION SUCCEED!\n");
  // fflush(stdout);

  // Test Enclave Generating ecc256 key pair
  // printf("<------TEST GENERATING ECC KEY PAIR----->\n");
  // test_status = testInitializeKeys(enclave_id, &pubkey);
  // assert(test_status == CP_SUCCESS);
  // printf("<------ECC KEY PAIR GENERATED------>\n");
  // fflush(stdout);
  uint64_t ids[MAX_PLATOON_VEHICLES];
  cp_ec256_public_t enclave_pub_keys[MAX_PLATOON_VEHICLES];
  for (unsigned int i = 0; i < MAX_PLATOON_VEHICLES; ++i) {
    commpact_status_t status = initEnclave(ids + i);
    if (status == CP_SUCCESS) {
      printf("%lu enclave init succeed\n", ids[i]);
    } else {
      printf("%lu enclave init failed\n", ids[i]);
      exit(1);
    }
  }

  for (int i = 0; i < MAX_PLATOON_VEHICLES; ++i) {
    commpact_status_t status = setInitialPosition(ids[i], i);
    if (status == CP_SUCCESS) {
      printf("%lu enclave set init position succeed\n", ids[i]);
    } else {
      printf("%lu enclave set init postion failed\n", ids[i]);
      exit(1);
    }
  }

  for (int i = 0; i < MAX_PLATOON_VEHICLES; ++i) {
    commpact_status_t status = initializeKeys(ids[i], enclave_pub_keys + i);
    if (status == CP_SUCCESS) {
      printf("%lu enclave init key succeed\n", ids[i]);
    } else {
      printf("%lu enclave init key failed\n", ids[i]);
      exit(1);
    }
  }

  for (int i = 0; i < MAX_PLATOON_VEHICLES; ++i) {
    commpact_status_t status = setInitialSpeedBounds(ids[i], 10, 20);
    if (status == CP_SUCCESS) {
      printf("%lu enclave init speed bounds succeed\n", ids[i]);
    } else {
      printf("%lu enclave init speed bounds failed\n", ids[i]);
      exit(1);
    }
  }

  for (int i = 0; i < MAX_PLATOON_VEHICLES; ++i) {
    commpact_status_t status = setInitialRecoveryPhaseTimeout(ids[i], 10);
    if (status == CP_SUCCESS) {
      printf("%lu enclave init recovery timeout succeed\n", ids[i]);
    } else {
      printf("%lu enclave init revovery timeout failed\n", ids[i]);
      exit(1);
    }
  }

  for (int i = 0; i < MAX_PLATOON_VEHICLES; ++i) {
    bool verdict = false;
    commpact_status_t status = checkAllowedSpeed(ids[i], 15, &verdict);
    if (!verdict || status != CP_SUCCESS) {
      printf("%lu enclave check speed fail\n", ids[i]);
      exit(1);
    }
    status = checkAllowedSpeed(ids[i], 25, &verdict);
    if (verdict || status != CP_SUCCESS) {
      printf("%lu enclave check speed fail\n", ids[i]);
      exit(1);
    }
    printf("%lu enclave check speed succeed\n", ids[i]);
  }

  contract_chain_t contract;
  contract.contract_id = 1;
  contract.seq_num = 1;
  contract.sent_time = 0;
  contract.valid_time = 1;
  contract.recovery_phase_timeout = 3;
  contract.contract_type = 0x0;
  contract.chain_length = MAX_PLATOON_VEHICLES + 1;
  for (int i = 0; i < MAX_PLATOON_VEHICLES; ++i) {
    contract.chain_order[i] = i;
  }
  contract.chain_order[MAX_PLATOON_VEHICLES] = 0;
  contract.upper_speed = 22;
  contract.lower_speed = 12;
  contract.upper_accel = 3;
  contract.lower_accel = 2;
  contract.max_decel = 2;
  cp_ec256_signature_t signatures[MAX_PLATOON_VEHICLES + 1];

  for (int i = 0; i < MAX_PLATOON_VEHICLES; ++i) {
    commpact_status_t status = newContractChainGetSignatureCommpact(
        ids[contract.chain_order[i]], contract, signatures + i, i, signatures);
    if (status == CP_SUCCESS) {
      printf("%lu enclave get signature succeed\n",
             ids[contract.chain_order[i]]);
    } else {
      printf("%lu enclave get signature failed\n",
             ids[contract.chain_order[i]]);

      exit(1);
    }
  }
  return 0;
}
