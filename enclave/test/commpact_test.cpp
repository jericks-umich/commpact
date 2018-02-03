#include <cstdint>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>


#include "commpact.h"
#include "include/commpact_types.h"

#include "commpact_test.h"

#define TEST_ROUNDS_FOR_KENGEN 10 //We generate kys for a several rounds to ensure nothing goes wrong

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
commpact_status_t testInitializeKeys(uint64_t e_id, cp_ec256_public_t *pubkey){

	cp_ec256_public_t pub_keys_generated[TEST_ROUNDS_FOR_KENGEN];
	
	commpact_status_t status = CP_SUCCESS;
	memset(pub_keys_generated, 0 , TEST_ROUNDS_FOR_KENGEN*sizeof(cp_ec256_public_t));
	for(int i = 0; i < TEST_ROUNDS_FOR_KENGEN ; ++i ){
		status = initializeKeys(e_id, &pub_keys_generated[i]);
		if( status != CP_SUCCESS){
			return status;
		}
		
		//If success, print out the pubkey
		printf("<--%d%s ecc256 key pair generated successfully-->",
			i+1 , i>2?"th":(i>1?"rd":(i>0?"nd":"st")));
		printf("<--Public key value-->\n");
		for(int j = 0; j < CP_ECP256_KEY_SIZE; ++j ){
			printf("x: %hhu\n",(pub_keys_generated+i)->gx[j]);
			printf("y: %hhu\n",(pub_keys_generated+i)->gy[j]);
		}
		fflush(stdout);
	}
	memcpy(pubkey, &pub_keys_generated[TEST_ROUNDS_FOR_KENGEN-1], sizeof(cp_ec256_public_t));
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
commpact_status_t testInitEnclave(uint64_t* e_id){
	commpact_status_t status = initEnclave(e_id);
	return status;
}


int main(int argc, char *argv[]) {
  uint64_t enclave_id = 0;
  int test_status = 1;
  cp_ec256_public_t pubkey;
  // Test Enclave Initiation
  printf("<------TESTING ENCLAVE INITIATION------>\n");
  test_status = testInitEnclave(&enclave_id);
  assert(test_status == CP_SUCCESS);
  printf("<------ENCLAVE INITIATION SUCCEED!\n");
  fflush(stdout);

  // Test Enclave Generating ecc256 key pair
  printf("<------TEST GENERATING ECC KEY PAIR----->\n");
  test_status = testInitializeKeys(enclave_id, &pubkey);
  assert(test_status == CP_SUCCESS);
  printf("<------ECC KEY PAIR GENERATED------>\n");
  fflush(stdout);
  return 0;
}
