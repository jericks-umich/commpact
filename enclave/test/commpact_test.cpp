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
retval : int
	0 if success, 1 if fail	
*/
int test_initializeKeys(uint64_t e_id, cp_ec256_public_t *pubkey){

	cp_ec256_public_t pub_keys_generated[TEST_ROUNDS_FOR_KENGEN];
	
	commpact_status_t status = CP_SUCCESS;

	for(int i = 0; i < TEST_ROUNDS_FOR_KENGEN ; ++i ){
		status = initializeKeys(e_id, pub_keys_generated + i);
		if( status != CP_SUCCESS){
			return 1;
		}
		
		//If success, print out the pubkey
		printf("<--%d%s ecc256 key pair generated successfully-->",
			i+1 , i>2?"th":(i>1?"rd":(i>0?"nd":"st")));
		printf("<--Public key value-->");
		for(int j = 0; j < CP_ECP256_KEY_SIZE; ++j ){
			printf("x: %hhu\n",(pub_keys_generated+i)->gx[j]);
			printf("y: %hhu\n",(pub_keys_generated+i)->gy[j]);
		}
		fflush(stdout);
	}
	memcpy(pubkey, &pub_keys_generated[TEST_ROUNDS_FOR_KENGEN-1], sizeof(cp_ec256_public_t));
	return 0;	
}


/*
Test initEnclave
Parameters 
----------
e_id: uint64_t*
	the pointer to a e_id
Returns
-------
retval : int
	0 if success, other number if fail
*/
int test_initEnclave(uint64_t* e_id){
	commpact_status_t status = initEnclave(e_id);
	return status == CP_SUCCESS? 0:1;
}


int main(int argc, char *argv[]) {
  uint64_t enclave_id = 0;
  int test_status = 1;
  cp_ec256_public_t pubkey;
  // Test Enclave Initiation
  printf("<------TESTING ENCLAVE INITIATION------>\n");
  test_status = test_initEnclave(&enclave_id);
  assert(!test_status);
  printf("<------ENCLAVE INITIATION SUCCEED!\n");
  fflush(stdout);

  // Test Enclave Generating ecc256 key pair
  printf("<------TEST GENERATING ECC KEY PAIR----->\n");
  test_status = test_initializeKeys(enclave_id, &pubkey);
  assert(!test_status);
  printf("<------ECC KEY PAIR GENERATED------>\n");
  fflush(stdout);
  return 0;
}
