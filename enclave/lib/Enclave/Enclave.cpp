#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sgx_error.h"
#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"

#include "Enclave.h"
#include "Enclave_t.h"

ec256_key_pair_t *key_pair = NULL; // Global EC256 cache
////////////
// PUBLIC //
////////////

//This is the function to generate a ecc256 key pair.
//When called, generate a key-pair and return the pub_key 
sgx_status_t initial_ec256_key_pair(sgx_ec256_public_t* pub){
	int retval = 0;
	int key_byte_index = 0; //index to the key byte in pub or priv in key_pair
	sgx_status_t status = SGX_SUCCESS;
	sgx_ecc_state_handle_t ecc_handle;
	
	//Check if key_pair available
	if(key_pair == NULL){
		key_pair = (ec256_key_pair_t*) calloc(1,sizeof(ec256_key_pair_t));
		if(key_pair == NULL){
			char msg[] = "ERROR: allocate memory for key_pair failed.";
			ocall_prints(&retval, msg);
			return SGX_ERROR_OUT_OF_MEMORY;
		}  
	}

	//Open ecc256 context
	status = sgx_ecc256_open_context(&ecc_handle);
	if( status != SGX_SUCCESS ){
		char msg[] = "ERROR: failed to open ecc256 context";
		ocall_prints(&retval, msg);
		return status;
	}

	//Generating key pair with eec256 context
	status = sgx_ecc256_create_key_pair(&(key_pair->priv), &(key_pair->pub),ecc_handle);
	if(status != SGX_SUCCESS){
		char msg[] = "ERROR: failed to generate ecc256 key pair";
		ocall_prints(&retval, msg);
		return status;
	}

	//Close ecc256 context
	status = sgx_ecc256_close_context(ecc_handle);
	if(status != SGX_SUCCESS){
		char msg[] = "ERROR: failed to close ecc256 context";
		ocall_prints(&retval, msg);
		return status;
	} 

	//Copy pub key to the outside
	memcpy(pub, &(key_pair->pub),sizeof(sgx_ec256_public_t));

	return SGX_SUCCESS;
}	

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
