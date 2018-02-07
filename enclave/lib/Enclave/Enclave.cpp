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
int position = 0;
sgx_ec256_public_t *pub_keys = NULL;
uint8_t platoon_len = 0;
////////////
// PUBLIC //
////////////

// This is the function to generate a ecc256 key pair.
// When called, generate a key-pair and return the pub_key
sgx_status_t initialEc256KeyPair(sgx_ec256_public_t *pub) {
  int retval = 0;
  sgx_status_t status = SGX_SUCCESS;
  sgx_ecc_state_handle_t ecc_handle;

  // Check if key_pair available
  if (key_pair == NULL) {
    key_pair = (ec256_key_pair_t *)calloc(1, sizeof(ec256_key_pair_t));
    if (key_pair == NULL) {
      char msg[] = "ERROR: allocate memory for key_pair failed.";
      ocallPrints(&retval, msg);
      return SGX_ERROR_OUT_OF_MEMORY;
    }
  }

  // Open ecc256 context
  status = sgx_ecc256_open_context(&ecc_handle);
  if (status != SGX_SUCCESS) {
    char msg[] = "ERROR: open ecc256 context failed";
    ocallPrints(&retval, msg);
    return status;
  }

  // Generating key pair with eec256 context
  status = sgx_ecc256_create_key_pair(&(key_pair->priv), &(key_pair->pub),
                                      ecc_handle);
  if (status != SGX_SUCCESS) {
    char msg[] = "ERROR: generate ecc256 key pair failed";
    ocallPrints(&retval, msg);
    return status;
  }

  // Close ecc256 context
  status = sgx_ecc256_close_context(ecc_handle);
  if (status != SGX_SUCCESS) {
    char msg[] = "ERROR: close ecc256 context failed";
    ocallPrints(&retval, msg);
    return status;
  }

  // Copy pub key to the outside
  memcpy(pub, &(key_pair->pub), sizeof(sgx_ec256_public_t));

  return SGX_SUCCESS;
}

// This is the function to set vehicle's position
sgx_status_t setPosition(int *pos) {
  memcpy(&position, pos, sizeof(int));
  return SGX_SUCCESS;
}

// This is the function to set all pubkeys of vehicles in the platoon
// It takes 2 parameters
// pubkeys : sgx_ec256_public_t pubkeys*
//	A pointer to an array of pubkeys to be set, ordered by position in
// platoon
// platoon_len : uint8_t
//	The length of platoon
sgx_status_t setPubKeys(sgx_ec256_public_t *pub_keys_in,
                        uint8_t platoon_len_in) {
  int retval = 0;

  // Free the memory if it has been allocated previously
  if (pub_keys != NULL) {
    free(pub_keys);
    pub_keys = NULL;
  }

  // Allocate new memory
  pub_keys =
      (sgx_ec256_public_t *)calloc(platoon_len_in, sizeof(sgx_ec256_public_t));
  if (pub_keys == NULL) {
    char msg[] = "ERROR: allocate memory for public keys failed";
    ocallPrints(&retval, msg);
    return SGX_ERROR_INVALID_STATE;
  }

  // Copy the public keys into the inside memory
  memcpy(pub_keys, pub_keys_in, platoon_len_in * sizeof(sgx_ec256_public_t));

  // Set the length of the platoon
  platoon_len = platoon_len_in;

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

// Get position of the enclave
sgx_status_t getPosition(int *pos) {
  memcpy(pos, &position, sizeof(int));
  return SGX_SUCCESS;
}
