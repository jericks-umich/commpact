#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "sgx_error.h"
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"

#include "Enclave_t.h"
#include "Enclave.h"

////////////
// PUBLIC //
////////////

ec256_key_handle_t *ec256_key_handles = NULL; // Global EC256 Key Store Cache

sgx_status_t generate_ec256_key_pair( sgx_ec256_public_t* pub ){
	int retval			= 0;  // debug print return value
	int key_index 		= 0;  // index handle to ec256 key pair in key store
	int key_byte_index 	= 0;  // index to key byte in pub or priv ec256 key
	int free_key_handle = -1; // index to next available ec256 key pair bin in key store
	sgx_status_t status = SGX_SUCCESS;  // SGX status value
	sgx_ecc_state_handle_t 	ecc_handle; // handle to SGX EC context

	// Check if Cached Key Handles Available
	if ( ec256_key_handles == NULL ){
		ec256_key_handles = (ec256_key_handle_t*)calloc(NUMBER_OF_EC256_KEY_PAIRS,sizeof( ec256_key_handle_t ));
		if ( ec256_key_handles == NULL ){
			char msg[] = "ERROR: could not allocate memory for key pair store cache.";
			ocall_prints( &retval, msg );
			return SGX_ERROR_OUT_OF_MEMORY;
		}

		// Try to load existing sealed keys from disk
		if ( load_ec256_keys() != SGX_SUCCESS ){
			// Initialize cached EC256 key store
			//char msg1[] = "Could not load sealed keys from disk. Initializing new EC256 key store cache...";
			//ocall_prints(&retval, msg1);
		}
	}

	// Generate a new EC256 key pair, add to cached key store, and backup on disk
	//char msg2[] = "Creating new EC256 key pair...";
	//ocall_prints(&retval, msg2);


	// Find first key pair handle not in use, scaning through all to eliminate timing side channel
	free_key_handle = -1;
	for ( key_index = 0; key_index < NUMBER_OF_EC256_KEY_PAIRS; key_index++ ){
		if ( ec256_key_handles[ key_index ].in_use == false && free_key_handle == -1 ){
			free_key_handle = key_index;
		}
	}
	sgx_ec256_private_t *private_key 		 	= &ec256_key_handles[ free_key_handle ].key_pair.priv;
	sgx_ec256_public_t  *public_key  			= &ec256_key_handles[ free_key_handle ].key_pair.pub;

	// Open ECC256 context
	status = sgx_ecc256_open_context(&ecc_handle);
	if ( status != SGX_SUCCESS ){
		return status;
	}

	// Generate ECC256 key pair with ECC256 context, caching in key store
	status = sgx_ecc256_create_key_pair(private_key, public_key, ecc_handle);
	if ( status != SGX_SUCCESS ){
		return status;
	}

	// Close ECC256 context
	status = sgx_ecc256_close_context(ecc_handle);
	if ( status != SGX_SUCCESS ){
		return status;
	}

	// Back up modified EC256 key store on disk
	if ( store_ec256_keys() != SGX_SUCCESS ){
		// Do not save newly generated key pair if it cannot be backed up on disk (line 93 marks the key as valid)
		char msg3[] = "ERROR: unable to backup EC256 key store on disk.\n    New EC256 key pair destroyed.";
		ocall_prints(&retval, msg3);
		return status;
	}

	// Copy memory of public key to return buffer and return
	ec256_key_handles[ free_key_handle ].in_use = true;
	memcpy(pub, public_key, sizeof(sgx_ec256_public_t));

	//char msg4[] = "SUCCESS: generated new EC256 key pair and added to key store.";
	//ocall_prints(&retval, msg4);
	return SGX_SUCCESS;
}

// pub is input for finding the keypair to delete them
sgx_status_t delete_ec256_key_pair( sgx_ec256_public_t* pub ){
	int retval				 = 0; 			 // debug print return value
	int key_index 			 = 0; 			 // index handle to ec256 key pair in key store
	int key_to_delete_handle = -1; 			 // index to next available ec256 key pair bin in key store
	sgx_status_t status 	 = SGX_SUCCESS;  // SGX status value

	// Check if Cached Key Handles Available
	if ( ec256_key_handles == NULL ){
		// Allocate memory for EC256 key store cache
		ec256_key_handles = (ec256_key_handle_t*)malloc( NUMBER_OF_EC256_KEY_PAIRS*sizeof( ec256_key_handle_t ));
		if ( ec256_key_handles == NULL ){
			char msg[] = "ERROR: could not allocate memory for key pair store cache.";
			ocall_prints( &retval, msg );
			return SGX_ERROR_OUT_OF_MEMORY;
		}
		
		// Try to load existing sealed keys from disk
		if ( load_ec256_keys() != SGX_SUCCESS ){
			free( ec256_key_handles );
			char msg1[] = "WARNING: no EC256 key store to delete key from.";
			ocall_prints( &retval, msg1 );
			return SGX_ERROR_INVALID_STATE;
		}
	}

	// Iterate through key store to delete key pair, go through all keys to eliminate timing side channel
	key_to_delete_handle = -1;
	for ( key_index = 0; key_index < NUMBER_OF_EC256_KEY_PAIRS; key_index++ ){
		if ( memcmp( pub, &ec256_key_handles[ key_index ].key_pair.pub, sizeof(sgx_ec256_public_t) ) == 0 &&
			ec256_key_handles[ key_index ].in_use == true){

			// Only mark one key handle to be deleted (in case where pub key passed in is all 0s)
			if ( key_to_delete_handle == -1 ){
				key_to_delete_handle = key_index;
			}
		}
	}

	// Delete key pair by marking it available for use
	ec256_key_handles[ key_to_delete_handle ].in_use = false;

	// Write modified key store to disk
	if ( store_ec256_keys() != SGX_SUCCESS ){
		// Do not delete generated key pair if it cannot be coherent on disk
		ec256_key_handles[ key_to_delete_handle ].in_use = true;
		char msg2[] = "ERROR: unable to write modified EC256 key store to disk.\n    EC256 key pair NOT deleted.";
		ocall_prints( &retval, msg2 );
		return status;
	}

	return SGX_SUCCESS;
}

sgx_status_t delete_all_ec256_key_pairs(){
	int retval  		   	   = 0; 
	jalapeno_status_t j_status = J_SUCCESS; 

	free( ec256_key_handles );
	ec256_key_handles = NULL;
	ocall_delete_sealed_keys_file( &j_status );
	//char msg1[] = "Deleted sealed key store file.";
	//ocall_prints( &retval, msg1 );

	return SGX_SUCCESS;
}

// for description, see Enclave.edl
sgx_status_t encrypt_aes_gcm(sgx_aes_gcm_128bit_tag_t* tag, 
		uint8_t* ciphertext, uint8_t* plaintext, uint32_t plaintext_len, 
		sgx_ec256_public_t* server_pubkey, sgx_ec256_public_t* client_pubkey, 
		uint8_t* server_random, uint32_t server_random_len, uint8_t* client_random, uint32_t client_random_len,
		uint8_t is_client) {

	sgx_status_t status;
	int retval;
	
	// retrieve local privkey associated with this pubkey
	sgx_ec256_private_t local_privkey;
	if (is_client == 1) {
		status = get_privkey(&local_privkey, client_pubkey);
	} else {
		status = get_privkey(&local_privkey, server_pubkey);
	}
	if (status != SGX_SUCCESS) {
		char msg1[] = "ERROR: Could not retrieve private key associated with local pubkey.";
		ocall_prints(&retval, msg1);
		return status;
	}

	// generate pre-master secret from the local privkey and remote pubkey
	sgx_ec256_dh_shared_t premaster_secret;
	sgx_ecc_state_handle_t 	ecc_handle;
	status = sgx_ecc256_open_context(&ecc_handle);
	if ( status != SGX_SUCCESS ){
		return status;
	}
	if (is_client == 1) {
		status = sgx_ecc256_compute_shared_dhkey(&local_privkey, server_pubkey, &premaster_secret, ecc_handle);
	} else {
		status = sgx_ecc256_compute_shared_dhkey(&local_privkey, client_pubkey, &premaster_secret, ecc_handle);
	}
	if ( status != SGX_SUCCESS ){
		return status;
	}
	status = sgx_ecc256_close_context(ecc_handle);
	if ( status != SGX_SUCCESS ){
		return status;
	}

	// generate master secret from pre-master secret and server/client random bytes
	uint8_t master_secret[MASTER_SECRET_SIZE];
#define MASTER_SECRET_STR "master secret"
	uint32_t seed_len = sizeof(MASTER_SECRET_STR) + server_random_len + client_random_len;
	uint8_t seed[seed_len];
	memcpy(seed, MASTER_SECRET_STR, sizeof(MASTER_SECRET_STR));
	memcpy(seed+sizeof(MASTER_SECRET_STR), client_random, client_random_len);
	memcpy(seed+sizeof(MASTER_SECRET_STR)+client_random_len, server_random, server_random_len);
	prf_sha256(master_secret, MASTER_SECRET_SIZE, premaster_secret.s, sizeof(premaster_secret), seed, seed_len);

	// generate client/server keys from master secret
	uint32_t secret_data_size = (2*SGX_SHA256_HASH_SIZE) + (2*SGX_AESGCM_KEY_SIZE) + (2*SGX_AESGCM_IV_SIZE);
	uint8_t secret_data[secret_data_size];
#define SECRET_KEYS_STR "key expansion"
	uint32_t key_str_len = sizeof(SECRET_KEYS_STR) + server_random_len + client_random_len;
	uint8_t key_str[key_str_len];
	memcpy(key_str, SECRET_KEYS_STR, sizeof(SECRET_KEYS_STR));
	memcpy(key_str+sizeof(SECRET_KEYS_STR), server_random, server_random_len);
	memcpy(key_str+sizeof(SECRET_KEYS_STR)+server_random_len, client_random, client_random_len);
	prf_sha256(secret_data, secret_data_size, master_secret, MASTER_SECRET_SIZE, key_str, key_str_len);
	// grab client/server MAC secret
	uint8_t* client_mac = secret_data;
	uint8_t* server_mac = secret_data + SGX_SHA256_HASH_SIZE;
	// grab client/server write key
	uint8_t* client_write_key = secret_data + (2*SGX_SHA256_HASH_SIZE);
	uint8_t* server_write_key = secret_data + (2*SGX_SHA256_HASH_SIZE) + SGX_AESGCM_KEY_SIZE;
	// grab client/server IV
	uint8_t* client_iv = secret_data + (2*SGX_SHA256_HASH_SIZE) + (2*SGX_AESGCM_KEY_SIZE);
	uint8_t* server_iv = secret_data + (2*SGX_SHA256_HASH_SIZE) + (2*SGX_AESGCM_KEY_SIZE) + SGX_AESGCM_IV_SIZE;

	// encrypt plaintext with appropriate key and store in ciphertext
	uint8_t* encrypt_key;
	uint8_t* encrypt_iv;
	if (is_client == 1) {
		encrypt_key = client_write_key;
		encrypt_iv = client_iv;
	} else {
		encrypt_key = server_write_key;
		encrypt_iv = server_iv;
	}
	status = sgx_rijndael128GCM_encrypt((sgx_aes_gcm_128bit_key_t*) encrypt_key,
			plaintext, plaintext_len, ciphertext, encrypt_iv, SGX_AESGCM_IV_SIZE, NULL, 0, tag);
	if ( status != SGX_SUCCESS ){
		char msg2[] = "ERROR: could not turn plaintext into ciphertext.";
		ocall_prints(&retval, msg2);
		return status;
	}

	return SGX_SUCCESS;
}

sgx_status_t decrypt_aes_gcm(sgx_aes_gcm_128bit_tag_t* tag, 
		uint8_t* ciphertext, uint8_t* plaintext, uint32_t plaintext_len, 
		sgx_ec256_public_t* server_pubkey, sgx_ec256_public_t* client_pubkey, 
		uint8_t* server_random, uint32_t server_random_len, uint8_t* client_random, uint32_t client_random_len,
		uint8_t is_client) {

	sgx_status_t status;
	int retval;
	
	// retrieve local privkey associated with this pubkey
	sgx_ec256_private_t local_privkey;
	if (is_client == 1) {
		status = get_privkey(&local_privkey, client_pubkey);
	} else {
		status = get_privkey(&local_privkey, server_pubkey);
	}
	if (status != SGX_SUCCESS) {
		char msg1[] = "ERROR: Could not retrieve private key associated with local pubkey.";
		ocall_prints(&retval, msg1);
		return status;
	}

	// generate pre-master secret from the local privkey and remote pubkey
	sgx_ec256_dh_shared_t premaster_secret;
	sgx_ecc_state_handle_t 	ecc_handle;
	status = sgx_ecc256_open_context(&ecc_handle);
	if ( status != SGX_SUCCESS ){
		return status;
	}
	if (is_client == 1) {
		status = sgx_ecc256_compute_shared_dhkey(&local_privkey, server_pubkey, &premaster_secret, ecc_handle);
	} else {
		status = sgx_ecc256_compute_shared_dhkey(&local_privkey, client_pubkey, &premaster_secret, ecc_handle);
	}
	if ( status != SGX_SUCCESS ){
		return status;
	}
	status = sgx_ecc256_close_context(ecc_handle);
	if ( status != SGX_SUCCESS ){
		return status;
	}

	// generate master secret from pre-master secret and server/client random bytes
	uint8_t master_secret[MASTER_SECRET_SIZE];
#define MASTER_SECRET_STR "master secret"
	uint32_t seed_len = sizeof(MASTER_SECRET_STR) + server_random_len + client_random_len;
	uint8_t seed[seed_len];
	memcpy(seed, MASTER_SECRET_STR, sizeof(MASTER_SECRET_STR));
	memcpy(seed+sizeof(MASTER_SECRET_STR), client_random, client_random_len);
	memcpy(seed+sizeof(MASTER_SECRET_STR)+client_random_len, server_random, server_random_len);
	prf_sha256(master_secret, MASTER_SECRET_SIZE, premaster_secret.s, sizeof(premaster_secret), seed, seed_len);

	// generate client/server keys from master secret
	uint32_t secret_data_size = (2*SGX_SHA256_HASH_SIZE) + (2*SGX_AESGCM_KEY_SIZE) + (2*SGX_AESGCM_IV_SIZE);
	uint8_t secret_data[secret_data_size];
#define SECRET_KEYS_STR "key expansion"
	uint32_t key_str_len = sizeof(SECRET_KEYS_STR) + server_random_len + client_random_len;
	uint8_t key_str[key_str_len];
	memcpy(key_str, SECRET_KEYS_STR, sizeof(SECRET_KEYS_STR));
	memcpy(key_str+sizeof(SECRET_KEYS_STR), server_random, server_random_len);
	memcpy(key_str+sizeof(SECRET_KEYS_STR)+server_random_len, client_random, client_random_len);
	prf_sha256(secret_data, secret_data_size, master_secret, MASTER_SECRET_SIZE, key_str, key_str_len);
	// grab client/server MAC secret
	uint8_t* client_mac = secret_data;
	uint8_t* server_mac = secret_data + SGX_SHA256_HASH_SIZE;
	// grab client/server write key
	uint8_t* client_write_key = secret_data + (2*SGX_SHA256_HASH_SIZE);
	uint8_t* server_write_key = secret_data + (2*SGX_SHA256_HASH_SIZE) + SGX_AESGCM_KEY_SIZE;
	// grab client/server IV
	uint8_t* client_iv = secret_data + (2*SGX_SHA256_HASH_SIZE) + (2*SGX_AESGCM_KEY_SIZE);
	uint8_t* server_iv = secret_data + (2*SGX_SHA256_HASH_SIZE) + (2*SGX_AESGCM_KEY_SIZE) + SGX_AESGCM_IV_SIZE;

	// decrypt ciphertext with appropriate key and store in plaintext
	uint8_t* decrypt_key;
	uint8_t* decrypt_iv;
	if (is_client == 1) {
		decrypt_key = server_write_key;
		decrypt_iv = server_iv;
	} else {
		decrypt_key = client_write_key;
		decrypt_iv = client_iv;
	}
	status = sgx_rijndael128GCM_decrypt((sgx_aes_gcm_128bit_key_t*) decrypt_key,
			ciphertext, plaintext_len, plaintext, decrypt_iv, SGX_AESGCM_IV_SIZE, NULL, 0, tag);
	if ( status != SGX_SUCCESS ){
		char msg2[] = "ERROR: could not turn ciphertext into plaintext.";
		ocall_prints(&retval, msg2);
		return status;
	}

	return SGX_SUCCESS;
}

/////////////
// PRIVATE //
/////////////

// look up private key associated with given public key
sgx_status_t get_privkey(sgx_ec256_private_t* privkey, sgx_ec256_public_t* pubkey) {
	sgx_status_t status;
	int retval;
	uint8_t found_it = 0;
	// check to make sure the keys are loaded into memory
	//  if not, try to load them from disk
	//   if that fails, return error
	if (ec256_key_handles == NULL) {
		status = load_ec256_keys();
		if (status != SGX_SUCCESS) {
			return status;
		}
	}

	// iterate over all keypairs (DON'T RETURN EARLY) and store a copy of the correct privkey into the return variable
	for (int i=0; i<NUMBER_OF_EC256_KEY_PAIRS; i++) {
		if ((0 == memcmp(pubkey, &ec256_key_handles[i].key_pair.pub, sizeof(sgx_ec256_public_t))) &&
				(ec256_key_handles[i].in_use == true)) {
			found_it = 1;
			memcpy(privkey, &ec256_key_handles[i].key_pair.priv, sizeof(sgx_ec256_private_t));
			// don't break/return early!
		}
	}

	if (found_it == 0) {
		char msg[] = "ERROR: could not find privkey associated with pubkey.";
		ocall_prints(&retval, msg);
		return SGX_ERROR_INVALID_STATE;
	}
	return SGX_SUCCESS;
}

sgx_status_t load_ec256_keys(){
	int 					retval 	 = 0; 	 		// debug print return value
	jalapeno_status_t 		j_status = J_SUCCESS; 	// custom status value
	sgx_status_t 			status   = SGX_SUCCESS; // SGX status value
	sgx_ecc_state_handle_t 	ecc_handle;
	uint32_t 				ec256_key_handles_length = NUMBER_OF_EC256_KEY_PAIRS * sizeof( ec256_key_handle_t );
	uint32_t 				seal_size = 0;
	sgx_sealed_data_t* 		sealed_data;

	// #define MAC_TEXT "JALAPENO v1.0"
	// uint8_t mac_text[sizeof(MAC_TEXT)];
	// uint8_t mac_text_check[sizeof(MAC_TEXT)];
	// memcpy(mac_text, MAC_TEXT, sizeof(MAC_TEXT));
	// uint32_t mac_text_len = sizeof(MAC_TEXT);

	// calculate how much space the sealed keys will take
	//seal_size = sgx_calc_sealed_data_size( mac_text_len, ec256_key_handles_length );
	seal_size = sgx_calc_sealed_data_size( 0, ec256_key_handles_length );
	if (seal_size == UINT32_MAX ){
		return SGX_ERROR_OUT_OF_MEMORY;
	}
	
	// attempt to load sealed keys from disk
	sealed_data = (sgx_sealed_data_t*) malloc( seal_size );
	if ( sealed_data == NULL ){
		char msg[] = "ERROR: could not allocate memory for sealed data.";
		ocall_prints( &retval, msg );
		return SGX_ERROR_OUT_OF_MEMORY;
	}
	status = ocall_load_sealed_keys( &j_status, (uint8_t*) sealed_data, seal_size );
	if ( status != SGX_SUCCESS ){
		free( sealed_data );
		char msg1[] = "ERROR: could not retrieved sealed EC256 keys from disk.";
		ocall_prints( &retval, msg1 );
		return status;
	}
	else if ( j_status == J_CANT_OPEN_FILE ){
		free( sealed_data );
		//char msg2[] = "WARNING: problem opening sealed EC256 keys file from disk.";
		//ocall_prints( &retval, msg2 );
		return SGX_ERROR_INVALID_STATE;
	}
	//char msg3[] = "SUCCESS: retrieved sealed EC256 keys from disk.";
	//ocall_prints( &retval, msg3 );

	// attempt to unseal and cache successfully loaded key data
	//status = sgx_unseal_data(sealed_data, mac_text_check, &mac_text_len, (uint8_t*)ec256_key_handles, &ec256_key_handles_length);
	status = sgx_unseal_data( sealed_data, NULL, 0, (uint8_t*)ec256_key_handles, &ec256_key_handles_length );
	free( sealed_data );
	if ( status != SGX_SUCCESS ){
		char msg4[] = "ERROR: could not unseal EC256 keys.";
		ocall_prints( &retval, msg4 );
		return status;
	}
	// check if mac_text matches
	//if (memcmp( mac_text, mac_text_check, mac_text_len ) != 0) {
	//  return SGX_ERROR_UNEXPECTED;
	//}
	//char msg5[] = "SUCCESS: unsealed and cached EC256 keys.";
	//ocall_prints( &retval, msg5 );	
	return SGX_SUCCESS;
}

// Seal and store EC256 keys to disk
sgx_status_t store_ec256_keys(){
	int 					retval 	 = 0; 	 		// debug print return value
	jalapeno_status_t 		j_status = J_SUCCESS; 		// custom status value
	sgx_status_t 			status   = SGX_SUCCESS; // SGX status value

	sgx_ecc_state_handle_t 	ecc_handle 				 = NULL;
	uint32_t 				ec256_key_handles_length = NUMBER_OF_EC256_KEY_PAIRS * sizeof( ec256_key_handle_t );
	uint32_t 				seal_size 				 = 0;
	sgx_sealed_data_t* 		sealed_data 			 = NULL;

	// #define MAC_TEXT "JALAPENO v1.0"
	// uint8_t mac_text[sizeof(MAC_TEXT)];
	// uint8_t mac_text_check[sizeof(MAC_TEXT)];
	// memcpy(mac_text, MAC_TEXT, sizeof(MAC_TEXT));
	// uint32_t mac_text_len = sizeof(MAC_TEXT);

	// calculate how much space the sealed EC256 keys will take
	seal_size = sgx_calc_sealed_data_size( 0, ec256_key_handles_length );
	if (seal_size == UINT32_MAX) {
		return SGX_ERROR_OUT_OF_MEMORY;
	}

	// seal cached EC256 key store
	sealed_data = (sgx_sealed_data_t*) malloc( seal_size );
	if ( sealed_data == NULL ){
		char msg[] = "ERROR: could not allocate memory for sealed data.";
		ocall_prints( &retval, msg );
		return SGX_ERROR_OUT_OF_MEMORY;
	}
	//status = sgx_seal_data( mac_text_len, mac_text, ec256_key_handles_length, (uint8_t*) &ec256_key_handles, seal_size, sealed_data );
	status = sgx_seal_data( 0, NULL, ec256_key_handles_length, (uint8_t*)ec256_key_handles, seal_size, sealed_data );
	if (status != SGX_SUCCESS) {
		char msg1[] = "ERROR: cannot seal EC256 key store.";
		ocall_prints( &retval, msg1 );
		free( sealed_data) ;
		return status;
	}
	//char msg2[] = "SUCCESS: sealed EC256 key store.";
	//ocall_prints( &retval, msg2 );

	// store the sealed EC256 key to disk
	status = ocall_store_sealed_keys( &j_status, (uint8_t*) sealed_data, seal_size );
	free( sealed_data );
	if (status != SGX_SUCCESS || j_status != J_SUCCESS) {
		char msg3[] = "ERROR: cannot store EC256 key store to disk.";
		ocall_prints( &retval, msg3 );
		return status;
	}

	//char msg4[] = "SUCCESS: stored sealed EC256 keys to disk.";
	//ocall_prints( &retval, msg4 );
	return SGX_SUCCESS;
}

// counts and returns the number of in-use keys in key store cache
int get_num_ec256_key_pairs(){
	int key_index 			 	  = 0; // index handle to ec256 key pair in key store
	int num_valid_ec256_key_pairs = 0; // number of valid key pairs in key store cache

	if (ec256_key_handles != NULL){
		for ( key_index = 0; key_index < NUMBER_OF_EC256_KEY_PAIRS; key_index++ ){
			if (ec256_key_handles[ key_index ].in_use == true){
				num_valid_ec256_key_pairs++;
			}
		}
	}

	return num_valid_ec256_key_pairs;
}

// helper function for generating TLS keys
// inputs: buf_len -- number of bytes to be generated and put in buf
//         key
//         key_len
//         seed
//         seed_len
// outputs: buf
void prf_sha256(uint8_t* buf, uint32_t buf_len, uint8_t* key, uint32_t key_len, uint8_t* seed, uint32_t seed_len) {
	int retval;
	uint8_t iter_msg[SHA256_BLOCKSIZE+seed_len];
	uint8_t a[SHA256_BLOCKSIZE];
	uint8_t buf_chunk[SHA256_BLOCKSIZE];
	hmac_sha256((sgx_sha256_hash_t*)a, key, key_len, seed, seed_len); // get a(1)
	for (int i=0; i<(buf_len/SHA256_BLOCKSIZE + 1); i++) {
		// create the msg to hash this iteration
		memcpy(iter_msg, a, SHA256_BLOCKSIZE);
		memcpy(iter_msg+SHA256_BLOCKSIZE, seed, seed_len);
		hmac_sha256(&buf_chunk, key, key_len, iter_msg, SHA256_BLOCKSIZE+seed_len);
		// copy some part of it (likely all of it) into buf
		if (buf_len >= (i+1)*SHA256_BLOCKSIZE) {
			memcpy(buf+(i*SHA256_BLOCKSIZE),buf_chunk, SHA256_BLOCKSIZE);
		} else {
			memcpy(buf+(i*SHA256_BLOCKSIZE),buf_chunk, buf_len%SHA256_BLOCKSIZE);
			return; // EXIT since we copied the last bit, so we're done
		}
		hmac_sha256((sgx_sha256_hash_t*)a, key, key_len, a, SHA256_BLOCKSIZE); // get a(n) for next iteration
	}
	char msg[] = "ERROR: should not have gotten here in prf_sha256().";
	ocall_prints(&retval, msg );
	return;
}

// helper functionn for PRF
// inputs: key
//         key_len
//         msg
//         msg_len
// outputs: hash
// Approximately follows pseudo-code given on wikipedia for hmac
// See https://en.wikipedia.org/wiki/Hash-based_message_authentication_code
void hmac_sha256(sgx_sha256_hash_t* hash, uint8_t* key, uint32_t key_len, uint8_t* msg, uint32_t msg_len) {
	// set up opad and ipad constants
	//uint8_t opad[SHA256_BLOCKSIZE] = {0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c};
	//uint8_t ipad[SHA256_BLOCKSIZE] = {0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36};
	// check key and either pad or hash it to make key_k, size of one sha256 block (64 bytes)
	uint8_t key_k[SHA256_BLOCKSIZE];
	if (key_len > SHA256_BLOCKSIZE) { // if key is too long, hash it
		sgx_sha256_msg(key, key_len, (sgx_sha256_hash_t*)key_k);
	} else { // zero out the memory of key_k and copy over the given key (thereby padding the right bytes with zeroes)
		memset(key_k, 0, SHA256_BLOCKSIZE);
		memcpy(key_k, key, key_len);
	}
	uint8_t inner_hash[SHA256_BLOCKSIZE];
	uint8_t outer_msg[SHA256_BLOCKSIZE*2];
	// build inner_msg for hashing
	uint8_t inner_msg[msg_len+SHA256_BLOCKSIZE];
	for (int i=0; i<SHA256_BLOCKSIZE; i++) {
		//inner_msg[i] = ipad[i] ^ key_k[i];
		inner_msg[i] = 0x36 ^ key_k[i];
	}
	memcpy(&(inner_msg[SHA256_BLOCKSIZE]), msg, msg_len);
	// hash inner_msg
	sgx_sha256_msg(inner_msg, msg_len+SHA256_BLOCKSIZE, (sgx_sha256_hash_t*)inner_hash);
	// build outer_msg for hashing
	for (int i=0; i<SHA256_BLOCKSIZE; i++) {
		//outer_msg[i] = opad[i] ^ key_k[i];
		outer_msg[i] = 0x5c ^ key_k[i];
	}
	memcpy(&(outer_msg[SHA256_BLOCKSIZE]), inner_hash, SHA256_BLOCKSIZE);
	// hash outer_msg
	sgx_sha256_msg(outer_msg, SHA256_BLOCKSIZE*2, hash); // this puts our return value in the right place
}


//////////////////
// PUBLIC DEBUG //
//////////////////

sgx_status_t debug_number_ec256_key_pairs( int* num_keys ){
	int retval = 0;

	// Check if key store is cached in memory	
	if ( ec256_key_handles == NULL ){
		// Allocate memory for EC256 key store cache
		ec256_key_handles = (ec256_key_handle_t*)malloc( NUMBER_OF_EC256_KEY_PAIRS*sizeof( ec256_key_handle_t ));
		if ( ec256_key_handles == NULL ){
			char msg[] = "ERROR: could not allocate memory for key pair store cache.";
			ocall_prints( &retval, msg );
			return SGX_ERROR_OUT_OF_MEMORY;
		}
		if ( load_ec256_keys() != SGX_SUCCESS ){
			// No key store exists!
			*num_keys = 0;
			free( ec256_key_handles );
			ec256_key_handles = NULL;
		}
		else{
			// Key store was on disk and has now been cached
			*num_keys = get_num_ec256_key_pairs();
		}
	}
	else{
		// Key store was cached
		*num_keys = get_num_ec256_key_pairs();
	}
	return SGX_SUCCESS;
}



