#ifndef JALAPENO_TEST_H
#define JALAPENO_TEST_H

#include "../include/status.h"

//#define ENCLAVE_FILENAME "enclave.signed.so"
#define STORE_FILENAME 	 "/tmp/sgx_ec256_key_store.dump"

// API Exposed Functions
jalapeno_status_t init_crypto_enclave( sgx_enclave_id_t* enclave_id, const char* enclave_filename );
jalapeno_status_t generate_ec256_key_pair( sgx_enclave_id_t enclave_id, sgx_ec256_public_t* pub_key );
jalapeno_status_t delete_ec256_key_pair( sgx_enclave_id_t enclave_id, sgx_ec256_public_t* pub_key );
jalapeno_status_t delete_all_ec256_key_pairs( sgx_enclave_id_t enclave_id );
sgx_status_t tls_encrypt_aes_gcm( 
	sgx_enclave_id_t 			enclave_id, 
	sgx_aes_gcm_128bit_tag_t* 	mac, 
	uint8_t* 					ciphertext, 
	uint8_t*					plaintext,
	uint32_t 					plaintext_len, 
	sgx_ec256_public_t* 		server_pubkey, 
	sgx_ec256_public_t* 		client_pubkey, 
	uint8_t* 					server_random_bytes, 
	uint32_t 					num_server_random_bytes, 
	uint8_t* 					client_random_bytes, 
	uint32_t 					num_client_random_bytes, 
	uint8_t 					is_client );
sgx_status_t tls_decrypt_aes_gcm(
	sgx_enclave_id_t 			enclave_id, 
	sgx_aes_gcm_128bit_tag_t* 	mac, 
	uint8_t* 					ciphertext, 
	uint8_t*					plaintext, 
	uint32_t 					plaintext_len, 
	sgx_ec256_public_t* 		server_pubkey, 
	sgx_ec256_public_t* 		client_pubkey, 
	uint8_t* 					server_random_bytes, 
	uint32_t 					num_server_random_bytes, 
	uint8_t* 					client_random_bytes, 
	uint32_t 					num_client_random_bytes,  
	uint8_t 					is_client );

// API Exposed Debug Functions
jalapeno_status_t debug_number_ec256_key_pairs( sgx_enclave_id_t enclave_id, int* num_keys );
void print_ec256_pub_key( sgx_ec256_public_t* pub );

// Testing Functions
void generate_3_keys_and_delete_2( sgx_enclave_id_t enclave_id );
void generate_2_keys_and_delete_1( sgx_enclave_id_t enclave_id );
void webserver_ops( sgx_enclave_id_t enclave_id );

#endif // JALAPENO_TEST_H
