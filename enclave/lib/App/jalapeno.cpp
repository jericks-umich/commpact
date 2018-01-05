#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>

#include "sgx_eid.h"
#include "sgx_urts.h"
#include "sgx_tcrypto.h"
#include "sgx_error.h"

#include "Enclave_u.h"
#include "jalapeno.h"

//#define SGX_DEBUG_FLAG 1 // debug mode enabled

///////////////////////////
// API Exposed Functions //
///////////////////////////
// Initialize instance of crypto enclave
jalapeno_status_t init_crypto_enclave( sgx_enclave_id_t* enclave_id, const char* enclave_filename ) {
	int ret;
	int updated; // flag for whether the launch token is updated or not (it should be, since we don't pass it a valid one)
	sgx_launch_token_t token = {0};

	// create new enclave
	// https://software.intel.com/sites/products/sgx-sdk-users-guide-windows/Content/sgx_create_enclave.htm
	ret = sgx_create_enclave(
		enclave_filename,
		SGX_DEBUG_FLAG,
		&token,
		&updated,
		enclave_id,
		NULL );
	if ( ret != 0 ){
		printf("ERROR: failed (%x) to initialize SGX crypto enclave.\n", ret);
		return J_ERROR;
	}
	return J_SUCCESS;
}

// ECALL: generates ec256 key pair, seals it, and saves it to disk
jalapeno_status_t generate_ec256_key_pair( sgx_enclave_id_t enclave_id, sgx_ec256_public_t* pub_key ){
	sgx_status_t 		status   = SGX_SUCCESS;
	sgx_status_t 		retval   = SGX_SUCCESS;

	status = generate_ec256_key_pair( enclave_id, &retval, pub_key );
	
	if (status == SGX_SUCCESS){
		return J_SUCCESS;
	}
	else {
		return J_ERROR;
	}
}

// ECALL: deletes ec256 key pair and updates persistent sealed key file to reflect this change
jalapeno_status_t delete_ec256_key_pair( sgx_enclave_id_t enclave_id, sgx_ec256_public_t* pub_key ){
	sgx_status_t 		status   = SGX_SUCCESS;
	sgx_status_t 		retval   = SGX_SUCCESS;

	status = delete_ec256_key_pair( enclave_id, &retval, pub_key );

	if (status == SGX_SUCCESS){
		return J_SUCCESS;
	}
	else {
		return J_ERROR;
	}
}

// ECALL: deletes ALL ec256 key pair and deletes persistent sealed key file
jalapeno_status_t delete_all_ec256_key_pairs( sgx_enclave_id_t enclave_id ){
	sgx_status_t 		status   = SGX_SUCCESS;
	sgx_status_t 		retval   = SGX_SUCCESS;

	status = delete_all_ec256_key_pairs( enclave_id, &retval );

	if (status == SGX_SUCCESS){
		return J_SUCCESS;
	}
	else {
		return J_ERROR;
	}
}

// ECALL: encrypts plaintext with a TLS session key, which is derived from by a generated ECDH key
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
	uint8_t 					is_client ){

	sgx_status_t 		status   = SGX_SUCCESS;
	sgx_status_t 		retval   = SGX_SUCCESS;

	status = encrypt_aes_gcm(
		enclave_id, 
		&retval, 
		mac, 
		ciphertext, 
		plaintext, 
		plaintext_len, 
		server_pubkey, 
		client_pubkey, 
		server_random_bytes, 
		num_server_random_bytes, 
		client_random_bytes, 
		num_client_random_bytes, 
		is_client);

	return status;
}

// ECALL: decrypts plaintext with a TLS session key, which is derived from by a generated ECDH key
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
	uint8_t 					is_client ){

	sgx_status_t 		status   = SGX_SUCCESS;
	sgx_status_t 		retval   = SGX_SUCCESS;

	status = decrypt_aes_gcm(
		enclave_id, 
		&retval, 
		mac, 
		ciphertext, 
		plaintext, 
		plaintext_len, 
		server_pubkey, 
		client_pubkey, 
		server_random_bytes, 
		num_server_random_bytes, 
		client_random_bytes, 
		num_client_random_bytes, 
		is_client);

	return status;
}

// ECALL (for debugging use only): returns number of stored ec256 key pairs
jalapeno_status_t debug_number_ec256_key_pairs( sgx_enclave_id_t enclave_id, int* num_keys ){
	sgx_status_t 		status   = SGX_SUCCESS;
	sgx_status_t 		retval   = SGX_SUCCESS;

	status = debug_number_ec256_key_pairs( enclave_id, &retval, num_keys );

	if (status == SGX_SUCCESS){
		return J_SUCCESS;
	}
	else {
		return J_ERROR;
	}
}

// Prints out Hex representation of an EC256 public key
void print_ec256_pub_key( sgx_ec256_public_t* pub ){
	printf("Public gx: ");
	for(int i = 0; i < SGX_ECP256_KEY_SIZE; i++)
	{
		printf("%02X",pub->gx[i]);
	}
	printf("\n");
	printf("Public gy: ");
	for(int i = 0; i < SGX_ECP256_KEY_SIZE; i++)
	{
		printf("%02X",pub->gy[i]);
	}
	printf("\n");
}

////////////
// OCALLS //
////////////

int ocall_prints( const char* str ) {
  fprintf(stderr, "The enclave prints: \"%s\"\n", str);
}

jalapeno_status_t ocall_store_sealed_keys( const uint8_t* sealed_data, uint32_t len ) {
	FILE* fp;
	fp = fopen( STORE_FILENAME, "wb" );
	if (fp == NULL) {
		return J_CANT_OPEN_FILE;
	}
	fwrite( sealed_data, sizeof(uint8_t), len, fp );
	fclose( fp );
	return J_SUCCESS;
}

jalapeno_status_t ocall_load_sealed_keys( uint8_t* sealed_data, uint32_t len ) {
	FILE* fp;
	fp = fopen( STORE_FILENAME, "rb" );
	if (fp == NULL) {
		return J_CANT_OPEN_FILE;
	}
	fread( sealed_data, sizeof(uint8_t), len, fp );
	fclose( fp );
	return J_SUCCESS;
}

jalapeno_status_t ocall_delete_sealed_keys_file() {
	remove( STORE_FILENAME );
	return J_SUCCESS;
}

/////////////
// TESTING //
/////////////
// CDECL tells the compiler that the caller will do arg cleanup
/*
int SGX_CDECL main(int argc, char* argv[]) {
	sgx_enclave_id_t 	enclave_id = 0; 
	jalapeno_status_t 	j_status   = J_SUCCESS;

	// Init Crypto SGX Enclave
	j_status = init_crypto_enclave( &enclave_id );
	
	// Test #1
	generate_3_keys_and_delete_2( enclave_id );
	printf("---------------------------------------------------------\n");

	// Test #2
	generate_2_keys_and_delete_1( enclave_id );
	printf("---------------------------------------------------------\n");

	// Test #3
	webserver_ops( enclave_id );
	printf("---------------------------------------------------------\n");

	return 0;
}


void generate_3_keys_and_delete_2( sgx_enclave_id_t enclave_id ){
	jalapeno_status_t 	status   = J_SUCCESS;
	sgx_ec256_public_t 	pub_1;
	sgx_ec256_public_t 	pub_2;
	sgx_ec256_public_t 	pub_3;
	int 				num_keys = 0;

	// 1. Generate EC256 Public-Private Key Pair 1
	printf( "Generating EC256 key pair 1...\n" );
	status = generate_ec256_key_pair( enclave_id, &pub_1 );
	print_ec256_pub_key( &pub_1 );
	debug_number_ec256_key_pairs( enclave_id, &num_keys );
	printf( "Number of EC256 key pairs: %d\n", num_keys );
	printf( "Return status from generate_ec256_key_pair(): %d\n\n", status );

	// 2. Generate EC256 Public-Private Key Pair 2
	printf( "Generating EC256 key pair 2...\n" );
	status = generate_ec256_key_pair( enclave_id, &pub_2 );
	print_ec256_pub_key( &pub_2 );
	debug_number_ec256_key_pairs( enclave_id, &num_keys );
	printf( "Number of EC256 key pairs: %d\n", num_keys );
	printf( "Return status from generate_ec256_key_pair(): %d\n\n", status );

	// 3. Generate EC256 Public-Private Key Pair 3
	printf( "Generating EC256 key pair 3...\n" );
	status = generate_ec256_key_pair( enclave_id, &pub_3 );
	print_ec256_pub_key( &pub_3 );
	debug_number_ec256_key_pairs( enclave_id, &num_keys );
	printf( "Number of EC256 key pairs: %d\n", num_keys );
	printf( "Return status from generate_ec256_key_pair(): %d\n\n", status );

	// 4. Delete key pair 2
	printf( "Deleting  EC256 key pair 2...\n" );
	status = delete_ec256_key_pair( enclave_id, &pub_2 );
	debug_number_ec256_key_pairs( enclave_id, &num_keys );
	printf( "Number of EC256 key pairs: %d\n", num_keys );
	printf( "Return status from delete_ec256_key_pair(): %d\n\n", status );

	// 5. Delete key pair 3
	printf( "Deleting  EC256 key pair 3...\n" );
	status = delete_ec256_key_pair( enclave_id, &pub_3 );
	debug_number_ec256_key_pairs( enclave_id, &num_keys );
	printf( "Number of EC256 key pairs: %d\n", num_keys );
	printf( "Return status from delete_ec256_key_pair(): %d\n\n", status );

	// 6. Delete key store
	printf( "Deleting EC256 key pair store...\n" );
	status = delete_all_ec256_key_pairs( enclave_id );
	debug_number_ec256_key_pairs( enclave_id, &num_keys );
	printf( "Number of EC256 key pairs: %d\n", num_keys );
	printf( "Return status from delete_all_ec256_key_pairs(): %d\n\n", status );
}

void generate_2_keys_and_delete_1( sgx_enclave_id_t enclave_id ){
	jalapeno_status_t 	status   = J_SUCCESS;
	sgx_ec256_public_t 	pub_1;
	sgx_ec256_public_t 	pub_2;
	int 				num_keys = 0;

	// 1. Generate EC256 Public-Private Key Pair 1
	printf( "Generating EC256 key pair 1...\n" );
	status = generate_ec256_key_pair( enclave_id, &pub_1 );
	print_ec256_pub_key( &pub_1 );
	debug_number_ec256_key_pairs( enclave_id, &num_keys );
	printf( "Number of EC256 key pairs: %d\n", num_keys );
	printf( "Return status from generate_ec256_key_pair(): %d\n\n", status );

	// 2. Generate EC256 Public-Private Key Pair 2
	printf( "Generating EC256 key pair 2...\n" );
	status = generate_ec256_key_pair( enclave_id, &pub_2 );
	print_ec256_pub_key( &pub_2 );
	debug_number_ec256_key_pairs( enclave_id, &num_keys );
	printf( "Number of EC256 key pairs: %d\n", num_keys );
	printf( "Return status from generate_ec256_key_pair(): %d\n\n", status );

	// 3. Delete key pair 1
	printf( "Deleting  EC256 key pair 1...\n" );
	status = delete_ec256_key_pair( enclave_id, &pub_1 );
	debug_number_ec256_key_pairs( enclave_id, &num_keys );
	printf( "Number of EC256 key pairs: %d\n", num_keys );
	printf( "Return status from delete_ec256_key_pair(): %d\n\n", status );

	// 4. Delete key store cache
	printf( "Deleting EC256 key pair store...\n" );
	status = delete_all_ec256_key_pairs( enclave_id );
	debug_number_ec256_key_pairs( enclave_id, &num_keys );
	printf( "Number of EC256 key pairs: %d\n", num_keys );
	printf( "Return status from delete_all_ec256_key_pairs(): %d\n\n", status );
}



// here's the set of things that would happen with a web server:
// 1) Admin will install and configure web server
//	- Will need to generate pub/priv keypair, use pubkey for certificate
// 2) Will need to accept connections from clients
//	- Clients will make TLS request, certificate will be exchanged with pubkey in it
//	- ECDH protocol will occur -- client will generate EC pub/priv keypair and send pubkey
//		- shared key will be derived on both sides using own privkey + remote pubkey
//		- future data will be encrypted with either shared key directly, or key derived from shared key
//			- in TLS, apparently additional session info is concatenated to shared key, then hash is taken and used as session key
// 3) mid-connection, another connection may initiate
//	- must support multiple sessions, use remote pubkey as index (for now, just recompute shared key as needed)
// 4) The connection ends
//	- We must throw away the ephemeral session key (ECDHE) so that PFS takes effect (ECDH is when we reuse the session key between sessions)

void webserver_ops( sgx_enclave_id_t enclave_id ) {
	jalapeno_status_t status;
	// sgx_status_t retval;
	sgx_ec256_public_t s_pub;
	sgx_ec256_public_t c_pub;
	uint8_t client_random[28] = {0}; // super random ;)
	uint8_t server_random[28] = {0};
	uint32_t c_len = sizeof(client_random);
	uint32_t s_len = sizeof(server_random);
	sgx_aes_gcm_128bit_tag_t mac;
	uint8_t plaintext[32];
	uint32_t plaintext_len = sizeof(plaintext);
	uint8_t ciphertext[32];
	uint8_t new_plaintext[32];
	int 	num_keys = 0;

#define SERVER_MESSAGE "ServerSecretMessage"
#define SERVER_MESSAGE_LEN sizeof(SERVER_MESSAGE)
	memset(plaintext, 0, 32);
	memcpy(plaintext, SERVER_MESSAGE, SERVER_MESSAGE_LEN);

	printf("Performing webserver operations.\n");

	// 1) Admin will install and configure web server
	//	- Will need to generate pub/priv keypair, use pubkey for certificate
	printf("Generating server EC256 key pair...\n");
	status = generate_ec256_key_pair(enclave_id, &s_pub);
	printf("EC256 key pair generated. Use to set up CSR.\n");
	print_ec256_pub_key(&s_pub);
	// TODO: we'll need to actually output this in a form that can be used for a CSR
	// TODO: we'll also need to get SGX to sign this so the dev can authenticate it's the right keypair
	
	// 2) Will need to accept connections from clients
	//	- Clients will make TLS request, certificate will be exchanged with pubkey in it
	//	- ECDH protocol will occur -- client will generate EC pub/priv keypair and send pubkey
	//		- shared key will be derived on both sides using own privkey + remote pubkey
	//		- future data will be encrypted with either shared key directly, or key derived from shared key
	//			- in TLS, apparently additional session info is concatenated to shared key, then hash is taken and used as session key

	// We're going to simulate both the client and server here, so first generate a new keypair for the client
	printf("Generating client EC256 key pair...\n");
	status = generate_ec256_key_pair(enclave_id, &c_pub);

	// simulate the server/client exchanging pubkeys
	// ta-da that's done (since we have both in local [untrusted] memory)
	// we're going to leave the client's pubkey in untrusted memory and make the untrusted app hold on to it as part of the session information, since it can't hold onto the session keys anymore

	// since we're not storing the session keys in the enclave (we're going to recompute it each time), we don't have to initialize anything

	// ask the server to encrypt a message for the client
	printf("Asking the server to encrypt the message, '%s'.\n", plaintext);
	// note: we need the following to compute the pre-master secret, master secret, and session keys:
	// server pub key (to look up server priv key)
	// client pub key
	// ==> this can generate the pre-master secret
	// https://tools.ietf.org/html/rfc2246#page-21
	// clienthello.random
	// serverhello.random
	// ==> this can generate the master secret
	// https://tools.ietf.org/html/rfc5246
	// ==> this can generate the session keys

	status = tls_encrypt_aes_gcm(enclave_id, &mac, ciphertext, plaintext, plaintext_len, &s_pub, &c_pub, server_random, s_len, client_random, c_len, 0);
	printf("Status of encryption: %d\n", status);
	printf("Ciphertext:");
	for (int i=0; i<plaintext_len; i++) {
		printf(" 0x%x", ciphertext[i]);
	}
	printf("\n");

	// now, ask the client to decrypt the message
	printf("Asking the client to decrypt the message\n");
	// just like before with the encrypt function, but now we're the client
	status = tls_decrypt_aes_gcm(enclave_id, &mac, ciphertext, new_plaintext, plaintext_len, &s_pub, &c_pub, server_random, s_len, client_random, c_len, 1);
	printf("Status of decryption: %d\n", status);
	printf("Plaintext: '%s'\n", new_plaintext);
	for (int i=0; i<plaintext_len; i++) {
		printf(" 0x%x", new_plaintext[i]);
	}
	printf("\n\n");

	// delete server and client ec256 key pairs
	printf( "Deleting EC256 key pair store...\n" );
	status = delete_all_ec256_key_pairs( enclave_id );
	debug_number_ec256_key_pairs( enclave_id, &num_keys );
	printf( "Number of EC256 key pairs: %d\n", num_keys );
	printf( "Return status from delete_all_ec256_key_pairs(): %d\n\n", status );
}

*/


