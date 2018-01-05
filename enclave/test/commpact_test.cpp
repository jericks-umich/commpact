#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <time.h>

#include "sgx_eid.h"
#include "sgx_tcrypto.h"
#include "include/status.h"
#include "commpact.h"

#include "commpact_test.h"

// CDECL tells the compiler that the caller will do arg cleanup
int SGX_CDECL main(int argc, char* argv[]) {
	sgx_enclave_id_t 	enclave_id = 0; 
	commpact_status_t 	cp_status   = CP_SUCCESS;

	// Init Crypto SGX Enclave
	cp_status = init_crypto_enclave( &enclave_id, ENCLAVE_FILENAME );
	
	// Test #1
	generate_3_keys_and_delete_2( enclave_id );
	printf("---------------------------------------------------------\n");

	// Test #2
	generate_2_keys_and_delete_1( enclave_id );
	printf("---------------------------------------------------------\n");

	// Test #3
	webserver_ops( enclave_id );
	printf("---------------------------------------------------------\n");

	// Note: we run out of enclave memory at 1000000 (1MB) XXX
	uint32_t plaintext_len = 100000; // change and recompile as needed for testing
	webserver_ops_speed_test(enclave_id, plaintext_len);

	//// Test how long it takes to generate keys
	gen_n_keys( enclave_id, 2);

	return 0;
}

void generate_3_keys_and_delete_2( sgx_enclave_id_t enclave_id ){
	commpact_status_t 	status   = CP_SUCCESS;
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
	commpact_status_t 	status   = CP_SUCCESS;
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
	commpact_status_t status;
	sgx_status_t retval;
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

	retval = tls_encrypt_aes_gcm(enclave_id, &mac, ciphertext, plaintext, plaintext_len, &s_pub, &c_pub, server_random, s_len, client_random, c_len, 0);
	printf("Status of encryption: %d\n", retval);
	printf("Ciphertext:");
	for (int i=0; i<plaintext_len; i++) {
		printf(" 0x%x", ciphertext[i]);
	}
	printf("\n");

	// now, ask the client to decrypt the message
	printf("Asking the client to decrypt the message\n");
	// just like before with the encrypt function, but now we're the client
	retval = tls_decrypt_aes_gcm(enclave_id, &mac, ciphertext, new_plaintext, plaintext_len, &s_pub, &c_pub, server_random, s_len, client_random, c_len, 1);
	printf("Status of decryption: %d\n", retval);
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

void webserver_ops_speed_test( sgx_enclave_id_t enclave_id, uint32_t plaintext_len ) {
	sgx_status_t status1;
	sgx_status_t status2;
	sgx_ec256_public_t s_pub;
	sgx_ec256_public_t c_pub;
	uint8_t client_random[28] = {0}; // super random ;)
	uint8_t server_random[28] = {0};
	uint32_t c_len = sizeof(client_random);
	uint32_t s_len = sizeof(server_random);
	sgx_aes_gcm_128bit_tag_t mac;
	uint8_t* plaintext;
	uint8_t* ciphertext;
	uint8_t* new_plaintext;
	timespec start;
	timespec end;
	timespec dif;


	// allocate memory for our plaintext tests
	plaintext = (uint8_t*)calloc(1,plaintext_len);
	ciphertext = (uint8_t*)calloc(1,plaintext_len);
	new_plaintext = (uint8_t*)calloc(1,plaintext_len);

	// set plaintext to something discernable, like sequential byte values
	for(int i=0; i<plaintext_len; i++) {
		plaintext[i] = (uint8_t)i%256;
	}
	
	// generate the keys we'll need for the following operations
	generate_ec256_key_pair(enclave_id, &s_pub);
	generate_ec256_key_pair(enclave_id, &c_pub);

	// now, perform encryption test
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
	status1 = tls_encrypt_aes_gcm(enclave_id, &mac, ciphertext, plaintext, plaintext_len, &s_pub, &c_pub, server_random, s_len, client_random, c_len, 0);
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);
	dif = diff(start, end);
	printf("%ld.%09ld, ", dif.tv_sec, dif.tv_nsec);
	

	// now, perform decryption test
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
	status2 = tls_decrypt_aes_gcm(enclave_id, &mac, ciphertext, new_plaintext, plaintext_len, &s_pub, &c_pub, server_random, s_len, client_random, c_len, 1);
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);
	dif = diff(start, end);
	printf("%ld.%09ld\n", dif.tv_sec, dif.tv_nsec);

	// make sure that plaintext and new_plaintext match
	if (0 != memcmp(plaintext, new_plaintext, plaintext_len)) {
		printf("Error: plaintext and new_plaintext don't match!\n");
		printf("%d %d\n", status1, status2);
		for (int i=0; i<10; i++) {
			printf(" 0x%x", plaintext[i]);
		}
		printf("\n");
		for (int i=0; i<10; i++) {
			printf(" 0x%x", ciphertext[i]);
		}
		printf("\n");
		for (int i=0; i<10; i++) {
			printf(" 0x%x", new_plaintext[i]);
		}
		printf("\n");
	}

	// free all allocated memory
	free(plaintext);
	free(ciphertext);
	free(new_plaintext);

	// delete server and client ec256 key pairs
	delete_all_ec256_key_pairs( enclave_id );
}

timespec diff(timespec start, timespec end) {
	timespec temp;
	if ((end.tv_nsec-start.tv_nsec)<0) {
		temp.tv_sec = end.tv_sec-start.tv_sec-1;
		temp.tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
	} else {
		temp.tv_sec = end.tv_sec-start.tv_sec;
		temp.tv_nsec = end.tv_nsec-start.tv_nsec;
	}
	return temp;
}

void gen_n_keys( sgx_enclave_id_t enclave_id, uint32_t num) {
	sgx_ec256_public_t* keys;
	timespec start;
	timespec end;
	timespec dif;

	// allocate memory for pubkeys that get returned
	keys = (sgx_ec256_public_t*) calloc(sizeof(sgx_ec256_public_t), num);

	// generate n keys
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
	for (int i=0; i<num; i++) {
		generate_ec256_key_pair(enclave_id, &keys[i]);
	}
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);
	dif = diff(start, end);
	printf("%ld.%09ld\n", dif.tv_sec, dif.tv_nsec);

	// delete all ec256 key pairs
	delete_all_ec256_key_pairs( enclave_id );
}
