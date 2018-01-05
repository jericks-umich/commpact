#ifndef JALAPENO_H
#define JALAPENO_H

#include <time.h>

#define ENCLAVE_FILENAME "/home/jericks/projects/jalapeno/lib/enclave.signed.so"
#define KEY_STORE_FILENAME 	 "/tmp/sgx_ec256_key_store.dump"

// Test Functions
void generate_3_keys_and_delete_2( sgx_enclave_id_t enclave_id );
void generate_2_keys_and_delete_1( sgx_enclave_id_t enclave_id );
void webserver_ops( sgx_enclave_id_t enclave_id );
void webserver_ops_speed_test( sgx_enclave_id_t enclave_id, uint32_t plaintext_len );
void gen_n_keys( sgx_enclave_id_t enclave_id, uint32_t num);
timespec diff(timespec start, timespec end);


#endif // JALAPENO_H
