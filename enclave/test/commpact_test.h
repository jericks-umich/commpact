#ifndef COMMPACT_H
#define COMMPACT_H

#define ENCLAVE_FILENAME "/home/chshibo/workspace/commpact/enclave/lib/enclave.signed.so"
#define KEY_STORE_FILENAME 	 "/tmp/sgx_ec256_key_store.dump"

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
	 0 if success, others if fail	
*/
int test_initializeKeys(uint64_t e_id, cp_ec256_public_t *pubkey);


/*
Test initEnclave
Parameters 
----------
e_id: uint64_t*
	the pointer to a e_id
Returns
-------
retval : int
	0 if success, others` if fail
*/
int test_initEnclave(uint64_t* e_id);

#endif // COMMPACT_H
