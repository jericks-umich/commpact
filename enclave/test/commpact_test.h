#ifndef COMMPACT_H
#define COMMPACT_H

#define ENCLAVE_FILENAME "../lib/enclave.signed.so"
#define KEY_STORE_FILENAME "/tmp/sgx_ec256_key_store.dump"

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
commpact_status_t testInitializeKeys(uint64_t e_id, cp_ec256_public_t *pubkey);

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
commpact_status_t testInitEnclave(uint64_t *e_id);

// TODO test for set position

// TODO test for set initial pub keys
#endif // COMMPACT_H
