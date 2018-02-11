#include "../include/commpact_types.h"

#include "../include/ecu_types.h"

#ifndef ENCLAVE_H
#define ENCLAVE_H

// private function definitions go here (but not public ones, since those are
// already exposed via edger8r

typedef struct _ec256_key_pair_t {
  sgx_ec256_public_t pub;
  sgx_ec256_private_t priv;
} ec256_key_pair_t;

/////////////
// PRIVATE //
/////////////
int ECUMessage(sgx_ec256_signature_t *signature, ecu_message_t *message);

#endif // ENCLAVE_H
