#ifndef ENCLAVE_H
#define ENCLAVE_H

#include "../include/commpact_types.h"

#include "../include/ecu_types.h"

// private function definitions go here (but not public ones, since those are
// already exposed via edger8r

typedef struct _ec256_key_pair_t {
  sgx_ec256_public_t pub;
  sgx_ec256_private_t priv;
} ec256_key_pair_t;

// PRIVATE
////////////////////////////////////////////////////////////////////////////////
sgx_status_t sendECUMessage();
sgx_status_t sendECUMessage(sgx_ec256_signature_t *signature,
                            ecu_message_t *message);
sgx_status_t verifyMessageSignature(uint8_t *message, uint64_t message_size,
                                    sgx_ec256_signature_t *signature,
                                    sgx_ec256_public_t *pub_key,
                                    uint8_t *result);
sgx_status_t validateSignaturesHelper(contract_chain_t *contract,
                                      cp_ec256_signature_t *signatures,
                                      uint8_t num_signatures);
sgx_status_t checkParametersHelper(contract_chain_t *contract);
sgx_status_t updateParametersHelper(contract_chain_t *contract);
sgx_status_t signContractHelper(contract_chain_t *contract,
                                sgx_ec256_signature_t *return_signature);
////////////////////////////////////////////////////////////////////////////////

#endif /* ENCLAVE_H */
