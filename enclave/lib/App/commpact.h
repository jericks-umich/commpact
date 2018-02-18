#ifndef COMMPACT_H
#define COMMPACT_H

#define ENCLAVE_FILENAME "/tmp/enclave.signed.so"

#include "../include/commpact_types.h"

// public (API exposed) functions
////////////////////////////////////////////////////////////////////////////////
commpact_status_t initEnclave(uint64_t *enclave_id);
commpact_status_t setInitialPosition(uint64_t enclave_id, int position);
commpact_status_t initializeKeys(uint64_t enclave_id,
                                 cp_ec256_public_t *pubkey);
commpact_status_t setInitialSpeedBounds(uint64_t enclave_id, double lower,
                                        double upper);
commpact_status_t setInitialRecoveryPhaseTimeout(uint64_t enclave_id,
                                                 double timeout);
commpact_status_t checkAllowedSpeed(uint64_t enclave_id, double speed,
                                    bool *verdict);
commpact_status_t newContractChainGetSignatureEnclave(
    contract_chain_t contract, cp_ec256_signature_t *return_signature,
    uint8_t num_signatures, cp_ec256_signature_t *signatures);
////////////////////////////////////////////////////////////////////////////////

// private (static) functions
////////////////////////////////////////////////////////////////////////////////
commpact_status_t validateSignaturesHelper(uint64_t enclave_id,
                                           contract_chain_t *contract,
                                           cp_ec256_signature_t *signatures,
                                           uint8_t num_signatures);
commpact_status_t checkParametersHelper(uint64_t enclave_id,
                                        contract_chain_t *contract);
commpact_status_t updateParametersHelper(uint64_t enclave_id,
                                         contract_chain_t *contract);
commpact_status_t signContractHelper(uint64_t enclave_id,
                                     contract_chain_t *contract,
                                     cp_ec256_signature_t *return_signature);
////////////////////////////////////////////////////////////////////////////////

#endif /* COMMPACT_H */
