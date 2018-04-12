#ifndef COMMPACT_H
#define COMMPACT_H

#define DEFAULT_ENCLAVE_FILENAME "/tmp/enclave.signed.so"
#define COMMPACT_DEBUG
#define USING_REAL_ECU 1
//#define USING_BIG_ENDIAN // comment out when not using the automotive ECU --
// automotive ECU looks like is little-endian after all
//#define TIME_ECU // comment this out when not timing the ECU specifically
#define DEBUG_ECU_LATENCY_FILENAME "/tmp/ecu_latency.txt"
#define CPU_TICKS_PER_SEC 4000000000 // 4Ghz

#include "../include/commpact_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// public (API exposed) functions
////////////////////////////////////////////////////////////////////////////////
commpact_status_t initEnclave(uint64_t *e_id);
commpact_status_t initEnclaveWithFilename(uint64_t *e_id,
                                          const char *enclave_filename);
commpact_status_t setInitialPosition(uint64_t enclave_id, uint8_t position);
commpact_status_t initializeKeys(uint64_t enclave_id,
                                 cp_ec256_public_t *pubkey);
commpact_status_t setInitialSpeedBounds(uint64_t enclave_id, double lower,
                                        double upper);
commpact_status_t setInitialRecoveryPhaseTimeout(uint64_t enclave_id,
                                                 double timeout);
commpact_status_t checkAllowedSpeed(uint64_t enclave_id, double speed,
                                    bool *verdict);
commpact_status_t newContractChainGetSignatureCommpact(
    uint64_t enclave_id, contract_chain_t contract,
    cp_ec256_signature_t *return_signature, uint8_t num_signatures,
    cp_ec256_signature_t *signatures);
////////////////////////////////////////////////////////////////////////////////

// debug functions
////////////////////////////////////////////////////////////////////////////////
#ifdef COMMPACT_DEBUG
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
#endif
////////////////////////////////////////////////////////////////////////////////

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* COMMPACT_H */
