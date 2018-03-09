#ifndef COMMPACT_H
#define COMMPACT_H

#define DEFAULT_ENCLAVE_FILENAME "/tmp/enclave.signed.so"
#define COMMPACT_DEBUG
#define USING_REAL_ECU 1
#define PORT 9999
#define SERVER_IP "192.168.0.2"

#include "../include/commpact_types.h"
#include "../include/ecu_types.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

// public (API exposed) functions
////////////////////////////////////////////////////////////////////////////////
commpact_status_t initEnclave(uint64_t *e_id);
commpact_status_t initEnclaveWithFilename(uint64_t *e_id,
                                          const char *enclave_filename);
commpact_status_t setInitialPosition(uint64_t enclave_id, int position);
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

// private (static) functions
////////////////////////////////////////////////////////////////////////////////
commpact_status_t setParametersRealECU(int position,
                                       cp_ec256_signature_t *enclave_signature,
                                       ecu_message_t *message,
                                       cp_ec256_signature_t *ecu_signature);
commpact_status_t setupSocket();
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
