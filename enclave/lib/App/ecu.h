#ifndef ECU_H
#define ECU_H

//#include "sgx_tcrypto.h"
#include <stdio.h>
#include <string.h>

#include "../include/commpact_types.h"
#include "../include/ecu_types.h"

commpact_status_t setEnclavePubKey(cp_ec256_public_t *pub_key);
commpact_status_t setParametersECU(cp_ec256_signature_t *enclave_signature,
                                   ecu_message_t *message,
                                   cp_ec256_signature_t *ecu_signature);
commpact_status_t generateKeyPair(cp_ec256_public_t *pub_key);
commpact_status_t signMessage(ecu_message_t *message,
                              cp_ec256_signature_t *signature);
#endif /* ECU_H */
