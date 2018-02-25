#ifndef ECU_H
#define ECU_H

#include "../include/commpact_types.h"
#include "../include/ecu_types.h"
#include <stdio.h>
#include <string.h>
typedef struct _ecu_t {
  ecu_message_t ecu_parameters;
  cp_ec256_public_t enclave_pub_key;
  cp_ec256_public_t ecu_pub_key;
  cp_ec256_private_t ecu_priv_key;
} ecu_t;
commpact_status_t setEnclavePubKey(ecu_t *ecu, cp_ec256_public_t *pub_key);
commpact_status_t setParametersECU(ecu_t *ecu,
                                   cp_ec256_signature_t *enclave_signature,
                                   ecu_message_t *message,
                                   cp_ec256_signature_t *ecu_signature);
commpact_status_t generateKeyPair(ecu_t *ecu, cp_ec256_public_t *pub_key);
commpact_status_t signMessage(ecu_t *ecu, ecu_message_t *message,
                              cp_ec256_signature_t *signature);
#endif /* ECU_H */
