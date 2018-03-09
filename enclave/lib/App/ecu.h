#ifndef ECU_H
#define ECU_H

#include <stdio.h>
#include <string.h>

#include "../include/commpact_types.h"
#include "../include/ecu_types.h"

#define ECU_SOCK_MSG_TYPE 0x0
#define ECU_SOCK_PUB_KEY_TYPE 0x1
typedef struct _ecu_t {
  ecu_message_t ecu_parameters;
  cp_ec256_public_t enclave_pub_key;
  cp_ec256_public_t ecu_pub_key;
  cp_ec256_private_t ecu_priv_key;
} ecu_t;

commpact_status_t setEnclavePubKey(int position, cp_ec256_public_t *pub_key);
commpact_status_t setEnclavePubKeyRealECU(int position,
                                          cp_ec256_public_t *pub_key);
commpact_status_t getRealECUPubKey(int position, cp_ec256_public_t *pub_key);
commpact_status_t setParametersECU(int position,
                                   cp_ec256_signature_t *enclave_signature,
                                   ecu_message_t *message,
                                   cp_ec256_signature_t *ecu_signature);
commpact_status_t generateKeyPair(int position, cp_ec256_public_t *pub_key);
commpact_status_t signMessage(ecu_t *ecu, ecu_message_t *message,
                              cp_ec256_signature_t *signature);
commpact_status_t setParametersRealECU(int position,
                                       cp_ec256_signature_t *enclave_signature,
                                       ecu_message_t *message,
                                       cp_ec256_signature_t *ecu_signature);
commpact_status_t setupSocket();
#endif /* ECU_H */
