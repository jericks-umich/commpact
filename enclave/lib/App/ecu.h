#ifndef ECU_H
#define ECU_H

#include "sgx_tcrypto.h"
#include "string.h"

#include "../include/commpact_types.h"
#include "../include/ecu_types.h"

commpact_status_t setParametersECU(cp_ec256_signature_t *signature,
                                   ecu_message_t *message);

#endif /* ECU_H */
