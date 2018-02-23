#include "../include/commpact_crypto_types.h"
#include "../include/commpact_types.h"
#ifndef _CP_CRYPTO_H
#define _CP_CRYPTO_H
commpact_status_t cp_ecc256_open_context(void **p_ecc_handle);
commpact_status_t cp_ecc256_close_context(void *ecc_handle);
commpact_status_t cp_ecc256_create_key_pair(cp_ec256_private_t *p_private,
                                            cp_ec256_public_t *p_public,
                                            void *ecc_handle);

commpact_status_t cp_ecdsa_sign(const uint8_t *p_data, uint32_t data_size,
                                cp_ec256_private_t *p_private,
                                cp_ec256_signature_t *p_signature,
                                void *ecc_handle);
commpact_status_t cp_ecdsa_verify(const uint8_t *p_data, uint32_t data_size,
                                  const cp_ec256_public_t *p_public,
                                  cp_ec256_signature_t *p_signature,
                                  uint8_t *p_result, void *ecc_handle);

#endif //_CP_CRYPTO_H
