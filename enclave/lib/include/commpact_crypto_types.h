#include <stdint.h>

#ifndef _COMMPACT_CRYPTO_TYPES_H
#define _COMMPACT_CRYPTO_TYPES_H

#define CP_MK_ERROR(x) (0x00000000 | (x))
#define CP_ECP256_KEY_SIZE 32
#define CP_NISTP_ECP256_KEY_SIZE (CP_ECP256_KEY_SIZE / sizeof(uint32_t))
#define CP_SHA256_HASH_SIZE 32

typedef enum {
  CP_EC_VALID = CP_MK_ERROR(0x0000),
  CP_EC_INVALID_SIGNATURE = CP_MK_ERROR(0x8001),
} ec_generic_ecresult_t;

typedef struct _cp_ec256_public_t {
  uint8_t gx[CP_ECP256_KEY_SIZE];
  uint8_t gy[CP_ECP256_KEY_SIZE];
} cp_ec256_public_t;

typedef struct _cp_ec256_signature_t {
  uint32_t x[CP_NISTP_ECP256_KEY_SIZE];
  uint32_t y[CP_NISTP_ECP256_KEY_SIZE];
} cp_ec256_signature_t;

typedef struct _cp_ec256_private_t {
  uint8_t r[CP_ECP256_KEY_SIZE];
} cp_ec256_private_t;

#endif
