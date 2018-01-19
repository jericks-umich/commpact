#ifndef COMMPACT_STATUS_H
#define COMMPACT_STATUS_H

#define CP_MK_ERROR(x) (0x00000000 | (x))

typedef enum {
  CP_SUCCESS = CP_MK_ERROR(0x0000),
  CP_CANT_OPEN_FILE = CP_MK_ERROR(0x8001),
  CP_ERROR = CP_MK_ERROR(0x8002),
  CP_WARN = CP_MK_ERROR(0x8004),
} commpact_status_t;

#define CP_ECP256_KEY_SIZE 32
#define CP_NISTP_ECP256_KEY_SIZE (CP_ECP256_KEY_SIZE / sizeof(uint32_t))

typedef struct _cp_ec256_public_t {
  uint8_t gx[CP_ECP256_KEY_SIZE];
  uint8_t gy[CP_ECP256_KEY_SIZE];
} cp_ec256_public_t;

typedef struct _cp_ec256_signature_t {
  uint32_t x[CP_NISTP_ECP256_KEY_SIZE];
  uint32_t y[CP_NISTP_ECP256_KEY_SIZE];
} cp_ec256_signature_t;

#endif // COMMPACT_STATUS_H
