#ifndef COMMPACT_STATUS_H
#define COMMPACT_STATUS_H

#define CP_MK_ERROR(x) (0x00000000 | (x))

typedef enum {
  CP_SUCCESS = CP_MK_ERROR(0x0000),
  CP_CANT_OPEN_FILE = CP_MK_ERROR(0x8001),
  CP_ERROR = CP_MK_ERROR(0x8002),
  CP_WARN = CP_MK_ERROR(0x8004),
  CP_INVALID_PARAMETER = CP_MK_ERROR(0x8008),
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

// Contract Chain Message Type

#define MAX_PLATOON_VEHICLES 8

typedef struct _contract_chain_t {
  uint32_t contract_id;          // identifier for the contract
  uint32_t seq_num;              // identifier for the contract chain
  double sent_time;              // prevents acceptance of delayed packets
  double valid_time;             // chain is valid until this time
  double recovery_phase_timeout; // recovery phase extended to this time
  uint8_t chain_order[MAX_PLATOON_VEHICLES]; // array of vehicle positions;
                                             // contract chain should be passed
                                             // in this order
  float upper_speed;                         // maximum contract speed
  float lower_speed;                         // minimum contract speed
  float upper_accel;                         // maximum contract acceleration
  float lower_accel; // maximum negative contract acceleration
  uint8_t flags;     // flag bitmap: join = 0x4, leave = 0x2, split = 0x1
  float max_decel;   // declared maximum deceleration rate for a joining vehicle
} contract_chain_t;

#endif // COMMPACT_STATUS_H
