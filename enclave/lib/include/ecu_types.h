#ifndef ECU_TYPES_H
#define ECU_TYPES_H

typedef struct _ecu_message_t {

  double recovery_phase_timeout;
  double upper_speed;
  double lower_speed;
  double upper_accel;
  double lower_accel;
  double max_decel;
  uint8_t num_vehicles;
  uint8_t position;
  uint8_t pad[6]; // make sure to pad this struct to 8-byte alignment
} ecu_message_t;

#endif /* ECU_TYPES_H */
