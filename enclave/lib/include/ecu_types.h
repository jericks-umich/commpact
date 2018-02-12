#ifndef ECU_TYPES_H
#define ECU_TYPES_H

typedef struct _ecu_message_t {
  int position;
  uint8_t platoon_len;
  double lower_speed;
  double upper_speed;
  double lower_acc;
  double upper_acc;
  double max_decel;
  double recovery_phase_timeout;
} ecu_message_t;

#endif /* ECU_TYPES_H */
