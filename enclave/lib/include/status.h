#ifndef STATUS_H
#define STATUS_H

#define CP_MK_ERROR(x)       (0x00000000|(x))

typedef enum {
  CP_SUCCESS 		= CP_MK_ERROR(0x0000),
  CP_CANT_OPEN_FILE 	= CP_MK_ERROR(0x8001),
  CP_ERROR 			= CP_MK_ERROR(0x8002),
} commpact_status_t;

#endif // STATUS_H
