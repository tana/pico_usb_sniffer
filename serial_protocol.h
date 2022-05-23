// Protocol for serial communication to PC

#include <stdint.h>

// Maximum length of command in bytes (before SLIP encoding)
#define SERIAL_MAX_CMD_LEN 32

typedef enum {
  SERIAL_PACKET_TYPE_USB = 0
} serial_packet_type_t;

typedef struct {
  uint8_t type; // One of serial_packet_type_t
  uint32_t timestamp;   // Time in microseconds
} __attribute__((packed)) serial_packet_header_t;

typedef enum {
  SERIAL_CMD_TYPE_START_CAPTURE = 0,
  SERIAL_CMD_TYPE_STOP_CAPTURE = 1,
  SERIAL_CMD_TYPE_SET_PID_FILTER = 2
} serial_cmd_type_t;

typedef struct {
  uint8_t type; // One of serial_cmd_type_t
} __attribute__((packed)) serial_start_capture_cmd_t;

typedef struct {
  uint8_t type; // One of serial_cmd_type_t
} __attribute__((packed)) serial_stop_capture_cmd_t;

typedef struct {
  uint8_t type; // One of serial_cmd_type_t
  uint16_t pid_ignore_flags;  // If k-th bit is 1, packets with PID k are ignored (k is a 4-bit number)
} __attribute__((packed)) serial_set_pid_filter_cmd_t;