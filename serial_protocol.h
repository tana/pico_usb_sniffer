// Protocol for serial communication to PC

#include <stdint.h>

typedef enum {
  SERIAL_PACKET_TYPE_USB = 0
} serial_packet_type_t;

typedef struct {
  uint32_t type; // One of serial_packet_type_t
  uint32_t timestamp;   // Time in microseconds
} serial_packet_header_t;