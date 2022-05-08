// Packetization for serial communicaton using byte stuffing method of Serial Line Internet Protocol (SLIP)
// Reference:
//  Serial Line Internet Protocol - Wikipedia, https://en.wikipedia.org/w/index.php?title=Serial_Line_Internet_Protocol&oldid=1064759583
//  RFC 1055 - Nonstandard for transmission of IP datagrams over serial lines: SLIP, https://datatracker.ietf.org/doc/html/rfc1055

#include <stdint.h>
#include <stddef.h>

#define SLIP_END 0xC0
#define SLIP_ESC 0xDB
#define SLIP_ESC_END 0xDC
#define SLIP_ESC_ESC 0xDD

// Calculate maximum length of encoded data from input data length
#define SLIP_MAX_ENCODED_LEN(input_len) (2 * (input_len) + 1)

// Encode bytes using SLIP
// Length of output array must be at least SLIP_MAX_ENCODED_LEN(input_len).
// Returns actual length of output.
size_t slip_encode(const uint8_t *input, size_t input_len, uint8_t *output);

// Decode SLIP-encoded bytes
// Length of output array must be same size or longer than input array.
// Returns actual length of output.
size_t slip_decode(const uint8_t *input, size_t input_len, uint8_t *output);