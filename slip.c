// Packetization for serial communicaton using byte stuffing method of Serial Line Internet Protocol (SLIP)
// Reference:
//  Serial Line Internet Protocol - Wikipedia, https://en.wikipedia.org/w/index.php?title=Serial_Line_Internet_Protocol&oldid=1064759583
//  RFC 1055 - Nonstandard for transmission of IP datagrams over serial lines: SLIP, https://datatracker.ietf.org/doc/html/rfc1055

#include "slip.h"

size_t slip_encode(const uint8_t *input, size_t input_len, uint8_t *output)
{
  size_t pos = 0;
  for (size_t i = 0; i < input_len; i++) {
    uint8_t c = input[i];

    if (c == SLIP_END) {
      output[pos] = SLIP_ESC;
      pos++;
      output[pos] = SLIP_ESC_END;
      pos++;
    } else if (c == SLIP_ESC) {
      output[pos] = SLIP_ESC;
      pos++;
      output[pos] = SLIP_ESC_ESC;
      pos++;
    } else {
      output[pos] = c;
      pos++;
    }
  }

  output[pos] = SLIP_END;
  pos++;

  return pos;
}

size_t slip_decode(const uint8_t *input, size_t input_len, uint8_t *output)
{
  size_t pos = 0;
  for (size_t i = 0; i < input_len; i++) {
    uint8_t c = input[i];

    if (c == SLIP_ESC_END) {
      output[pos] = SLIP_END;
      pos++;
    } else if (c == SLIP_ESC_ESC) {
      output[pos] = SLIP_ESC;
      pos++;
    } else if (c == SLIP_ESC) {
      // ignore
    } else if (c == SLIP_END) {
      // ignore
    } else {
      output[pos] = c;
      pos++;
    }
  }

  return pos;
}