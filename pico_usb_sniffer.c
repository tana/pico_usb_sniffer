// USB sniffing using PIO
// (Only for Full-Speed communications)
// References:
//   USB Made Simple, Part 3 - Data Flow, https://www.usbmadesimple.co.uk/ums_3.htm
//   USB (Communications) - Wikipedia, https://en.wikipedia.org/w/index.php?title=USB_(Communications)&oldid=1071371871

#include <stdio.h>
#include "pico/stdlib.h"
#include "pico/multicore.h"
#include "pico/util/queue.h"
#include "hardware/pio.h"
#include "hardware/clocks.h"
#include "usb_sniff.pio.h"

#define LED_PIN PICO_DEFAULT_LED_PIN
#define DP_PIN 11           // USB D+ pin
#define DM_PIN (DP_PIN + 1) // Next to the D+ pin (because of the restriction of PIO)

#define PIO_IRQ_EOP 0

#define CAPTURE_BUF_LEN 2048
#define PACKET_QUEUE_LEN 256

#define USB_SYNC 0x01   // USB sync pattern before NRZI encoding

// This structure represents position of a packet in capture_buf
typedef struct {
  uint start_pos;
  uint len;
} packet_pos_t;

// Ring buffer which stores data of received packets
uint8_t capture_buf[CAPTURE_BUF_LEN];
// For transmission of packet_pos_t from Core 1 to Core 0
queue_t packet_queue;

void usb_sniff_program_init(PIO pio, uint sm, uint offset, uint dp_pin)
{
  // Get default configuration for a PIO state machine
  pio_sm_config conf = usb_sniff_program_get_default_config(offset);
  // Input number 0 is assigned to USB D+ pin (GPIO number is dp_pin).
  // Input number 1 is USB D- pin (GPIO number is dp_pin+1).
  sm_config_set_in_pins(&conf, dp_pin);
  // Right shift (LSB first), autopush when 8 bits are read
  sm_config_set_in_shift(&conf, true, true, 8);
  // Right shift (LSB first), no autopull
  sm_config_set_out_shift(&conf, true, false, 32);
  // 120 MHz clock (10 x 12 Mbps)
  sm_config_set_clkdiv(&conf, (float)clock_get_hz(clk_sys) / 120000000);
  // Because only RX FIFO is needed, two FIFOs are combined into single RX FIFO.
  sm_config_set_fifo_join(&conf, PIO_FIFO_JOIN_RX);

  pio_gpio_init(pio, dp_pin);  // Allow PIO to use the specified pin
  pio_gpio_init(pio, dp_pin + 1);
  pio_sm_set_consecutive_pindirs(pio, sm, dp_pin, 2, false);  // Speicify D+ and D- pins as input

  pio_sm_init(pio, sm, offset, &conf);  // Initialize the state machine with the config created above

  pio_sm_set_enabled(pio, sm, true);  // Start the state machine
}

// Capture USB traffic on Core 1
void core1_main()
{
  PIO pio = pio0;

  // Load program into a PIO module and store the offset address where it is loaded
  uint offset = pio_add_program(pio, &usb_sniff_program);

  uint sm = pio_claim_unused_sm(pio, true);
  usb_sniff_program_init(pio, sm, offset, DP_PIN);

  uint packet_start_pos = 0;
  uint packet_len = 0;

  packet_pos_t current_packet = {
    .start_pos = 0,
    .len = 0
  };

  while (1) {
    if (pio_interrupt_get(pio, PIO_IRQ_EOP)) {
      pio_interrupt_clear(pio, PIO_IRQ_EOP);

      queue_add_blocking(&packet_queue, &current_packet); // Copy current_packet and send to Core 0

      current_packet.start_pos = (current_packet.start_pos + current_packet.len) % CAPTURE_BUF_LEN;
      current_packet.len = 0;
    }

    if (pio_sm_is_rx_fifo_full(pio, sm)) {
      gpio_put(LED_PIN, true);
      panic("RX FIFO full\n");
    } else {
      gpio_put(LED_PIN, false);
    }

    uint pos = (current_packet.start_pos + current_packet.len) % CAPTURE_BUF_LEN;
    capture_buf[pos] = pio_sm_get_blocking(pio, sm) >> 24;

    current_packet.len++;
  }
}

int main()
{
  // Change system clock to 120 MHz (10 times the frequency of USB Full Speed)
  set_sys_clock_khz(120000, true);

  stdio_usb_init();

  gpio_init(LED_PIN);
  gpio_set_dir(LED_PIN, true);

  queue_init(&packet_queue, sizeof(packet_pos_t), PACKET_QUEUE_LEN);

  multicore_launch_core1(core1_main); // Start core1_main on another core

  while (true) {
    packet_pos_t packet;
    // Receive a packet from Core 1
    queue_remove_blocking(&packet_queue, &packet);

    if (capture_buf[packet.start_pos] != USB_SYNC) {
      //printf("no sync %02X %02x len=%d\n", capture_buf[packet.start_pos], capture_buf[(packet.start_pos + 1) % CAPTURE_BUF_LEN], packet.len);
      continue; // Skip invalid packet which does not start with sync pattern
    }

    uint8_t second_byte = capture_buf[(packet.start_pos + 1) % CAPTURE_BUF_LEN];
    // First 4 bits of the second byte are bit-inversion of PID, and the rest are PID itself.
    if (((~(second_byte >> 4)) & 0xF) == (second_byte & 0xF)) {
      uint32_t pid = second_byte & 0xF;
      switch (pid) {
      case 0x5:
        printf("SOF ");
        break;
      case 0x1:
        printf("OUT ");
        break;
      case 0x9:
        printf("IN ");
        break;
      case 0xD:
        printf("SETUP ");
        break;
      case 0x3:
        printf("DATA0 ");
        break;
      case 0xB:
        printf("DATA1 ");
        break;
      case 0xC:
        printf("PRE ");
        break;
      default:
        printf("%2X ", pid);
      }
    } else {
      printf("bad pid %02X len=%d\n", second_byte, packet.len);
      continue; // Skip invalid packet which has a broken PID byte
    }

    printf("len=%d\n", packet.len);
  }
}