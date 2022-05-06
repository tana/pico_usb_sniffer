// USB sniffing using PIO
// (Only for Full-Speed communications)
// References:
//   USB Made Simple, Part 3 - Data Flow, https://www.usbmadesimple.co.uk/ums_3.htm
//   USB (Communications) - Wikipedia, https://en.wikipedia.org/w/index.php?title=USB_(Communications)&oldid=1071371871
//   USB 2.0 Specification, https://www.usb.org/document-library/usb-20-specification
//   Pico-PIO_USB, https://github.com/sekigon-gonnoc/Pico-PIO-USB

#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "pico/multicore.h"
#include "pico/util/queue.h"
#include "pico/time.h"
#include "hardware/pio.h"
#include "hardware/clocks.h"
#include "hardware/dma.h"
#include "hardware/irq.h"
#include "usb_sniff.pio.h"
#include "slip.h"
#include "serial_protocol.h"

#define LED_PIN PICO_DEFAULT_LED_PIN
#define DP_PIN 11           // USB D+ pin
#define DM_PIN (DP_PIN + 1) // Next to the D+ pin (because of the restriction of PIO)

#define PIO_IRQ_EOP 0

#define CAPTURE_BUF_LEN 8192
#define PACKET_QUEUE_LEN 8192

#define USB_MAX_PACKET_LEN 1028 // Max length of a packet including sync pattern, PID, and CRC

// Maximum length of packet (header + USB packet) sent to PC (before SLIP encoding)
// 1 is subtracted from USB_MAX_PACKET_LEN beceuse SYNC is not sent to the PC
#define SERIAL_MAX_PACKET_LEN (sizeof(serial_packet_header_t) + USB_MAX_PACKET_LEN - 1)

#define USB_SYNC 0x80   // USB sync pattern before NRZI encoding (because USB is LSB-first, actual bit sequence is reversed)

// This structure represents position of a packet in capture_buf
typedef struct {
  uint start_pos;
  uint len;
} packet_pos_t;

// Ring buffer which stores data of received packets
// We use 32 bits to store one byte of received data, because 0xFFFFFFFF is used to represent an End of Packet (EOP).
uint32_t capture_buf[CAPTURE_BUF_LEN];
// For transmission of packet_pos_t from Core 1 to Core 0
queue_t packet_queue;

// Number of DMA channel used for capturing
uint capture_dma_chan;

// Called when DMA completes transfer of data whose amount is specified in its setting
void handle_dma_complete_interrupt()
{
  dma_channel_acknowledge_irq0(capture_dma_chan);
  dma_channel_set_write_addr(capture_dma_chan, capture_buf, true);  // Restart DMA
}

void usb_sniff_program_init(PIO pio, uint sm, uint offset, uint dp_pin, uint dma_chan)
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

  // Store DMA channel number for use in interrupt handlers
  capture_dma_chan = dma_chan;

  // DMA configuration
  dma_channel_config chan_conf = dma_channel_get_default_config(dma_chan);
  channel_config_set_read_increment(&chan_conf, false); // Always read from same address (RX FIFO)
  channel_config_set_write_increment(&chan_conf, true); // Write address increases after writing each byte
  channel_config_set_transfer_data_size(&chan_conf, DMA_SIZE_32);  // Transfer 4 bytes at once
  channel_config_set_dreq(&chan_conf, pio_get_dreq(pio, sm, false));  // PIO SM requests DMA to transfer
  // Apply configuration to a DMA channel
  dma_channel_configure(
    dma_chan, &chan_conf,
    capture_buf,
    &pio->rxf[sm],
    CAPTURE_BUF_LEN,
    false  // Don't start now
  );
  
  // Interrupt when DMA transfer is finished
  // It is used to make DMA run forever and implement a ring buffer
  dma_channel_set_irq0_enabled(dma_chan, true); // DMA_IRQ_0 is fired when DMA completes
  irq_set_exclusive_handler(DMA_IRQ_0, handle_dma_complete_interrupt);  // Handler runs on current core
  irq_set_priority(DMA_IRQ_0, 0); // DMA interrupt has the highest priority
  irq_set_enabled(DMA_IRQ_0, true);
  
  dma_channel_start(dma_chan);  // Start DMA

  pio_sm_set_enabled(pio, sm, true);  // Start the state machine
}

// Capture USB traffic on Core 1
void core1_main()
{
  PIO pio = pio0;

  // Load program into a PIO module and store the offset address where it is loaded
  uint offset = pio_add_program(pio, &usb_sniff_program);

  uint sm = pio_claim_unused_sm(pio, true);
  uint dma_chan = dma_claim_unused_channel(true);
  usb_sniff_program_init(pio, sm, offset, DP_PIN, dma_chan);

  uint pos = 0;
  uint packet_start_pos = 0;

  while (true) {
    while (&capture_buf[pos] != (uint32_t*)(dma_hw->ch[capture_dma_chan].write_addr)) {
      if (capture_buf[pos] == 0xFFFFFFFF) { // When an EOP is detected
        packet_pos_t packet_pos = {
          .start_pos = packet_start_pos,
          .len = (pos > packet_start_pos)
                  ? (pos - packet_start_pos)
                  : ((CAPTURE_BUF_LEN - packet_start_pos) + pos)
        };
        queue_add_blocking(&packet_queue, &packet_pos); // Copy packet_pos and send to Core 0

        packet_start_pos = (pos + 1) % CAPTURE_BUF_LEN;
      }

      pos = (pos + 1) % CAPTURE_BUF_LEN;
    }
  }
}

int main()
{
  // Change system clock to 120 MHz (10 times the frequency of USB Full Speed)
  set_sys_clock_khz(120000, true);

  stdio_usb_init();

  // Initialize GPIO for error indicating LED
  gpio_init(LED_PIN);
  gpio_set_dir(LED_PIN, true);

  queue_init(&packet_queue, sizeof(packet_pos_t), PACKET_QUEUE_LEN);

  multicore_launch_core1(core1_main); // Start core1_main on another core

  uint8_t serial_packet[SERIAL_MAX_PACKET_LEN];
  uint8_t encoded_packet[SLIP_MAX_ENCODED_LEN(SERIAL_MAX_PACKET_LEN)];

  while (true) {
    packet_pos_t packet;
    // Receive a packet from Core 1
    queue_remove_blocking(&packet_queue, &packet);

    uint8_t first_byte = capture_buf[packet.start_pos] >> 24;

    if (first_byte != USB_SYNC) {
      gpio_put(LED_PIN, true);
      continue; // Skip invalid packet which does not start with sync pattern
    }

    if (packet.len == 1) {
      gpio_put(LED_PIN, true);
      continue; // Skip invalid packet which has no content
    }

    uint8_t second_byte = capture_buf[(packet.start_pos + 1) % CAPTURE_BUF_LEN] >> 24;

    // First 4 bits of the second byte are bit-inversion of PID, and the rest are PID itself.
    if (((~(second_byte >> 4)) & 0xF) != (second_byte & 0xF)) {
      gpio_put(LED_PIN, true);
      continue; // Skip invalid packet which has a broken PID byte (First 4 bits are not bit-inversion of the rest)
    }

    gpio_put(LED_PIN, false); // When a correct packet is received, turn off the LED

    // uint32_t pid = second_byte & 0xF;
    // TODO: packet filtering by PID
    
    serial_packet_header_t header = {
      .type = (uint8_t)SERIAL_PACKET_TYPE_USB,
      .timestamp = to_us_since_boot(get_absolute_time())  // Time is not actual capture time, but time of sending to PC
    };

    memcpy(serial_packet, &header, sizeof(serial_packet_header_t));

    // Copy packet content excluding the first SYNC byte
    for (int i = 1; i < packet.len; i++) {
      serial_packet[sizeof(serial_packet_header_t) + i - 1] = capture_buf[(packet.start_pos + i) % CAPTURE_BUF_LEN] >> 24;
    }

    size_t encoded_len = slip_encode(serial_packet, sizeof(serial_packet_header_t) + packet.len - 1, encoded_packet);

    // Send to PC
    fwrite(encoded_packet, encoded_len, 1, stdout);
    fflush(stdout);
  }
}