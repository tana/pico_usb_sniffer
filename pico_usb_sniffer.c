// USB sniffing using PIO
// (Only for Full-Speed communications)
// References:
//   USB Made Simple, Part 3 - Data Flow, https://www.usbmadesimple.co.uk/ums_3.htm
//   USB (Communications) - Wikipedia, https://en.wikipedia.org/w/index.php?title=USB_(Communications)&oldid=1071371871

#include <stdio.h>
#include <malloc.h>
#include "pico/stdlib.h"
#include "pico/multicore.h"
#include "pico/util/queue.h"
#include "hardware/pio.h"
#include "hardware/clocks.h"
#include "hardware/dma.h"
#include "hardware/irq.h"
#include "usb_sniff.pio.h"

#define LED_PIN PICO_DEFAULT_LED_PIN
#define DP_PIN 11           // USB D+ pin
#define DM_PIN (DP_PIN + 1) // Next to the D+ pin (because of the restriction of PIO)

#define PIO_IRQ_EOP 0

#define CAPTURE_BUF_LEN 8192
#define PACKET_QUEUE_LEN 8192

#define USB_MAX_PACKET_LEN 1028 // Max length of a packet including sync pattern, PID, and CRC

#define USB_SYNC 0x01   // USB sync pattern before NRZI encoding

// This structure represents position of a packet in capture_buf
typedef struct {
  uint start_pos;
  uint len;
} packet_pos_t;

// Ring buffer which stores data of received packets
// Actual data is only 8 bits but store all 32 bits in the RX FIFO of PIO.
// This is inefficient (consumes 4x memory), but this is necessary due to restriction of DMA.
uint32_t capture_buf[CAPTURE_BUF_LEN];
// For transmission of packet_pos_t from Core 1 to Core 0
queue_t packet_queue;

// Start address of currently capturing packet
uint32_t *packet_start_addr;

// PIO instance used for USB sniffing
PIO sniff_pio;

// Number of DMA channel used for capturing
uint capture_dma_chan;

// Called when End of Packet is detected
void handle_eop_interrupt()
{
  pio_interrupt_clear(sniff_pio, pis_interrupt0);

  // Get current destination address of the DMA channel
  uint32_t *next_addr = (uint32_t*)(dma_hw->ch[capture_dma_chan].write_addr);

  // printf("%p %p\n", packet_start_addr, next_addr);

  if (next_addr != packet_start_addr) { // Skip if no data is captured (probably no USB device is connected)
    // The following two variables are numbers of uint32_t, not bytes.
    // (Subtracting a pointer from a pointer becomes number of elements, not bytes)
    uint start_pos = packet_start_addr - capture_buf;
    uint next_pos = next_addr - capture_buf;

    packet_pos_t packet_pos = {
      .start_pos = start_pos,
      .len = (next_pos > start_pos)
              ? (next_pos - start_pos)
              : ((CAPTURE_BUF_LEN - start_pos) + next_pos)
    };
    // printf("%p %p %p %d %d %d\n", capture_buf, packet_start_addr, next_addr, start_pos, next_pos, packet_pos.len);

    packet_start_addr = next_addr;

    queue_add_blocking(&packet_queue, &packet_pos); // Copy packet_pos and send to Core 0
  }
}

// Called when DMA completes transfer of data whose amount is specified in its setting
void handle_dma_complete_interrupt()
{
  dma_channel_acknowledge_irq0(capture_dma_chan);
  // printf("DMA finish\n");
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

  // Store some variables for use in interrupt handlers
  sniff_pio = pio;
  capture_dma_chan = dma_chan;
  packet_start_addr = capture_buf;

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
  irq_set_priority(DMA_IRQ_0, 0); // DMA interrupt has the highest priority (higher than End of Packet interrupt)
  irq_set_enabled(DMA_IRQ_0, true);
  
  dma_channel_start(dma_chan);  // Start DMA

  // Configure interrupt on End of Packet
  pio_set_irq0_source_enabled(pio, pis_interrupt0, true); // IRQ 0 from PIO SM generates system interrupt
  uint interrupt_num = (pio_get_index(pio) == 0) ? PIO0_IRQ_0 : PIO1_IRQ_0;
  irq_set_exclusive_handler(interrupt_num, handle_eop_interrupt); // Interrupt handler runs on current core
  irq_set_enabled(interrupt_num, true);

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

  while (true) {
    if (pio_sm_is_rx_fifo_full(pio, sm)) {
      gpio_put(LED_PIN, true);
      panic("RX FIFO full\n");
    } else {
      gpio_put(LED_PIN, false);
    }

    if (dma_hw->ch[dma_chan].ctrl_trig & 0x8000) {
      gpio_put(LED_PIN, true);
      panic("DMA bus error\n");
    }
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

    uint8_t first_byte = capture_buf[packet.start_pos] >> 24;
    uint8_t second_byte = capture_buf[(packet.start_pos + 1) % CAPTURE_BUF_LEN] >> 24;

    if (first_byte != USB_SYNC) {
      printf("no sync %02X %02X len=%d\n", first_byte, second_byte, packet.len);
      continue; // Skip invalid packet which does not start with sync pattern
    }

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