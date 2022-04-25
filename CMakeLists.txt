cmake_minimum_required(VERSION 3.13)

include(pico_sdk_import.cmake)

project(pico_usb_sniffer)

pico_sdk_init()

add_executable(pico_usb_sniffer
  pico_usb_sniffer.c
)

pico_generate_pio_header(pico_usb_sniffer ${CMAKE_CURRENT_LIST_DIR}/usb_sniff.pio)

target_link_libraries(pico_usb_sniffer pico_stdlib pico_multicore pico_stdio_usb hardware_pio hardware_dma hardware_irq)

pico_add_extra_outputs(pico_usb_sniffer)