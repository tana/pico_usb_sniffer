#!/usr/bin/python

# Script for saving USB traffic captured by a Raspberry Pi Pico into a PCAP file
# References:
#   LibpcapFileFormat, https://wiki.wireshark.org/Development/LibpcapFileFormat
#   Link-layer header types, https://www.tcpdump.org/linktypes.html

import struct
import time
import serial
import sliplib

PCAP_LINKTYPE_USB_2_0 = 288

class PcapGlobalHeader:
    def __init__(self, thiszone=0, sigfigs=0, snaplen=65535, network=1):
        self.magic_number = 0xa1b2c3d4
        self.version_major = 2
        self.version_minor = 4
        self.thiszone = thiszone
        self.sigfigs = sigfigs
        self.snaplen = snaplen
        self.network = network

        # Create a precompiled struct format
        self.struct = struct.Struct('IHHiIII')
    

    def pack_into(self, buffer, offset):
        self.struct.pack_into(
            buffer, offset,
            self.magic_number,
            self.version_major,
            self.version_minor,
            self.thiszone,
            self.sigfigs,
            self.snaplen,
            self.network
        )
    

    def pack(self):
        buf = bytearray(self.struct.size)
        self.pack_into(buf, 0)
        return bytes(buf)


class PcapRecordHeader:
    def __init__(self, timestamp_sec, timestamp_usec, incl_len, orig_len):
        self.timestamp_sec = timestamp_sec
        self.timestamp_usec = timestamp_usec
        self.incl_len = incl_len
        self.orig_len = orig_len

        # Create a precompiled struct format
        self.struct = struct.Struct('IIII')
    

    def pack_into(self, buffer, offset):
        self.struct.pack_into(
            buffer, offset,
            self.timestamp_sec,
            self.timestamp_usec,
            self.incl_len,
            self.orig_len
        )
    

    def pack(self):
        buf = bytearray(self.struct.size)
        self.pack_into(buf, 0)
        return bytes(buf)


class PcapFileWriter:
    def __init__(self, path, timezone_offset=0, timestamp_accuracy=0, snapshot_len=65535, link_type=1):
        self.stream = open(path, 'wb')

        global_header = PcapGlobalHeader(timezone_offset, timestamp_accuracy, snapshot_len, link_type)
        self.stream.write(global_header.pack())


    def close(self):
        self.stream.close()


    # Called in the beginning of a "with" statement
    def __enter__(self):
        return self
    

    # Called in the end of a "with" statement
    def __exit__(self, exc_type, exc_val, exc_traceback):
        self.close()
        return False    # Does not suppress exception
    

    def write_packet(self, time_us, data, orig_len=None):
        if orig_len is None:
            orig_len = len(data)

        header = PcapRecordHeader(
            time_us // 1_000_000, time_us % 1_000_000,
            len(data), orig_len
        )
        
        self.stream.write(header.pack())
        self.stream.write(data)


SERIAL_PACKET_TYPE_USB = 0

class Sniffer:
    def __init__(self, port_name, out_path):
        # Baudrate has no meaning because it is a virtual serial port on USB
        # Serial port must not have timeout, because SlipStream treats 0-length bytes from stream as the end of stream.
        # (See: https://sliplib.readthedocs.io/en/master/module.html#slipwrapper )
        # It still allows interrupting by Ctrl-C because SlipStream seems to use another thread for receiving.
        self.serial = serial.Serial(port_name)
        self.slip_stream = sliplib.SlipStream(self.serial, chunk_size=1)

        self.pcap_file = PcapFileWriter(out_path, link_type=PCAP_LINKTYPE_USB_2_0)
    
    
    # Release resources
    def close(self):
        self.pcap_file.close()
        self.serial.close()
    

    # Called in the beginning of a "with" statement
    def __enter__(self):
        return self
    

    # Called in the end of a "with" statement
    def __exit__(self, exc_type, exc_val, exc_traceback):
        self.close()
        return False    # Does not suppress exception
    

    def capture(self):
        while True:
            packet = self.slip_stream.recv_msg()

            if len(packet) < 4:
                continue    # Wrong packet received from serial port (no packet type)

            packet_type = struct.unpack_from('<I', packet, 0)[0]
            if packet_type == SERIAL_PACKET_TYPE_USB:
                timestamp = struct.unpack_from('<I', packet, 4)[0]
                data = packet[8:]
                self.pcap_file.write_packet(timestamp, data)


if __name__ == '__main__':
    import sys
    with Sniffer('COM6', 'test.pcap') as sniffer:
        sniffer.capture()