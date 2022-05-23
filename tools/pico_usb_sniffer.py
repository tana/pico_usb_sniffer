#!/usr/bin/python

# Script for saving USB traffic captured by a Raspberry Pi Pico into a PCAP file
# References:
#   LibpcapFileFormat, https://wiki.wireshark.org/Development/LibpcapFileFormat
#   Link-layer header types, https://www.tcpdump.org/linktypes.html
#   USB 2.0 Specification, https://www.usb.org/document-library/usb-20-specification

import sys
import struct
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
        if path == '-':
            self.stream = sys.stdout
        else:
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

class SerialPacketHeader:
    # Create a precompiled struct format as a class variable
    struct = struct.Struct('<BI')

    def __init__(self, type=SERIAL_PACKET_TYPE_USB, timestamp=0):
        self.type = type
        self.timestamp = timestamp
    

    @classmethod
    def unpack_from(cls, buffer, offset=0):
        type, timestamp = cls.struct.unpack_from(buffer, offset)
        return cls(type, timestamp)


    @classmethod
    def unpack(cls, buffer):
        return cls.unpack_from(buffer)


SERIAL_CMD_TYPE_START_CAPTURE = 0
SERIAL_CMD_TYPE_STOP_CAPTURE = 1
SERIAL_CMD_TYPE_SET_PID_FILTER = 2

class StartCaptureCommand:
    # Create a precompiled struct format as a class variable
    struct = struct.Struct('<B')

    def __init__(self):
        self.type = SERIAL_CMD_TYPE_START_CAPTURE
    

    def pack(self):
        return self.struct.pack(self.type)


    @classmethod
    def unpack_from(cls, buffer, offset=0):
        type = cls.struct.unpack_from(buffer, offset)
        assert type == SERIAL_CMD_TYPE_START_CAPTURE

        return cls(type)


    @classmethod
    def unpack(cls, buffer):
        return cls.unpack_from(buffer)


class StopCaptureCommand:
    # Create a precompiled struct format as a class variable
    struct = struct.Struct('<B')

    def __init__(self):
        self.type = SERIAL_CMD_TYPE_STOP_CAPTURE
    

    def pack(self):
        return self.struct.pack(self.type)


    @classmethod
    def unpack_from(cls, buffer, offset=0):
        type = cls.struct.unpack_from(buffer, offset)
        assert type == SERIAL_CMD_TYPE_STOP_CAPTURE

        return cls(type)


    @classmethod
    def unpack(cls, buffer):
        return cls.unpack_from(buffer)


class SetPidFilterCommand:
    # Create a precompiled struct format as a class variable
    struct = struct.Struct('<BH')

    def __init__(self, pid_ignore_flags):
        self.type = SERIAL_CMD_TYPE_SET_PID_FILTER
        self.pid_ignore_flags = pid_ignore_flags
    

    def pack(self):
        return self.struct.pack(self.type, self.pid_ignore_flags)


    @classmethod
    def unpack_from(cls, buffer, offset=0):
        type, pid_ignore_flags = cls.struct.unpack_from(buffer, offset)
        assert type == SERIAL_CMD_TYPE_SET_PID_FILTER

        return cls(type, pid_ignore_flags)


    @classmethod
    def unpack(cls, buffer):
        return cls.unpack_from(buffer)


# USB Packet Identifiers (PIDs)
# PIDs exclusive for High Speed mode are not included.
# Unlike actual order in USB signals, numbers are MSB first here.
USB_PIDS = {
    'OUT': 0b0001, 'IN': 0b1001, 'SOF': 0b0101, 'SETUP': 0b1101,
    'DATA0': 0b0011, 'DATA1': 0b1011, 'ACK': 0b0010, 'NAK': 0b1010,
    'STALL': 0b1110, 'PRE': 0b1100
}

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
        self.start_capture()

        try:
            while True:
                packet = self.slip_stream.recv_msg()

                if len(packet) < 1:
                    continue    # Wrong packet received from serial port (no packet type)

                packet_type = packet[0]
                if packet_type == SERIAL_PACKET_TYPE_USB:
                    header = SerialPacketHeader.unpack_from(packet, 0)
                    data = packet[SerialPacketHeader.struct.size:]
                    self.pcap_file.write_packet(header.timestamp, data)
        finally:
            self.stop_capture()
    
    
    def start_capture(self):
        self.slip_stream.send_msg(StartCaptureCommand().pack())


    def stop_capture(self):
        self.slip_stream.send_msg(StopCaptureCommand().pack())


    def set_pid_filter(self, pids_to_ignore):
        flags = 0
        for pid in pids_to_ignore:
            flags |= (1 << pid)
        
        cmd = SetPidFilterCommand(flags)
        self.slip_stream.send_msg(cmd.pack())


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('port', help='name of the serial port (e.g. COM1 on Windows or /dev/ttyACM0 on Linux).')
    parser.add_argument(
        '-o', '--output', default='-',
        help='path of output file. \'-\' indicates stdout. Default is \'-\'.'
    )
    parser.add_argument(
        '-i', '--ignore-pids', nargs='*',
        choices=USB_PIDS.keys(), default={},
        type=lambda pid: pid.upper(),    # Lower case is converted to upper case
        help='Packet Identifiers (PIDs, e.g. SOF or ACK) to ignore. Case-insensitive.',
        metavar='PID'
    )

    args = parser.parse_args()

    with Sniffer(args.port, args.output) as sniffer:
        sniffer.set_pid_filter({USB_PIDS[pid] for pid in args.ignore_pids})
        sniffer.capture()