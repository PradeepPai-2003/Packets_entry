import struct
import os
import logging
from typing import Optional, Dict, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class RawPacket:
    ts_sec: int
    ts_usec: int
    incl_len: int
    orig_len: int
    data: bytes

class PcapReader:
    def __init__(self):
        self._file = None
        self.fmt_prefix = "<"  # Default to little endian
        self.magic_number = 0
        self.version_major = 0
        self.version_minor = 0
        self.thiszone = 0
        self.sigfigs = 0
        self.snaplen = 65535
        self.network = 1  # Default Ethernet

    def open(self, filename: str) -> bool:
        """Open a PCAP file for reading."""
        self.close()
        try:
            self._file = open(filename, 'rb')
            header_data = self._file.read(24)
            if len(header_data) < 24:
                logger.error(f"PCAP global header too short ({len(header_data)} bytes)")
                self.close()
                return False

            # Unpack first with little endian to check magic
            magic = struct.unpack("<I", header_data[0:4])[0]
            if magic == 0xa1b2c3d4:
                self.fmt_prefix = "<"
            elif magic == 0xd4c3b2a1:
                self.fmt_prefix = ">"
            else:
                logger.error(f"Invalid PCAP magic number: 0x{magic:08x}")
                self.close()
                return False

            # Unpack the full global header
            fields = struct.unpack(f"{self.fmt_prefix}IHHIIII", header_data)
            self.magic_number = fields[0]
            self.version_major = fields[1]
            self.version_minor = fields[2]
            self.thiszone = fields[3]
            self.sigfigs = fields[4]
            self.snaplen = fields[5]
            self.network = fields[6]

            return True
        except Exception as e:
            logger.error(f"Could not open PCAP file {filename}: {e}")
            self.close()
            return False

    def read_next_packet(self) -> Optional[RawPacket]:
        """Read the next packet from the PCAP file. Returns None if EOF or error."""
        if not self._file:
            return None

        header_data = self._file.read(16)
        if not header_data or len(header_data) < 16:
            return None

        # Unpack packet header
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
            f"{self.fmt_prefix}IIII", header_data
        )

        # Sanity check on length to prevent memory issues
        if incl_len > self.snaplen or incl_len > 65535:
            logger.warning(f"Invalid packet length in PCAP: {incl_len} bytes")
            return None

        # Read actual packet payload
        packet_data = self._file.read(incl_len)
        if len(packet_data) < incl_len:
            logger.warning(f"Truncated packet data, expected {incl_len} bytes, got {len(packet_data)}")
            return None

        return RawPacket(
            ts_sec=ts_sec,
            ts_usec=ts_usec,
            incl_len=incl_len,
            orig_len=orig_len,
            data=packet_data
        )

    def close(self) -> None:
        """Close the file if open."""
        if self._file:
            self._file.close()
            self._file = None

    def get_global_header_dict(self) -> Dict[str, Any]:
        """Return global header fields as a dictionary."""
        return {
            "magic_number": self.magic_number,
            "version_major": self.version_major,
            "version_minor": self.version_minor,
            "thiszone": self.thiszone,
            "sigfigs": self.sigfigs,
            "snaplen": self.snaplen,
            "network": self.network,
            "fmt_prefix": self.fmt_prefix
        }


class PcapWriter:
    def __init__(self):
        self._file = None
        self.fmt_prefix = "<"

    def open(self, filename: str, global_header: Dict[str, Any]) -> bool:
        """Open a PCAP file for writing, writing the global header using the given fields."""
        self.close()
        try:
            self._file = open(filename, 'wb')
            self.fmt_prefix = global_header.get("fmt_prefix", "<")
            
            header_data = struct.pack(
                f"{self.fmt_prefix}IHHIIII",
                global_header.get("magic_number", 0xa1b2c3d4),
                global_header.get("version_major", 2),
                global_header.get("version_minor", 4),
                global_header.get("thiszone", 0),
                global_header.get("sigfigs", 0),
                global_header.get("snaplen", 65535),
                global_header.get("network", 1)
            )
            self._file.write(header_data)
            return True
        except Exception as e:
            logger.error(f"Could not open output PCAP file {filename}: {e}")
            self.close()
            return False

    def write_packet(self, ts_sec: int, ts_usec: int, data: bytes) -> bool:
        """Write a packet to the output PCAP file."""
        if not self._file:
            return False

        try:
            length = len(data)
            header_data = struct.pack(
                f"{self.fmt_prefix}IIII",
                ts_sec,
                ts_usec,
                length,
                length
            )
            self._file.write(header_data)
            self._file.write(data)
            return True
        except Exception as e:
            logger.error(f"Failed to write packet to PCAP: {e}")
            return False

    def close(self) -> None:
        """Close the file if open."""
        if self._file:
            self._file.close()
            self._file = None
