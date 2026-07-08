import struct
from typing import Optional
from dataclasses import dataclass
from ..capture.pcap import RawPacket
from ..utils.helpers import mac_to_str, ip_to_str

# Protocol flag and number constants
class TCPFlags:
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20

class Protocol:
    ICMP = 1
    TCP = 6
    UDP = 17

class EtherType:
    IPv4 = 0x0800
    IPv6 = 0x86DD
    ARP = 0x0806

@dataclass
class ParsedPacket:
    # Timestamps
    timestamp_sec: int = 0
    timestamp_usec: int = 0
    
    # Ethernet layer
    src_mac: str = ""
    dest_mac: str = ""
    ether_type: int = 0
    
    # IP layer
    has_ip: bool = False
    ip_version: int = 0
    src_ip: str = ""
    dest_ip: str = ""
    protocol: int = 0
    ttl: int = 0
    
    # Transport layer
    has_tcp: bool = False
    has_udp: bool = False
    src_port: int = 0
    dest_port: int = 0
    
    # TCP-specific
    tcp_flags: int = 0
    seq_number: int = 0
    ack_number: int = 0
    
    # Payload
    payload_length: int = 0
    payload_offset: int = 0
    payload_data: Optional[bytes] = None

class PacketParser:
    @staticmethod
    def parse(raw: RawPacket) -> Optional[ParsedPacket]:
        """Parse a raw packet and return a ParsedPacket object, or None if invalid."""
        parsed = ParsedPacket(
            timestamp_sec=raw.ts_sec,
            timestamp_usec=raw.ts_usec
        )
        
        data = raw.data
        length = len(data)
        offset = 0
        
        # 1. Parse Ethernet Header (14 bytes)
        if length < 14:
            return None  # Packet too short for Ethernet header
            
        parsed.dest_mac = mac_to_str(data[0:6])
        parsed.src_mac = mac_to_str(data[6:12])
        parsed.ether_type = struct.unpack(">H", data[12:14])[0]
        offset = 14
        
        # 2. Parse IPv4 Header (if EtherType is IPv4)
        if parsed.ether_type == EtherType.IPv4:
            if length < offset + 20:
                return None  # Packet too short for IPv4 minimum header
                
            ip_header_start = offset
            version_ihl = data[ip_header_start]
            parsed.ip_version = (version_ihl >> 4) & 0x0F
            ihl = version_ihl & 0x0F  # Number of 32-bit words
            
            if parsed.ip_version != 4:
                return None  # Not IPv4
                
            ip_header_len = ihl * 4
            if ip_header_len < 20 or length < offset + ip_header_len:
                return None
                
            parsed.ttl = data[ip_header_start + 8]
            parsed.protocol = data[ip_header_start + 9]
            
            # Unpack source/destination IPs directly as uint32 little endian (matches std::memcpy on LE CPU)
            src_ip_val = struct.unpack("<I", data[ip_header_start + 12 : ip_header_start + 16])[0]
            dest_ip_val = struct.unpack("<I", data[ip_header_start + 16 : ip_header_start + 20])[0]
            
            parsed.src_ip = ip_to_str(src_ip_val)
            parsed.dest_ip = ip_to_str(dest_ip_val)
            parsed.has_ip = True
            
            offset += ip_header_len
            
            # 3. Parse Transport Layer
            if parsed.protocol == Protocol.TCP:
                if length < offset + 20:
                    return None
                    
                tcp_header_start = offset
                parsed.src_port, parsed.dest_port = struct.unpack(
                    ">HH", data[tcp_header_start : tcp_header_start + 4]
                )
                parsed.seq_number, parsed.ack_number = struct.unpack(
                    ">II", data[tcp_header_start + 4 : tcp_header_start + 12]
                )
                
                data_offset = (data[tcp_header_start + 12] >> 4) & 0x0F
                tcp_header_len = data_offset * 4
                
                parsed.tcp_flags = data[tcp_header_start + 13]
                
                if tcp_header_len < 20 or length < offset + tcp_header_len:
                    return None
                    
                parsed.has_tcp = True
                offset += tcp_header_len
                
            elif parsed.protocol == Protocol.UDP:
                if length < offset + 8:
                    return None
                    
                udp_header_start = offset
                parsed.src_port, parsed.dest_port = struct.unpack(
                    ">HH", data[udp_header_start : udp_header_start + 4]
                )
                
                parsed.has_udp = True
                offset += 8

        # 4. Set Payload info
        if offset < length:
            parsed.payload_length = length - offset
            parsed.payload_offset = offset
            parsed.payload_data = data[offset:]
        else:
            parsed.payload_length = 0
            parsed.payload_offset = length
            parsed.payload_data = b""
            
        return parsed

    @staticmethod
    def protocol_to_string(protocol: int) -> str:
        if protocol == Protocol.ICMP:
            return "ICMP"
        elif protocol == Protocol.TCP:
            return "TCP"
        elif protocol == Protocol.UDP:
            return "UDP"
        return f"Unknown({protocol})"

    @staticmethod
    def tcp_flags_to_string(flags: int) -> str:
        result = []
        if flags & TCPFlags.SYN:
            result.append("SYN")
        if flags & TCPFlags.ACK:
            result.append("ACK")
        if flags & TCPFlags.FIN:
            result.append("FIN")
        if flags & TCPFlags.RST:
            result.append("RST")
        if flags & TCPFlags.PSH:
            result.append("PSH")
        if flags & TCPFlags.URG:
            result.append("URG")
        return " ".join(result) if result else "none"
