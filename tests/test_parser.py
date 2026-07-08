import unittest
import struct
from my_packet_analyzer.capture.pcap import RawPacket
from my_packet_analyzer.parser.protocols import PacketParser, TCPFlags, Protocol, EtherType

class TestPacketParser(unittest.TestCase):
    def test_ethernet_only(self):
        # 14 bytes Ethernet header (MACs and EtherType ARP = 0x0806)
        dest_mac = b'\x00\x11\x22\x33\x44\x55'
        src_mac = b'\xaa\xbb\xcc\xdd\xee\xff'
        ethertype = struct.pack(">H", EtherType.ARP)
        data = dest_mac + src_mac + ethertype
        
        raw = RawPacket(ts_sec=100, ts_usec=200, incl_len=len(data), orig_len=len(data), data=data)
        parsed = PacketParser.parse(raw)
        
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.dest_mac, "00:11:22:33:44:55")
        self.assertEqual(parsed.src_mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(parsed.ether_type, EtherType.ARP)
        self.assertFalse(parsed.has_ip)

    def test_ipv4_tcp(self):
        # Ethernet (14 bytes)
        dest_mac = b'\x00\x11\x22\x33\x44\x55'
        src_mac = b'\xaa\xbb\xcc\xdd\xee\xff'
        ethertype = struct.pack(">H", EtherType.IPv4)
        
        # IP (20 bytes)
        version_ihl = 0x45
        tos = 0
        total_len = 40  # 20 IP + 20 TCP
        ident = 123
        flags_frag = 0
        ttl = 64
        protocol = Protocol.TCP
        checksum = 0
        src_ip = b'\xc0\xa8\x01\x64'  # 192.168.1.100
        dest_ip = b'\x0a\x00\x00\x01'  # 10.0.0.1
        ip_hdr = struct.pack(
            ">BBHHHBBH4s4s",
            version_ihl, tos, total_len, ident, flags_frag, ttl, protocol, checksum, src_ip, dest_ip
        )
        
        # TCP (20 bytes)
        src_port = 54321
        dst_port = 443
        seq = 10000
        ack = 20000
        data_offset = 0x50  # 5 * 4 = 20 bytes
        flags = TCPFlags.SYN | TCPFlags.ACK
        window = 65535
        tcp_checksum = 0
        urg = 0
        tcp_hdr = struct.pack(
            ">HHIIBBHHH",
            src_port, dst_port, seq, ack, data_offset, flags, window, tcp_checksum, urg
        )
        
        data = dest_mac + src_mac + ethertype + ip_hdr + tcp_hdr
        
        raw = RawPacket(ts_sec=100, ts_usec=200, incl_len=len(data), orig_len=len(data), data=data)
        parsed = PacketParser.parse(raw)
        
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.dest_mac, "00:11:22:33:44:55")
        self.assertEqual(parsed.src_mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(parsed.ether_type, EtherType.IPv4)
        
        self.assertTrue(parsed.has_ip)
        self.assertEqual(parsed.ip_version, 4)
        self.assertEqual(parsed.src_ip, "192.168.1.100")
        self.assertEqual(parsed.dest_ip, "10.0.0.1")
        self.assertEqual(parsed.protocol, Protocol.TCP)
        self.assertEqual(parsed.ttl, 64)
        
        self.assertTrue(parsed.has_tcp)
        self.assertEqual(parsed.src_port, 54321)
        self.assertEqual(parsed.dest_port, 443)
        self.assertEqual(parsed.seq_number, 10000)
        self.assertEqual(parsed.ack_number, 20000)
        self.assertEqual(parsed.tcp_flags, TCPFlags.SYN | TCPFlags.ACK)
        self.assertEqual(parsed.payload_length, 0)

if __name__ == '__main__':
    unittest.main()
