import unittest
import struct
import random
from my_packet_analyzer.dpi.extractor import SNIExtractor, HTTPHostExtractor, DNSExtractor

class TestDPIExtractors(unittest.TestCase):
    def test_tls_sni_extraction(self):
        # Generate a TLS Client Hello with SNI
        sni = "www.youtube.com"
        
        # SNI extension
        sni_bytes = sni.encode('ascii')
        sni_entry = struct.pack('>BH', 0, len(sni_bytes)) + sni_bytes
        sni_list = struct.pack('>H', len(sni_entry)) + sni_entry
        sni_ext = struct.pack('>HH', 0x0000, len(sni_list)) + sni_list
        
        # Supported versions extension (TLS 1.3)
        supported_versions = struct.pack('>HHB', 0x002b, 3, 2) + struct.pack('>H', 0x0304)
        
        # All extensions
        extensions = sni_ext + supported_versions
        extensions_data = struct.pack('>H', len(extensions)) + extensions
        
        # Client Hello body
        client_version = struct.pack('>H', 0x0303)  # TLS 1.2
        random_bytes = bytes([1] * 32)
        session_id = struct.pack('B', 0)  # No session ID
        cipher_suites = struct.pack('>H', 4) + struct.pack('>HH', 0x1301, 0x1302)
        compression = struct.pack('BB', 1, 0)
        
        client_hello_body = client_version + random_bytes + session_id + cipher_suites + compression + extensions_data
        
        # Handshake header
        handshake = struct.pack('B', 0x01)  # Client Hello
        handshake += struct.pack('>I', len(client_hello_body))[1:]  # 3-byte length
        handshake += client_hello_body
        
        # TLS record header
        record = struct.pack('B', 0x16)  # Handshake
        record += struct.pack('>H', 0x0301)  # TLS 1.0
        record += struct.pack('>H', len(handshake))
        record += handshake
        
        # Extract SNI
        extracted = SNIExtractor.extract(record)
        self.assertEqual(extracted, sni)

    def test_http_host_extraction(self):
        payload = b"GET /index.html HTTP/1.1\r\nHost: www.facebook.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        extracted = HTTPHostExtractor.extract(payload)
        self.assertEqual(extracted, "www.facebook.com")

        # HTTP Host with port
        payload_with_port = b"POST /api HTTP/1.1\r\nHost: api.example.com:8080\r\n\r\n"
        extracted_with_port = HTTPHostExtractor.extract(payload_with_port)
        self.assertEqual(extracted_with_port, "api.example.com")

    def test_dns_query_extraction(self):
        domain = "google.com"
        txid = struct.pack('>H', 0x1234)
        flags = struct.pack('>H', 0x0100)  # Standard query
        counts = struct.pack('>HHHH', 1, 0, 0, 0)
        
        question = b''
        for label in domain.split('.'):
            question += struct.pack('B', len(label)) + label.encode()
        question += struct.pack('B', 0)  # Null terminator
        question += struct.pack('>HH', 1, 1)  # Type A, Class IN
        
        dns_data = txid + flags + counts + question
        
        extracted = DNSExtractor.extract_query(dns_data)
        self.assertEqual(extracted, domain)

if __name__ == '__main__':
    unittest.main()
