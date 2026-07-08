from typing import Optional
import struct

class SNIExtractor:
    CONTENT_TYPE_HANDSHAKE = 0x16
    HANDSHAKE_CLIENT_HELLO = 0x01
    EXTENSION_SNI = 0x0000
    SNI_TYPE_HOSTNAME = 0x00

    @staticmethod
    def is_tls_client_hello(payload: bytes) -> bool:
        length = len(payload)
        # Minimum TLS record: 5 bytes header + 4 bytes handshake header
        if length < 9:
            return False
            
        # Check TLS record header
        # Byte 0: Content Type (should be 0x16 = Handshake)
        if payload[0] != SNIExtractor.CONTENT_TYPE_HANDSHAKE:
            return False
            
        # Bytes 1-2: TLS Version
        version = (payload[1] << 8) | payload[2]
        if version < 0x0300 or version > 0x0304:
            return False
            
        # Bytes 3-4: Record length
        record_length = (payload[3] << 8) | payload[4]
        if record_length > length - 5:
            return False
            
        # Check handshake header (starts at byte 5)
        # Byte 5: Handshake Type (should be 0x01 = Client Hello)
        if payload[5] != SNIExtractor.HANDSHAKE_CLIENT_HELLO:
            return False
            
        return True

    @staticmethod
    def extract(payload: bytes) -> Optional[str]:
        if not SNIExtractor.is_tls_client_hello(payload):
            return None
            
        length = len(payload)
        
        # Skip TLS record header (5 bytes)
        offset = 5
        
        # Skip handshake header
        # Byte 0: Handshake type (1 byte, already checked)
        # Bytes 1-3: Length (3 bytes)
        if offset + 4 > length:
            return None
        handshake_length = (payload[offset + 1] << 16) | (payload[offset + 2] << 8) | payload[offset + 3]
        offset += 4
        
        # Client Hello body
        # Bytes 0-1: Client version (2 bytes)
        offset += 2
        
        # Bytes 2-33: Random (32 bytes)
        offset += 32
        
        # Session ID
        if offset >= length:
            return None
        session_id_length = payload[offset]
        offset += 1 + session_id_length
        
        # Cipher suites
        if offset + 2 > length:
            return None
        cipher_suites_length = (payload[offset] << 8) | payload[offset + 1]
        offset += 2 + cipher_suites_length
        
        # Compression methods
        if offset >= length:
            return None
        compression_methods_length = payload[offset]
        offset += 1 + compression_methods_length
        
        # Extensions
        if offset + 2 > length:
            return None
        extensions_length = (payload[offset] << 8) | payload[offset + 1]
        offset += 2
        
        extensions_end = offset + extensions_length
        if extensions_end > length:
            extensions_end = length  # Truncated, but try to parse anyway
            
        # Parse extensions to find SNI
        while offset + 4 <= extensions_end:
            extension_type = (payload[offset] << 8) | payload[offset + 1]
            extension_length = (payload[offset + 2] << 8) | payload[offset + 3]
            offset += 4
            
            if offset + extension_length > extensions_end:
                break
                
            if extension_type == SNIExtractor.EXTENSION_SNI:
                # SNI extension found
                # Structure:
                #   SNI List Length (2 bytes)
                #   SNI Type (1 byte) - 0x00 for hostname
                #   SNI Length (2 bytes)
                #   SNI Value (variable)
                
                if extension_length < 5:
                    break
                    
                sni_list_length = (payload[offset] << 8) | payload[offset + 1]
                if sni_list_length < 3:
                    break
                    
                sni_type = payload[offset + 2]
                sni_length = (payload[offset + 3] << 8) | payload[offset + 4]
                
                if sni_type != SNIExtractor.SNI_TYPE_HOSTNAME:
                    break
                if sni_length > extension_length - 5:
                    break
                    
                # Extract the hostname
                try:
                    sni = payload[offset + 5 : offset + 5 + sni_length].decode('ascii', errors='replace')
                    return sni
                except Exception:
                    break
                    
            offset += extension_length
            
        return None


class HTTPHostExtractor:
    @staticmethod
    def is_http_request(payload: bytes) -> bool:
        if len(payload) < 4:
            return False
            
        # Check for common HTTP methods
        methods = [b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI"]
        prefix = payload[0:4]
        return any(prefix == m for m in methods)

    @staticmethod
    def extract(payload: bytes) -> Optional[str]:
        if not HTTPHostExtractor.is_http_request(payload):
            return None
            
        length = len(payload)
        
        # Search for "Host: " case-insensitively
        # In C++, search checks for case-insensitive 'H','o','s','t',':'
        for i in range(length - 5):
            if (payload[i] in (72, 104) and      # 'H' or 'h'
                payload[i+1] in (111, 79) and    # 'o' or 'O'
                payload[i+2] in (115, 83) and    # 's' or 'S'
                payload[i+3] in (116, 84) and    # 't' or 'T'
                payload[i+4] == 58):             # ':'
                
                # Skip "Host:" and any leading whitespace
                start = i + 5
                while start < length and payload[start] in (32, 9):  # Space or Tab
                    start += 1
                    
                # Find end of line (\r or \n)
                end = start
                while end < length and payload[end] not in (13, 10):  # \r or \n
                    end += 1
                    
                if end > start:
                    try:
                        host = payload[start:end].decode('ascii', errors='replace')
                        
                        # Remove port if present
                        if ':' in host:
                            host = host.split(':')[0]
                            
                        return host
                    except Exception:
                        pass
                        
        return None


class DNSExtractor:
    @staticmethod
    def is_dns_query(payload: bytes) -> bool:
        # Minimum DNS header is 12 bytes
        if len(payload) < 12:
            return False
            
        # Check QR bit (byte 2, bit 7) - should be 0 for query
        flags = payload[2]
        if flags & 0x80:
            return False  # This is a response, not a query
            
        # Check QDCOUNT (bytes 4-5) - should be > 0
        qdcount = (payload[4] << 8) | payload[5]
        if qdcount == 0:
            return False
            
        return True

    @staticmethod
    def extract_query(payload: bytes) -> Optional[str]:
        if not DNSExtractor.is_dns_query(payload):
            return None
            
        length = len(payload)
        # DNS query starts at byte 12
        offset = 12
        domain_parts = []
        
        while offset < length:
            label_length = payload[offset]
            
            if label_length == 0:
                # End of domain name
                break
                
            if label_length > 63:
                # Compression pointer or invalid
                break
                
            offset += 1
            if offset + label_length > length:
                break
                
            try:
                part = payload[offset : offset + label_length].decode('ascii', errors='replace')
                domain_parts.append(part)
            except Exception:
                break
                
            offset += label_length
            
        return ".".join(domain_parts) if domain_parts else None


class QUICSNIExtractor:
    @staticmethod
    def is_quic_initial(payload: bytes) -> bool:
        if len(payload) < 5:
            return False
        # QUIC long header starts with 1 bit set (form bit)
        return (payload[0] & 0x80) != 0

    @staticmethod
    def extract(payload: bytes) -> Optional[str]:
        if not QUICSNIExtractor.is_quic_initial(payload):
            return None
            
        length = len(payload)
        # Search for TLS Client Hello pattern within the QUIC packet
        # Look for the handshake type byte (0x01) followed by SNI extension
        for i in range(5, length - 50):
            if payload[i] == 0x01:  # Client Hello handshake type
                # Try to extract SNI starting 5 bytes before this offset (assuming it represents TLS record header)
                result = SNIExtractor.extract(payload[i - 5 :])
                if result:
                    return result
                    
        return None
