import logging
import sys

def ip_to_str(ip_val: int) -> str:
    """Convert a uint32 integer (little-endian byte layout) to dotted IP string."""
    return f"{(ip_val >> 0) & 0xFF}.{(ip_val >> 8) & 0xFF}.{(ip_val >> 16) & 0xFF}.{(ip_val >> 24) & 0xFF}"

def str_to_ip(ip_str: str) -> int:
    """Convert dotted IP string to uint32 integer (little-endian byte layout)."""
    try:
        octets = [int(o) for o in ip_str.split('.')]
        if len(octets) != 4:
            raise ValueError()
        return octets[0] | (octets[1] << 8) | (octets[2] << 16) | (octets[3] << 24)
    except Exception:
        raise ValueError(f"Invalid IP address format: {ip_str}")

def mac_to_str(mac_bytes: bytes) -> str:
    """Convert 6 bytes MAC address to colons formatted string."""
    return ":".join(f"{b:02x}" for b in mac_bytes)

def setup_logging(verbose: bool = False) -> None:
    """Set up the application-wide logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    
    # Root logger configuration
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Standard output handler
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(formatter)
    
    # Clear existing handlers
    if root_logger.hasHandlers():
        root_logger.handlers.clear()
        
    root_logger.addHandler(stdout_handler)
