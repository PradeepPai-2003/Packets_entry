import threading
import logging
from typing import Optional, List, Set
from dataclasses import dataclass
from ..core.types import AppType, app_type_to_string
from ..utils.helpers import str_to_ip, ip_to_str

logger = logging.getLogger(__name__)

@dataclass
class BlockReason:
    type: str  # "IP", "PORT", "APP", "DOMAIN"
    detail: str

@dataclass
class RuleStats:
    blocked_ips: int
    blocked_apps: int
    blocked_domains: int
    blocked_ports: int

class RuleManager:
    def __init__(self):
        # Thread locks for concurrent access
        self._ip_lock = threading.Lock()
        self._app_lock = threading.Lock()
        self._domain_lock = threading.Lock()
        self._port_lock = threading.Lock()
        
        # Rule sets
        self._blocked_ips: Set[int] = set()
        self._blocked_apps: Set[AppType] = set()
        self._blocked_domains: Set[str] = set()
        self._domain_patterns: List[str] = []  # For wildcard matching (e.g. *.domain.com)
        self._blocked_ports: Set[int] = set()

    # ========== IP Blocking ==========
    
    def block_ip(self, ip: str) -> None:
        """Block a source IP (dotted string)."""
        ip_val = str_to_ip(ip)
        with self._ip_lock:
            self._blocked_ips.add(ip_val)
        logger.info(f"Blocked IP: {ip}")

    def unblock_ip(self, ip: str) -> None:
        """Unblock a source IP (dotted string)."""
        ip_val = str_to_ip(ip)
        with self._ip_lock:
            self._blocked_ips.discard(ip_val)
        logger.info(f"Unblocked IP: {ip}")

    def is_ip_blocked(self, ip_val: int) -> bool:
        """Check if an IP value is blocked."""
        with self._ip_lock:
            return ip_val in self._blocked_ips

    def get_blocked_ips(self) -> List[str]:
        """Get a list of blocked IPs as dotted strings."""
        with self._ip_lock:
            return [ip_to_str(ip) for ip in self._blocked_ips]

    # ========== Application Blocking ==========
    
    def block_app(self, app: AppType) -> None:
        """Block an application type."""
        with self._app_lock:
            self._blocked_apps.add(app)
        logger.info(f"Blocked app: {app_type_to_string(app)}")

    def unblock_app(self, app: AppType) -> None:
        """Unblock an application type."""
        with self._app_lock:
            self._blocked_apps.discard(app)
        logger.info(f"Unblocked app: {app_type_to_string(app)}")

    def is_app_blocked(self, app: AppType) -> bool:
        """Check if an application type is blocked."""
        with self._app_lock:
            return app in self._blocked_apps

    def get_blocked_apps(self) -> List[AppType]:
        """Get a list of blocked application types."""
        with self._app_lock:
            return list(self._blocked_apps)

    # ========== Domain Blocking ==========
    
    def block_domain(self, domain: str) -> None:
        """Block a domain name or pattern."""
        with self._domain_lock:
            if '*' in domain:
                if domain not in self._domain_patterns:
                    self._domain_patterns.append(domain)
            else:
                self._blocked_domains.add(domain)
        logger.info(f"Blocked domain: {domain}")

    def unblock_domain(self, domain: str) -> None:
        """Unblock a domain name or pattern."""
        with self._domain_lock:
            if '*' in domain:
                if domain in self._domain_patterns:
                    self._domain_patterns.remove(domain)
            else:
                self._blocked_domains.discard(domain)
        logger.info(f"Unblocked domain: {domain}")

    @staticmethod
    def domain_matches_pattern(domain: str, pattern: str) -> bool:
        """Check if domain matches pattern (supports *.example.com wildcards)."""
        # Handle *.example.com pattern
        if len(pattern) >= 2 and pattern.startswith("*."):
            suffix = pattern[1:]  # .example.com
            # Check if domain ends with .example.com
            if domain.endswith(suffix):
                return True
            # Check if domain matches the bare domain (example.com)
            if domain == pattern[2:]:
                return True
        return False

    def is_domain_blocked(self, domain: str) -> bool:
        """Check if a domain is blocked (exact or wildcard pattern)."""
        with self._domain_lock:
            if domain in self._blocked_domains:
                return True
                
            lower_domain = domain.lower()
            for pattern in self._domain_patterns:
                if self.domain_matches_pattern(lower_domain, pattern.lower()):
                    return True
            return False

    def get_blocked_domains(self) -> List[str]:
        """Get a list of all blocked domains and wildcard patterns."""
        with self._domain_lock:
            return list(self._blocked_domains) + self._domain_patterns

    # ========== Port Blocking ==========
    
    def block_port(self, port: int) -> None:
        """Block a destination port."""
        with self._port_lock:
            self._blocked_ports.add(port)
        logger.info(f"Blocked port: {port}")

    def unblock_port(self, port: int) -> None:
        """Unblock a destination port."""
        with self._port_lock:
            self._blocked_ports.discard(port)
        logger.info(f"Unblocked port: {port}")

    def is_port_blocked(self, port: int) -> bool:
        """Check if a destination port is blocked."""
        with self._port_lock:
            return port in self._blocked_ports

    def get_blocked_ports(self) -> List[int]:
        """Get a list of all blocked ports."""
        with self._port_lock:
            return list(self._blocked_ports)

    # ========== Combined Check ==========
    
    def should_block(
        self,
        src_ip: int,
        dst_port: int,
        app: AppType,
        domain: str
    ) -> Optional[BlockReason]:
        """Evaluate all rules and return BlockReason if blocked, else None."""
        if self.is_ip_blocked(src_ip):
            return BlockReason("IP", ip_to_str(src_ip))
            
        if self.is_port_blocked(dst_port):
            return BlockReason("PORT", str(dst_port))
            
        if self.is_app_blocked(app):
            return BlockReason("APP", app_type_to_string(app))
            
        if domain and self.is_domain_blocked(domain):
            return BlockReason("DOMAIN", domain)
            
        return None

    # ========== Rule Persistence ==========
    
    def save_rules(self, filename: str) -> bool:
        """Save rules to a text configuration file."""
        try:
            with open(filename, 'w') as f:
                f.write("[BLOCKED_IPS]\n")
                for ip in self.get_blocked_ips():
                    f.write(f"{ip}\n")
                    
                f.write("\n[BLOCKED_APPS]\n")
                for app in self.get_blocked_apps():
                    f.write(f"{app_type_to_string(app)}\n")
                    
                f.write("\n[BLOCKED_DOMAINS]\n")
                for domain in self.get_blocked_domains():
                    f.write(f"{domain}\n")
                    
                f.write("\n[BLOCKED_PORTS]\n")
                for port in self.get_blocked_ports():
                    f.write(f"{port}\n")
            logger.info(f"Rules saved to: {filename}")
            return True
        except Exception as e:
            logger.error(f"Error saving rules to {filename}: {e}")
            return False

    def load_rules(self, filename: str) -> bool:
        """Load rules from a configuration file."""
        try:
            current_section = ""
            with open(filename, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith('[') and line.endswith(']'):
                        current_section = line
                        continue
                        
                    if current_section == "[BLOCKED_IPS]":
                        self.block_ip(line)
                    elif current_section == "[BLOCKED_APPS]":
                        # Match string back to AppType
                        found = False
                        for i in range(static_cast_app_count := int(AppType.APP_COUNT.value)):
                            app = AppType(i)
                            if app_type_to_string(app) == line:
                                self.block_app(app)
                                found = True
                                break
                        if not found:
                            logger.warning(f"Unknown app name in rules: {line}")
                    elif current_section == "[BLOCKED_DOMAINS]":
                        self.block_domain(line)
                    elif current_section == "[BLOCKED_PORTS]":
                        try:
                            self.block_port(int(line))
                        except ValueError:
                            logger.warning(f"Invalid port in rules: {line}")
            logger.info(f"Rules loaded from: {filename}")
            return True
        except Exception as e:
            logger.error(f"Error loading rules from {filename}: {e}")
            return False

    def clear_all(self) -> None:
        """Clear all rules."""
        with self._ip_lock:
            self._blocked_ips.clear()
        with self._app_lock:
            self._blocked_apps.clear()
        with self._domain_lock:
            self._blocked_domains.clear()
            self._domain_patterns.clear()
        with self._port_lock:
            self._blocked_ports.clear()
        logger.info("All rules cleared")

    def get_stats(self) -> RuleStats:
        """Get statistics count for each type of rule."""
        with self._ip_lock:
            ips = len(self._blocked_ips)
        with self._app_lock:
            apps = len(self._blocked_apps)
        with self._domain_lock:
            domains = len(self._blocked_domains) + len(self._domain_patterns)
        with self._port_lock:
            ports = len(self._blocked_ports)
            
        return RuleStats(ips, apps, domains, ports)
