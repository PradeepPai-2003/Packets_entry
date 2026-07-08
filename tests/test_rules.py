import unittest
import os
import tempfile
from my_packet_analyzer.rules.manager import RuleManager
from my_packet_analyzer.core.types import AppType
from my_packet_analyzer.utils.helpers import str_to_ip

class TestRuleManager(unittest.TestCase):
    def test_ip_blocking(self):
        manager = RuleManager()
        ip_str = "192.168.1.50"
        ip_val = str_to_ip(ip_str)
        
        self.assertFalse(manager.is_ip_blocked(ip_val))
        
        manager.block_ip(ip_str)
        self.assertTrue(manager.is_ip_blocked(ip_val))
        
        manager.unblock_ip(ip_str)
        self.assertFalse(manager.is_ip_blocked(ip_val))

    def test_app_blocking(self):
        manager = RuleManager()
        app = AppType.YOUTUBE
        
        self.assertFalse(manager.is_app_blocked(app))
        
        manager.block_app(app)
        self.assertTrue(manager.is_app_blocked(app))
        
        manager.unblock_app(app)
        self.assertFalse(manager.is_app_blocked(app))

    def test_domain_blocking_and_wildcard(self):
        manager = RuleManager()
        
        # Exact match
        manager.block_domain("facebook.com")
        self.assertTrue(manager.is_domain_blocked("facebook.com"))
        self.assertFalse(manager.is_domain_blocked("sub.facebook.com"))
        
        # Wildcard match
        manager.block_domain("*.tiktok.com")
        self.assertTrue(manager.is_domain_blocked("tiktok.com"))
        self.assertTrue(manager.is_domain_blocked("www.tiktok.com"))
        self.assertTrue(manager.is_domain_blocked("v16-web.tiktok.com"))
        self.assertFalse(manager.is_domain_blocked("nottiktok.com"))

    def test_save_load_rules(self):
        manager = RuleManager()
        manager.block_ip("10.0.0.5")
        manager.block_app(AppType.NETFLIX)
        manager.block_domain("*.github.com")
        manager.block_port(22)
        
        # Temporary file
        temp_fd, temp_path = tempfile.mkstemp()
        os.close(temp_fd)
        
        try:
            # Save rules
            self.assertTrue(manager.save_rules(temp_path))
            
            # Load into new manager
            new_manager = RuleManager()
            self.assertTrue(new_manager.load_rules(temp_path))
            
            # Verify rules loaded correctly
            self.assertTrue(new_manager.is_ip_blocked(str_to_ip("10.0.0.5")))
            self.assertTrue(new_manager.is_app_blocked(AppType.NETFLIX))
            self.assertTrue(new_manager.is_domain_blocked("api.github.com"))
            self.assertTrue(new_manager.is_port_blocked(22))
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

if __name__ == '__main__':
    unittest.main()
