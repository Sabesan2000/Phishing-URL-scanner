"""
Domain blocking functionality
Supports multiple blocking mechanisms
"""
import os
import platform
from typing import Dict


class DomainBlocker:
    """Handles domain blocking operations"""
    
    def __init__(self):
        self.system = platform.system()
        
    def block_domain(self, domain: str) -> str:
        """
        Block domain using appropriate mechanism
        Returns description of action taken
        """
        # For security reasons, we'll use a safe logging approach
        # rather than actually modifying system files
        
        action = self._log_block_action(domain)
        return action
    
    def _log_block_action(self, domain: str) -> str:
        """
        Log blocking action to file
        In production, this would integrate with firewall/security groups
        """
        try:
            # Create blocks directory if it doesn't exist
            os.makedirs('blocks', exist_ok=True)
            
            # Log to blocked domains file
            with open('blocks/blocked_domains.txt', 'a') as f:
                from datetime import datetime
                timestamp = datetime.utcnow().isoformat()
                f.write(f"{timestamp} | {domain}\n")
            
            return f"Domain '{domain}' added to block list"
            
        except Exception as e:
            return f"Failed to block domain: {str(e)}"
    
    def _add_to_hosts_file(self, domain: str) -> bool:
        """
        Add domain to hosts file (requires elevated privileges)
        This is a reference implementation - use with caution
        """
        hosts_path = self._get_hosts_path()
        
        try:
            # Read current hosts file
            with open(hosts_path, 'r') as f:
                content = f.read()
            
            # Check if domain already blocked
            if domain in content:
                return True
            
            # Add blocking entry
            with open(hosts_path, 'a') as f:
                f.write(f"\n127.0.0.1 {domain}\n")
                f.write(f"127.0.0.1 www.{domain}\n")
            
            return True
            
        except PermissionError:
            print("⚠️  Insufficient permissions to modify hosts file")
            return False
        except Exception as e:
            print(f"❌ Error modifying hosts file: {str(e)}")
            return False
    
    def _get_hosts_path(self) -> str:
        """Get hosts file path for current OS"""
        if self.system == 'Windows':
            return r'C:\Windows\System32\drivers\etc\hosts'
        else:  # Linux/Mac
            return '/etc/hosts'
