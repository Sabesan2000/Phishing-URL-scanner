"""
Configuration management
Loads settings from environment variables
"""
import os
from typing import Optional


class Config:
    """Application configuration"""
    
    def __init__(self):
        # API Keys
        self.virustotal_api_key = self._get_required_env('VIRUSTOTAL_API_KEY')
        
        # Threat thresholds
        self.high_threat_threshold = int(os.getenv('HIGH_THREAT_THRESHOLD', '3'))
        self.medium_threat_threshold = int(os.getenv('MEDIUM_THREAT_THRESHOLD', '1'))
        
        # Response actions
        self.auto_block = os.getenv('AUTO_BLOCK', 'false').lower() == 'true'
        
        # Notification settings (for future expansion)
        self.slack_webhook = os.getenv('SLACK_WEBHOOK_URL', '')
        self.teams_webhook = os.getenv('TEAMS_WEBHOOK_URL', '')
        
    def _get_required_env(self, key: str) -> str:
        """Get required environment variable or raise error"""
        value = os.getenv(key)
        if not value:
            raise ValueError(f"Required environment variable '{key}' not set")
        return value
    
    def validate(self) -> bool:
        """Validate configuration"""
        if not self.virustotal_api_key:
            print("❌ VIRUSTOTAL_API_KEY not configured")
            return False
        
        if self.high_threat_threshold < self.medium_threat_threshold:
            print("⚠️  HIGH_THREAT_THRESHOLD should be >= MEDIUM_THREAT_THRESHOLD")
            return False
        
        return True
