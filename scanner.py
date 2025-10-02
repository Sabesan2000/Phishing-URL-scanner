"""
Main phishing URL scanner module
Orchestrates URL analysis and response actions
"""
import sys
import argparse
from datetime import datetime
from typing import Dict, Optional
from urllib.parse import urlparse

from virustotal_client import VirusTotalClient
from blocker import DomainBlocker
from logger import ScanLogger
from config import Config


class PhishingScanner:
    """Main scanner class for analyzing URLs and taking response actions"""
    
    def __init__(self, config: Config):
        self.config = config
        self.vt_client = VirusTotalClient(config.virustotal_api_key)
        self.blocker = DomainBlocker()
        self.logger = ScanLogger()
        
    def normalize_url(self, url: str) -> str:
        """Normalize and validate URL format"""
        url = url.strip()
        
        # Add scheme if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        return url
    
    def extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        parsed = urlparse(url)
        return parsed.netloc
    
    def analyze_url(self, url: str) -> Dict:
        """
        Analyze URL for phishing threats
        Returns comprehensive analysis results
        """
        timestamp = datetime.utcnow().isoformat()
        
        try:
            # Normalize URL
            normalized_url = self.normalize_url(url)
            domain = self.extract_domain(normalized_url)
            
            print(f"\n{'='*60}")
            print(f"🔍 Analyzing URL: {normalized_url}")
            print(f"📅 Timestamp: {timestamp}")
            print(f"{'='*60}\n")
            
            # Query VirusTotal
            print("⏳ Querying VirusTotal API...")
            vt_results = self.vt_client.scan_url(normalized_url)
            
            if not vt_results:
                return {
                    'url': normalized_url,
                    'domain': domain,
                    'status': 'error',
                    'message': 'Failed to retrieve VirusTotal results',
                    'timestamp': timestamp
                }
            
            # Analyze threat level
            threat_analysis = self._analyze_threat_level(vt_results)
            
            # Prepare results
            results = {
                'url': normalized_url,
                'domain': domain,
                'timestamp': timestamp,
                'threat_level': threat_analysis['level'],
                'confidence': threat_analysis['confidence'],
                'malicious_count': threat_analysis['malicious'],
                'suspicious_count': threat_analysis['suspicious'],
                'clean_count': threat_analysis['clean'],
                'total_vendors': threat_analysis['total'],
                'status': 'success',
                'actions_taken': []
            }
            
            # Display results
            self._display_results(results)
            
            # Take response actions if malicious
            if threat_analysis['level'] in ['HIGH', 'MEDIUM']:
                if self.config.auto_block:
                    print(f"\n⚠️  Threat detected! Taking response actions...")
                    block_result = self.blocker.block_domain(domain)
                    results['actions_taken'].append(block_result)
                    print(f"✅ {block_result}")
                else:
                    print(f"\n⚠️  Threat detected! Auto-blocking disabled.")
                    print(f"💡 Recommendation: Block domain '{domain}' manually")
            
            # Log results
            self.logger.log_scan(results)
            
            return results
            
        except Exception as e:
            error_result = {
                'url': url,
                'status': 'error',
                'message': str(e),
                'timestamp': timestamp
            }
            print(f"\n❌ Error: {str(e)}")
            self.logger.log_scan(error_result)
            return error_result
    
    def _analyze_threat_level(self, vt_results: Dict) -> Dict:
        """Analyze VirusTotal results to determine threat level"""
        stats = vt_results.get('stats', {})
        
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        clean = stats.get('harmless', 0) + stats.get('undetected', 0)
        total = malicious + suspicious + clean
        
        # Determine threat level based on thresholds
        if malicious >= self.config.high_threat_threshold:
            level = 'HIGH'
            confidence = min(95, 70 + (malicious * 5))
        elif malicious >= self.config.medium_threat_threshold or suspicious >= 5:
            level = 'MEDIUM'
            confidence = min(85, 50 + (malicious * 7))
        elif suspicious > 0:
            level = 'LOW'
            confidence = 30 + (suspicious * 5)
        else:
            level = 'CLEAN'
            confidence = 95
        
        return {
            'level': level,
            'confidence': confidence,
            'malicious': malicious,
            'suspicious': suspicious,
            'clean': clean,
            'total': total
        }
    
    def _display_results(self, results: Dict):
        """Display analysis results in a readable format"""
        threat_level = results['threat_level']
        
        # Color coding for threat levels
        level_emoji = {
            'HIGH': '🚨',
            'MEDIUM': '⚠️',
            'LOW': '⚡',
            'CLEAN': '✅'
        }
        
        print(f"\n{'='*60}")
        print(f"📊 ANALYSIS RESULTS")
        print(f"{'='*60}")
        print(f"\n{level_emoji.get(threat_level, '❓')} Threat Level: {threat_level}")
        print(f"📈 Confidence: {results['confidence']}%")
        print(f"\n🔢 Vendor Analysis:")
        print(f"   • Malicious: {results['malicious_count']}")
        print(f"   • Suspicious: {results['suspicious_count']}")
        print(f"   • Clean: {results['clean_count']}")
        print(f"   • Total Vendors: {results['total_vendors']}")
        
        if threat_level in ['HIGH', 'MEDIUM']:
            print(f"\n💡 RECOMMENDATION:")
            print(f"   Block domain: {results['domain']}")
            print(f"   Investigate further for IOCs")
            print(f"   Alert security team")
        elif threat_level == 'LOW':
            print(f"\n💡 RECOMMENDATION:")
            print(f"   Monitor domain: {results['domain']}")
            print(f"   Consider additional analysis")
        else:
            print(f"\n💡 RECOMMENDATION:")
            print(f"   URL appears clean")
            print(f"   No immediate action required")


def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(
        description='Automated Phishing URL Scanner & Response Bot'
    )
    parser.add_argument(
        '--url',
        required=True,
        help='URL to scan for phishing threats'
    )
    parser.add_argument(
        '--auto-block',
        action='store_true',
        help='Automatically block malicious domains'
    )
    parser.add_argument(
        '--no-block',
        action='store_true',
        help='Disable automatic blocking (analysis only)'
    )
    
    args = parser.parse_args()
    
    # Load configuration
    config = Config()
    
    # Override auto-block setting if specified
    if args.auto_block:
        config.auto_block = True
    elif args.no_block:
        config.auto_block = False
    
    # Initialize scanner
    scanner = PhishingScanner(config)
    
    # Analyze URL
    results = scanner.analyze_url(args.url)
    
    # Exit with appropriate code
    if results['status'] == 'error':
        sys.exit(1)
    elif results.get('threat_level') in ['HIGH', 'MEDIUM']:
        sys.exit(2)  # Threat detected
    else:
        sys.exit(0)  # Clean


if __name__ == '__main__':
    main()
