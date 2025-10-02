"""
VirusTotal API v3 client for URL reputation checking
"""
import time
import requests
from typing import Dict, Optional


class VirusTotalClient:
    """Client for interacting with VirusTotal API v3"""
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            'x-apikey': api_key,
            'Accept': 'application/json'
        })
        self.rate_limit_delay = 15  # seconds between requests (free tier)
        
    def scan_url(self, url: str, max_retries: int = 3) -> Optional[Dict]:
        """
        Scan URL using VirusTotal API
        Returns analysis results or None on failure
        """
        try:
            # Submit URL for analysis
            url_id = self._submit_url(url)
            
            if not url_id:
                return None
            
            # Wait for rate limiting
            time.sleep(2)
            
            # Get analysis results
            analysis = self._get_analysis(url_id, max_retries)
            
            return analysis
            
        except requests.exceptions.RequestException as e:
            print(f"❌ Network error: {str(e)}")
            return None
        except Exception as e:
            print(f"❌ Unexpected error: {str(e)}")
            return None
    
    def _submit_url(self, url: str) -> Optional[str]:
        """Submit URL to VirusTotal for analysis"""
        endpoint = f"{self.BASE_URL}/urls"
        
        try:
            response = self.session.post(
                endpoint,
                data={'url': url},
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                # Extract URL ID from response
                url_id = data.get('data', {}).get('id')
                return url_id
            elif response.status_code == 429:
                print("⚠️  Rate limit exceeded. Waiting...")
                time.sleep(self.rate_limit_delay)
                return self._submit_url(url)  # Retry
            else:
                print(f"❌ API error: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"❌ Failed to submit URL: {str(e)}")
            return None
    
    def _get_analysis(self, url_id: str, max_retries: int) -> Optional[Dict]:
        """Get analysis results for submitted URL"""
        endpoint = f"{self.BASE_URL}/analyses/{url_id}"
        
        for attempt in range(max_retries):
            try:
                response = self.session.get(endpoint, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    attributes = data.get('data', {}).get('attributes', {})
                    
                    # Check if analysis is complete
                    status = attributes.get('status')
                    
                    if status == 'completed':
                        return {
                            'stats': attributes.get('stats', {}),
                            'results': attributes.get('results', {}),
                            'status': status
                        }
                    elif status == 'queued':
                        print(f"⏳ Analysis queued, waiting... (attempt {attempt + 1}/{max_retries})")
                        time.sleep(5)
                        continue
                    else:
                        print(f"⚠️  Analysis status: {status}")
                        return None
                        
                elif response.status_code == 429:
                    print("⚠️  Rate limit exceeded. Waiting...")
                    time.sleep(self.rate_limit_delay)
                    continue
                else:
                    print(f"❌ API error: {response.status_code}")
                    return None
                    
            except Exception as e:
                print(f"❌ Failed to get analysis (attempt {attempt + 1}): {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(3)
                    continue
                return None
        
        print("❌ Max retries exceeded")
        return None
