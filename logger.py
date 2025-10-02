"""
Logging utilities for scan results and actions
"""
import json
import os
from datetime import datetime
from typing import Dict


class ScanLogger:
    """Handles logging of scan results and actions"""
    
    def __init__(self, log_dir: str = 'logs'):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        
    def log_scan(self, results: Dict):
        """Log scan results to file"""
        try:
            # Create log filename with date
            date_str = datetime.utcnow().strftime('%Y-%m-%d')
            log_file = os.path.join(self.log_dir, f'scans_{date_str}.jsonl')
            
            # Append results as JSON line
            with open(log_file, 'a') as f:
                f.write(json.dumps(results) + '\n')
                
        except Exception as e:
            print(f"⚠️  Failed to log results: {str(e)}")
    
    def get_scan_history(self, days: int = 7) -> list:
        """Retrieve scan history for specified number of days"""
        history = []
        
        try:
            for i in range(days):
                date = datetime.utcnow() - timedelta(days=i)
                date_str = date.strftime('%Y-%m-%d')
                log_file = os.path.join(self.log_dir, f'scans_{date_str}.jsonl')
                
                if os.path.exists(log_file):
                    with open(log_file, 'r') as f:
                        for line in f:
                            history.append(json.loads(line))
            
            return history
            
        except Exception as e:
            print(f"⚠️  Failed to retrieve history: {str(e)}")
            return []
