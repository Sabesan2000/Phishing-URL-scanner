"""
AWS Lambda handler for serverless deployment
"""
import json
from scanner import PhishingScanner
from config import Config


def lambda_handler(event, context):
    """
    AWS Lambda entry point
    
    Expected event format:
    {
        "url": "http://suspicious-site.com/login",
        "action": "scan_and_block"  # or "scan_only"
    }
    """
    try:
        # Extract URL from event
        url = event.get('url')
        action = event.get('action', 'scan_only')
        
        if not url:
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'error': 'Missing required parameter: url'
                })
            }
        
        # Load configuration
        config = Config()
        
        # Set auto-block based on action
        config.auto_block = (action == 'scan_and_block')
        
        # Initialize scanner
        scanner = PhishingScanner(config)
        
        # Analyze URL
        results = scanner.analyze_url(url)
        
        # Return results
        return {
            'statusCode': 200,
            'body': json.dumps(results, indent=2)
        }
        
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e)
            })
        }
