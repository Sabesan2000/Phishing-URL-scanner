# Automated Phishing URL Scanner & Response Bot

A Python-based security tool that automatically analyzes suspicious URLs for phishing threats using VirusTotal API and takes automated response actions.

## Features

- 🔍 **URL Analysis**: Comprehensive threat intelligence via VirusTotal API v3
- 🚨 **Threat Detection**: Multi-level risk assessment (HIGH/MEDIUM/LOW/CLEAN)
- 🛡️ **Automated Response**: Optional domain blocking for malicious URLs
- 📊 **Detailed Reporting**: Human-readable analysis results with confidence scores
- 📝 **Audit Logging**: Complete audit trail of all scans and actions
- 🚀 **Multiple Deployment Options**: CLI, AWS Lambda, or Docker

## Quick Start

### Prerequisites

- Python 3.8 or higher
- VirusTotal API key (free tier available at [virustotal.com](https://www.virustotal.com))

### Installation

1. **Clone or download this repository**

2. **Install dependencies**:
\`\`\`bash
pip install -r requirements.txt
\`\`\`

3. **Configure environment variables**:
\`\`\`bash
cp .env.example .env
# Edit .env and add your VirusTotal API key
\`\`\`

4. **Set your API key**:
\`\`\`bash
export VIRUSTOTAL_API_KEY="your_api_key_here"
\`\`\`

### Usage

#### CLI Mode

**Basic scan (analysis only)**:
\`\`\`bash
python scanner.py --url "http://suspicious-site.com/login"
\`\`\`

**Scan with automatic blocking**:
\`\`\`bash
python scanner.py --url "http://suspicious-site.com/login" --auto-block
\`\`\`

**Disable blocking explicitly**:
\`\`\`bash
python scanner.py --url "http://suspicious-site.com/login" --no-block
\`\`\`

#### Example Output

\`\`\`
============================================================
🔍 Analyzing URL: https://suspicious-site.com/login
📅 Timestamp: 2025-02-10T15:30:45.123456
============================================================

⏳ Querying VirusTotal API...

============================================================
📊 ANALYSIS RESULTS
============================================================

🚨 Threat Level: HIGH
📈 Confidence: 90%

🔢 Vendor Analysis:
   • Malicious: 8
   • Suspicious: 2
   • Clean: 75
   • Total Vendors: 85

💡 RECOMMENDATION:
   Block domain: suspicious-site.com
   Investigate further for IOCs
   Alert security team

⚠️  Threat detected! Taking response actions...
✅ Domain 'suspicious-site.com' added to block list
\`\`\`

## Deployment Options

### AWS Lambda

1. **Package the application**:
\`\`\`bash
pip install -r requirements.txt -t package/
cp *.py package/
cd package && zip -r ../lambda-deployment.zip . && cd ..
\`\`\`

2. **Create Lambda function**:
   - Runtime: Python 3.11
   - Handler: `lambda_handler.lambda_handler`
   - Timeout: 30 seconds
   - Memory: 256 MB

3. **Set environment variables** in Lambda configuration:
   - `VIRUSTOTAL_API_KEY`
   - `AUTO_BLOCK` (optional)
   - `HIGH_THREAT_THRESHOLD` (optional)

4. **Test with event**:
\`\`\`json
{
  "url": "http://suspicious-site.com/login",
  "action": "scan_and_block"
}
\`\`\`

### Docker

1. **Build the image**:
\`\`\`bash
docker build -t phishing-scanner .
\`\`\`

2. **Run as container**:
\`\`\`bash
docker run --rm \
  -e VIRUSTOTAL_API_KEY="your_api_key" \
  -e AUTO_BLOCK="false" \
  phishing-scanner --url "http://suspicious-site.com"
\`\`\`

3. **Run with volume for logs**:
\`\`\`bash
docker run --rm \
  -e VIRUSTOTAL_API_KEY="your_api_key" \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/blocks:/app/blocks \
  phishing-scanner --url "http://suspicious-site.com"
\`\`\`

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VIRUSTOTAL_API_KEY` | Yes | - | Your VirusTotal API key |
| `HIGH_THREAT_THRESHOLD` | No | 3 | Malicious vendor count for HIGH threat |
| `MEDIUM_THREAT_THRESHOLD` | No | 1 | Malicious vendor count for MEDIUM threat |
| `AUTO_BLOCK` | No | false | Enable automatic domain blocking |
| `SLACK_WEBHOOK_URL` | No | - | Slack webhook for notifications (future) |
| `TEAMS_WEBHOOK_URL` | No | - | Teams webhook for notifications (future) |

### Threat Levels

- **HIGH**: ≥3 security vendors flag as malicious (default)
- **MEDIUM**: 1-2 vendors flag as malicious OR ≥5 flag as suspicious
- **LOW**: Some vendors flag as suspicious
- **CLEAN**: No threats detected

## Security Considerations

⚠️ **Important Security Notes**:

1. **API Key Protection**: Never commit your VirusTotal API key to version control
2. **Blocking Actions**: Domain blocking requires appropriate system permissions
3. **Rate Limiting**: Free VirusTotal API has rate limits (4 requests/minute)
4. **False Positives**: Always review results before taking automated actions
5. **Audit Trail**: All scans are logged to `logs/` directory for compliance

## Testing

### Test with Known URLs

**Clean URL (should return CLEAN)**:
\`\`\`bash
python scanner.py --url "https://www.google.com"
\`\`\`

**Malicious URL (use VirusTotal test URLs)**:
\`\`\`bash
python scanner.py --url "http://malware.testing.google.test/testing/malware/"
\`\`\`

### Exit Codes

- `0`: Success - URL is clean
- `1`: Error occurred during scanning
- `2`: Threat detected (HIGH or MEDIUM)

## Project Structure

\`\`\`
phishing-scanner/
├── scanner.py              # Main application logic
├── virustotal_client.py    # VirusTotal API integration
├── blocker.py              # Domain blocking functionality
├── logger.py               # Logging utilities
├── config.py               # Configuration management
├── lambda_handler.py       # AWS Lambda entry point
├── Dockerfile              # Docker deployment
├── requirements.txt        # Python dependencies
├── .env.example            # Environment variable template
├── README.md               # This file
├── logs/                   # Scan logs (created automatically)
└── blocks/                 # Blocked domains list (created automatically)
\`\`\`

## Troubleshooting

### Common Issues

**"Required environment variable 'VIRUSTOTAL_API_KEY' not set"**
- Solution: Set the `VIRUSTOTAL_API_KEY` environment variable

**"Rate limit exceeded"**
- Solution: Wait 60 seconds between requests (free tier limitation)
- Consider upgrading to VirusTotal premium for higher limits

**"Insufficient permissions to modify hosts file"**
- Solution: Run with elevated privileges (sudo on Linux/Mac, Administrator on Windows)
- Or use the default logging-based blocking mechanism

**"Network error" or timeout**
- Solution: Check internet connectivity and firewall settings
- Verify VirusTotal API is accessible from your network

## Future Enhancements

- [ ] Asynchronous scanning for multiple URLs
- [ ] Slack/Teams webhook notifications
- [ ] Screenshot capability for phishing pages
- [ ] Integration with additional threat intelligence APIs (AbuseIPDB, URLScan.io)
- [ ] Historical analysis tracking and trending
- [ ] Web dashboard for scan management
- [ ] Quarantine functionality for suspicious domains

## License

This tool is provided for security research and incident response purposes. Use responsibly and in accordance with applicable laws and regulations.

## Support

For issues, questions, or contributions, please refer to the project documentation or contact your security team.
