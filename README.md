# DARKWATCH Threat Intelligence Platform

Real-time threat intelligence aggregator pulling from 9 live threat feeds.

## Live Data Sources

| Feed | Type | Key Required |
|-----|------|-------------|
| AlienVault OTX | IoCs + Threat Pulses | Yes (free) |
| NVD | CVE Vulnerabilities | Optional |
| CISA KEV | Exploited CVEs | None |
| URLhaus | Malicious URLs | None |
| MalwareBazaar | Malware Hashes | None |
| Feodo Tracker | Botnet C2 IPs | None |
| ThreatFox | Multi-type IoCs | None |
| MITRE ATT&CK | Threat Actors + TTPs | None |
| PhishTank / OpenPhish | Phishing URLs | Optional |

## Quick Start

```bash
git clone https://github.com/kennedykwofie-debug/Ken-Projects
cd Ken-Projects
npm install
cp .env.example .env
npm start
```

Server starts at http://localhost:3001

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/v1/health | Health check |
| GET | /api/v1/stats | Dashboard stats |
| GET | /api/v1/threats | Threat feed |
| GET | /api/v1/iocs | Indicators of Compromise |
| GET | /api/v1/actors | Threat actors |
| GET | /api/v1/cves | CVEs |
| GET | /api/v1/phishing | Phishing campaigns |
| POST | /api/v1/cache/flush | Force refresh |

## Deploy to Railway

```bash
npm install -g @railway/cli
railway login
railway init
railway up
railway variables set OTX_API_KEY=your_key NVD_API_KEY=your_key
```
