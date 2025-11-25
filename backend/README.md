# Scamlytic API Backend

AI-Powered Scam Detection Platform - Django REST API Backend

## Overview

Scamlytic is a comprehensive scam detection platform that analyzes messages, URLs, phone numbers, and social media profiles to detect fraud, phishing, and scam attempts. The API combines multiple threat intelligence sources, advanced NLP algorithms, and LLM-based analysis for industry-leading accuracy.

## Features

### Analysis Capabilities

- **Message Analysis**: NLP-powered detection of scam patterns, urgency tactics, and social engineering
- **URL Analysis**: Multi-source threat intelligence (VirusTotal, Google Safe Browsing, PhishTank, URLhaus)
- **Phone Analysis**: Carrier detection, VoIP identification, fraud scoring, blocklist checks
- **Profile/Catfish Detection**: Reverse image search, AI-generated image detection, profile consistency analysis

### Key Differentiators vs. Competitors (VirusTotal, etc.)

1. **AI-Powered Analysis**: Uses GPT-4/Claude for contextual understanding
2. **Regional Expertise**: Specialized in Nigerian/African scam patterns (BVN, NIN phishing)
3. **Social Engineering Detection**: Identifies manipulation tactics, urgency language
4. **Comprehensive Reports**: Detailed explanations, not just scores
5. **Real-time Pattern Learning**: Crowdsourced scam reports improve detection

### Technical Features

- RESTful API with comprehensive documentation
- JWT and API key authentication
- Rate limiting by plan tier
- Webhook notifications
- Batch analysis support
- Scheduled reports
- Multi-source threat intelligence aggregation

## Architecture

```
backend/
├── scamlytic/           # Django project settings
├── apps/
│   ├── core/            # Base models, middleware, exceptions
│   ├── users/           # User management, API keys, auth
│   ├── analysis/        # Analysis endpoints and models
│   ├── reports/         # Report generation
│   └── integrations/    # Webhooks, external integrations
├── services/            # External API integrations
│   ├── llm_service.py   # OpenAI/Claude integration
│   ├── threat_intelligence.py  # VT, GSB, PhishTank
│   ├── message_analyzer.py
│   ├── url_analyzer.py
│   ├── phone_analyzer.py
│   └── image_analyzer.py
├── algorithms/          # Core detection algorithms
│   ├── text_analysis.py      # NLP analysis
│   ├── pattern_matcher.py    # Regex pattern matching
│   ├── risk_scorer.py        # Risk scoring engine
│   ├── url_parser.py         # URL analysis
│   └── phone_parser.py       # Phone number parsing
└── requirements.txt
```

## Installation

### Prerequisites

- Python 3.10+
- PostgreSQL 13+ (or SQLite for development)
- Redis 6+
- Virtual environment recommended

### Setup

1. Clone and navigate to backend:
```bash
cd backend
```

2. Create virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Configure environment:
```bash
cp .env.example .env
# Edit .env with your configuration
```

5. Run migrations:
```bash
python manage.py migrate
```

6. Create superuser:
```bash
python manage.py createsuperuser
```

7. Load initial data (threat types, patterns):
```bash
python manage.py loaddata initial_data
```

8. Start development server:
```bash
python manage.py runserver
```

### Running with Celery (for async tasks):
```bash
# Terminal 1: Redis
redis-server

# Terminal 2: Celery worker
celery -A scamlytic worker -l INFO

# Terminal 3: Celery beat (for scheduled tasks)
celery -A scamlytic beat -l INFO

# Terminal 4: Django
python manage.py runserver
```

## API Endpoints

### Base URL: `https://api.scamlytic.com/v1`

### Authentication

All endpoints require authentication via:
- Bearer token: `Authorization: Bearer scam_xxxxx`
- Or JWT: `Authorization: Bearer <jwt_token>`

### Analysis Endpoints

#### POST /v1/analyze/message/
Analyze text messages for scam indicators.

```json
{
    "content": "Your BVN has been flagged. Click here to verify: bit.ly/xxx",
    "context": "whatsapp",
    "sender_phone": "+234xxx"
}
```

#### POST /v1/analyze/url/
Check URL safety against multiple threat databases.

```json
{
    "url": "https://suspicious-site.com/login",
    "follow_redirects": true
}
```

#### POST /v1/analyze/phone/
Verify phone number reputation.

```json
{
    "phone": "+2348012345678"
}
```

#### POST /v1/analyze/profile/
Catfish detection for profile images.

```json
{
    "image_url": "https://example.com/profile.jpg",
    "profile_url": "https://instagram.com/username"
}
```

### Response Format

```json
{
    "scam_score": 85,
    "verdict": "HIGH_RISK",
    "threat_type": "BVN_PHISHING",
    "explanation": "This message contains BVN phishing indicators...",
    "recommended_action": "Do not respond. Block sender immediately.",
    "signals": ["bvn_phishing", "shortened_url", "urgency_language"],
    "request_id": "msg_abc123",
    "confidence": 0.92
}
```

### Threat Types

| Code | Description |
|------|-------------|
| `PHISHING_URL` | Malicious/phishing link detected |
| `BVN_PHISHING` | Bank Verification Number scam (Nigeria) |
| `NIN_PHISHING` | National ID Number scam (Nigeria) |
| `BANK_IMPERSONATION` | Fake bank communication |
| `LOTTERY_SCAM` | Fake prize/lottery |
| `ADVANCE_FEE` | 419/advance fee fraud |
| `ROMANCE_SCAM` | Dating scam |
| `JOB_SCAM` | Fake employment |
| `INVESTMENT_SCAM` | Ponzi/pyramid scheme |
| `CRYPTO_SCAM` | Cryptocurrency fraud |
| `CATFISH` | Fake profile detected |
| `LIKELY_SAFE` | No significant threats |

### Rate Limits

| Plan | Requests/Day | Requests/Minute |
|------|-------------|-----------------|
| Free | 50 | 10 |
| Pro | 10,000 | 100 |
| Developer | 10,000 | 60 |
| Business | 100,000 | 300 |
| Enterprise | Unlimited | 1000 |

## Configuration

### Required API Keys

For full functionality, configure these in `.env`:

| Service | Purpose | Required |
|---------|---------|----------|
| VIRUSTOTAL_API_KEY | URL/file reputation | Recommended |
| GOOGLE_SAFE_BROWSING_API_KEY | Phishing detection | Recommended |
| OPENAI_API_KEY | LLM analysis | Recommended |
| ANTHROPIC_API_KEY | Backup LLM | Optional |
| IPQUALITYSCORE_API_KEY | Phone/URL fraud scoring | Optional |
| TINEYE_API_KEY | Reverse image search | Optional |

The API works without these keys but with reduced accuracy.

## Development

### Running Tests
```bash
pytest
pytest --cov=apps  # with coverage
```

### Code Style
```bash
black .
flake8
isort .
```

### Generating Migrations
```bash
python manage.py makemigrations
python manage.py migrate
```

## Deployment

### Production Checklist

1. Set `DEBUG=False`
2. Generate secure `SECRET_KEY`
3. Configure PostgreSQL database
4. Set up Redis for caching
5. Configure allowed hosts
6. Enable HTTPS
7. Set up Celery workers
8. Configure error tracking (Sentry)
9. Set up monitoring

### Docker Deployment

```bash
docker-compose up -d
```

### Environment Variables

See `.env.example` for all configuration options.

## License

Proprietary - Scamlytic Inc.

## Support

- Documentation: https://docs.scamlytic.com
- Issues: https://github.com/scamlytic/api/issues
- Email: support@scamlytic.com
