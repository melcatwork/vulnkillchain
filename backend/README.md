# VulnKillChain Backend

FastAPI backend for CVE lookup and MITRE ATT&CK mapping.

## Setup

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
```

## Docker

```bash
docker build -t vulnkillchain-backend .
docker run -p 8000:8000 vulnkillchain-backend
```

## API Endpoints

- `GET /health` - Health check
- `GET /search?product=<name>` - Search CVEs for a product
- `GET /cve/{cve_id}` - Get details for a specific CVE
- `GET /attack/{cve_id}` - Get MITRE ATT&CK mapping for a CVE
