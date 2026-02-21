# VulnKillChain 🔥

> CVE Vulnerability Intelligence → MITRE ATT&CK Kill Chain Visualization

A web tool for cybersecurity engineers to query vulnerabilities in COTS products and generate MITRE ATT&CK-based cyber kill chain overviews.

## Features

- 🔍 **CVE Search** - Search by product name or CVE ID
- 🎯 **ATT&CK Mapping** - Automatic mapping to MITRE ATT&CK tactics/techniques  
- 📊 **Kill Chain Visualization** - Mermaid.js flowchart format
- ⚠️ **CISA KEV** - Known Exploited Vulnerabilities catalog
- 📈 **EPSS Scores** - Exploit Prediction Scoring System
- 📄 **Report Ready** - Copy Mermaid code for mermaid.live

## Tech Stack

| Component | Technology |
|-----------|------------|
| Frontend | React + Vite |
| Visualization | Mermaid.js |
| Backend | Python FastAPI |
| APIs | NVD, CISA KEV, EPSS |
| Hosting | Zeabur / Railway / Docker |

## Quick Start

### Local Development (Docker)

```bash
# Clone and navigate
cd vulnkillchain

# Start both services
docker-compose up --build

# Access
# Frontend: http://localhost:3000
# Backend API: http://localhost:8000
```

### Local Development (Manual)

```bash
# Backend
cd backend
pip install -r requirements.txt
uvicorn main:app --reload

# Frontend
cd frontend
npm install
npm run dev
```

### Deploy to Zeabur

1. Push to GitHub
2. Connect to Zeabur
3. Add both services:
   - `backend/` → port 8000
   - `frontend/` → port 3000 (with build command)

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check |
| `GET /search?product=<name>` | Search CVEs by product |
| `GET /cve/{cve_id}` | Get CVE details |
| `GET /attack/{cve_id}` | Get ATT&CK kill chain |
| `GET /cisa-kev` | CISA KEV list |
| `GET /epss/{cve_id}` | EPSS score |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VITE_API_URL` | `http://localhost:8000` | Backend API URL |

## Data Sources

- **NVD** (NIST) - National Vulnerability Database
- **CISA KEV** - Known Exploited Vulnerabilities Catalog
- **EPSS** - Exploit Prediction Scoring System (FIRST.org)

## License

MIT
