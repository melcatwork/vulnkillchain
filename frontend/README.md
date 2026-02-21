# VulnKillChain Frontend

React + Vite frontend for CVE search and MITRE ATT&CK kill chain visualization.

## Setup

```bash
cd frontend
npm install
npm run dev
```

## Docker

```bash
docker build -t vulnkillchain-frontend .
docker run -p 3000:3000 vulnkillchain-frontend
```
