"""
VulnKillChain Backend - FastAPI
CVE Search + MITRE ATT&CK Mapping
"""

from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, List, Dict, Any
import httpx
import os
from datetime import datetime

app = FastAPI(
    title="VulnKillChain API",
    description="CVE vulnerability lookup with MITRE ATT&CK kill chain visualization",
    version="0.1.0"
)

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Data source URLs
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"

# MITRE ATT&CK tactic IDs (Enterprise)
ATTACK_TACTICS = {
    "TA0001": {"name": "Initial Access", "phase": 1},
    "TA0002": {"name": "Execution", "phase": 2},
    "TA0003": {"name": "Persistence", "phase": 3},
    "TA0004": {"name": "Privilege Escalation", "phase": 4},
    "TA0005": {"name": "Defense Evasion", "phase": 5},
    "TA0006": {"name": "Credential Access", "phase": 6},
    "TA0007": {"name": "Discovery", "phase": 7},
    "TA0008": {"name": "Lateral Movement", "phase": 8},
    "TA0009": {"name": "Collection", "phase": 9},
    "TA0010": {"name": "Command and Control", "phase": 10},
    "TA0011": {"name": "Exfiltration", "phase": 11},
    "TA0040": {"name": "Impact", "phase": 12},
}

# CVE to ATT&CK technique mapping (simplified - in production, use ATT&CK API)
CVE_ATTACK_MAPPING = {
    "CVE-2021-44228": ["T1190", "T1059"],  # Log4Shell - Exploit, Exec
    "CVE-2021-45046": ["T1190", "T1059"],
    "CVE-2023-20198": ["T1190", "T1133"],   # Cisco IOS XE
    "CVE-2023-4863": ["T1190", "T1203"],   # Chrome/WebRTC
    "CVE-2023-36884": ["T1190", "T1566"],   # Office
    "CVE-2024-3400": ["T1190", "T1048"],    # Palo Alto PAN-OS
}


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "VulnKillChain API"
    }


@app.get("/search")
async def search_cves(
    product: str = Query(..., description="Product name to search"),
    vendor: Optional[str] = Query(None, description="Vendor name"),
    limit: int = Query(10, ge=1, le=50)
) -> Dict[str, Any]:
    """
    Search for CVEs by product name
    Uses NVD API
    """
    async with httpx.AsyncClient(timeout=30.0) as client:
        params = {
            "keywordSearch": product,
            "resultsPerPage": limit
        }
        if vendor:
            params["keywordSearch"] = f"{vendor} {product}"
        
        try:
            response = await client.get(NVD_API_URL, params=params)
            response.raise_for_status()
            data = response.json()
            
            cves = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                
                # Extract CVSS score
                metrics = cve.get("metrics", {})
                cvss_data = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) if metrics.get("cvssMetricV31") else {}
                
                cves.append({
                    "id": cve_id,
                    "description": cve.get("descriptions", [{}])[0].get("value", ""),
                    "cvss_score": cvss_data.get("baseScore", "N/A"),
                    "severity": cvss_data.get("baseSeverity", "UNKNOWN"),
                    "published": cve.get("published", ""),
                    "references": [
                        ref.get("url", "") 
                        for ref in cve.get("references", [])[:5]
                    ]
                })
            
            return {
                "product": product,
                "vendor": vendor,
                "count": len(cves),
                "cves": cves
            }
            
        except httpx.HTTPError as e:
            raise HTTPException(status_code=502, detail=f"NVD API error: {str(e)}")


@app.get("/cve/{cve_id}")
async def get_cve_details(cve_id: str) -> Dict[str, Any]:
    """Get detailed info for a specific CVE"""
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.get(f"{NVD_API_URL}?cveId={cve_id}")
            response.raise_for_status()
            data = response.json()
            
            if not data.get("vulnerabilities"):
                raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
            
            cve = data["vulnerabilities"][0]["cve"]
            
            # Extract metrics
            metrics = cve.get("metrics", {})
            cvss = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) if metrics.get("cvssMetricV31") else metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
            
            return {
                "id": cve.get("id"),
                "description": cve.get("descriptions", [{}])[0].get("value", ""),
                "cvss_score": cvss.get("baseScore"),
                "severity": cvss.get("baseSeverity"),
                "vector": cvss.get("vectorString"),
                "published": cve.get("published"),
                "modified": cve.get("lastModified"),
                "references": [
                    {"url": ref.get("url"), "source": ref.get("source")}
                    for ref in cve.get("references", [])
                ],
                "weaknesses": [
                    w.get("description", [{}])[0].get("value")
                    for w in cve.get("weaknesses", [])
                ]
            }
            
        except httpx.HTTPError:
            raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")


@app.get("/attack/{cve_id}")
async def get_attack_mapping(cve_id: str) -> Dict[str, Any]:
    """
    Get MITRE ATT&CK mapping for a CVE
    Returns kill chain phases in Mermaid format
    """
    cve_id = cve_id.upper()
    
    # Get CVE details
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.get(f"{NVD_API_URL}?cveId={cve_id}")
            response.raise_for_status()
            data = response.json()
            
            if not data.get("vulnerabilities"):
                raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
            
            cve = data["vulnerabilities"][0]["cve"]
            description = cve.get("descriptions", [{}])[0].get("value", "")
            
        except httpx.HTTPError:
            raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
    
    # Get techniques from mapping (or infer from description)
    techniques = CVE_ATTACK_MAPPING.get(cve_id, [])
    
    # Infer techniques from CVE description (simple keyword matching)
    if not techniques:
        techniques = infer_attack_techniques(description)
    
    # Build kill chain phases
    kill_chain = []
    used_phases = set()
    
    for tech_id in techniques:
        # Map technique to tactic (simplified)
        tactic = technique_to_tactic(tech_id)
        if tactic and tactic["id"] not in used_phases:
            kill_chain.append({
                "phase": tactic["phase"],
                "tactic_id": tactic["id"],
                "tactic_name": tactic["name"],
                "technique_id": tech_id,
            })
            used_phases.add(tactic["id"])
    
    # Sort by phase
    kill_chain.sort(key=lambda x: x["phase"])
    
    # Generate Mermaid flowchart
    mermaid_graph = generate_mermaid_killchain(cve_id, kill_chain)
    
    return {
        "cve_id": cve_id,
        "description": description[:500],  # Truncate long descriptions
        "techniques": techniques,
        "kill_chain": kill_chain,
        "mermaid": mermaid_graph
    }


def infer_attack_techniques(description: str) -> List[str]:
    """Simple inference of ATT&CK techniques from CVE description"""
    description = description.lower()
    techniques = []
    
    # Common CVE to technique mappings
    keyword_map = {
        "remote code execution": ["T1190", "T1059"],
        "rce": ["T1190", "T1059"],
        "arbitrary code": ["T1190", "T1059"],
        "sql injection": ["T1190", "T1056"],
        "xss": ["T1189"],
        "cross-site scripting": ["T1189"],
        "privilege escalation": ["T1068"],
        "bypass": ["T1078", "T1110"],
        "authentication": ["T1078", "T1110"],
        "credential": ["T1110"],
        "memory corruption": ["T1190"],
        "buffer overflow": ["T1190"],
        "directory traversal": ["T1083"],
        "file inclusion": ["T1083"],
        "command injection": ["T1059"],
        "deserialization": ["T1058"],
    }
    
    for keyword, techs in keyword_map.items():
        if keyword in description:
            for tech in techs:
                if tech not in techniques:
                    techniques.append(tech)
    
    return techniques[:5]  # Limit to 5 techniques


def technique_to_tactic(technique_id: str) -> Optional[Dict]:
    """Map a technique ID to its primary tactic"""
    # Simplified mapping - in production use ATT&CK API
    mapping = {
        "T1190": ("TA0001", "Initial Access"),
        "T1059": ("TA0002", "Execution"),
        "T1068": ("TA0004", "Privilege Escalation"),
        "T1078": ("TA0001", "Initial Access"),
        "T1110": ("TA0006", "Credential Access"),
        "T1083": ("TA0007", "Discovery"),
        "T1189": ("TA0001", "Initial Access"),
        "T1056": ("TA0006", "Credential Access"),
        "T1048": ("TA0010", "Exfiltration"),
        "T1566": ("TA0001", "Initial Access"),
        "T1203": ("TA0001", "Initial Access"),
        "T1133": ("TA0001", "Initial Access"),
    }
    
    if technique_id in mapping:
        tactic_id, tactic_name = mapping[technique_id]
        return {
            "id": tactic_id,
            "name": tactic_name,
            "phase": ATTACK_TACTICS.get(tactic_id, {}).get("phase", 0)
        }
    return None


def generate_mermaid_killchain(cve_id: str, kill_chain: List[Dict]) -> str:
    """Generate Mermaid flowchart for the kill chain"""
    lines = [
        "flowchart LR",
        f'    title["Kill Chain: {cve_id}"]',
    ]
    
    phases = ["Recon", "Weaponize", "Deliver", "Exploit", "Install", "C2", "Actions"]
    
    for i, phase in enumerate(kill_chain, 1):
        tech = phase.get("technique_id", "")
        tactic = phase.get("tactic_name", "")
        lines.append(f'    P{i}[{tactic}]')
    
    # Add connections
    for i in range(1, len(kill_chain)):
        lines.append(f"    P{i} --> P{i+1}")
    
    return "\n".join(lines)


@app.get("/cisa-kev")
async def get_cisa_kev(limit: int = Query(10, ge=1, le=100)) -> Dict[str, Any]:
    """Get list of known exploited vulnerabilities from CISA KEV"""
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.get(CISA_KEV_URL)
            response.raise_for_status()
            data = response.json()
            
            vulns = data.get("vulnerabilities", [])[:limit]
            
            return {
                "count": len(vulns),
                "vulnerabilities": [
                    {
                        "cve_id": v.get("cveID"),
                        "vendor": v.get("vendorProject"),
                        "product": v.get("product"),
                        "date_added": v.get("dateAdded"),
                        "short_description": v.get("shortDescription", "")[:200],
                    }
                    for v in vulns
                ]
            }
            
        except httpx.HTTPError as e:
            raise HTTPException(status_code=502, detail=f"CISA KEV error: {str(e)}")


@app.get("/epss/{cve_id}")
async def get_epss(cve_id: str) -> Dict[str, Any]:
    """Get EPSS (Exploit Prediction Scoring System) score for a CVE"""
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.get(EPSS_API_URL, params={"cve": cve_id})
            response.raise_for_status()
            data = response.json()
            
            if data.get("status"] == "OK" and data.get("data"):
                return {
                    "cve_id": cve_id,
                    "epss_score": float(data["data"][0]["epss"]),
                    "percentile": float(data["data"][0]["percentile"]),
                    "date": data["data"][0]["date"]
                }
            else:
                raise HTTPException(status_code=404, detail=f"No EPSS data for {cve_id}")
                
        except httpx.HTTPError as e:
            raise HTTPException(status_code=502, detail=f"EPSS API error: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
