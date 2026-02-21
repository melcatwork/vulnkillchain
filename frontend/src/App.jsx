import React, { useState, useEffect, useRef } from 'react'
import mermaid from 'mermaid'

// Initialize mermaid
mermaid.initialize({
  startOnLoad: false,
  theme: 'dark',
  securityLevel: 'loose',
})

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

function App() {
  const [searchTerm, setSearchTerm] = useState('')
  const [searchType, setSearchType] = useState('product') // product or cve
  const [results, setResults] = useState(null)
  const [selectedCve, setSelectedCve] = useState(null)
  const [attackData, setAttackData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [activeTab, setActiveTab] = useState('search') // search, cisa-kev
  const mermaidRef = useRef(null)

  useEffect(() => {
    if (attackData?.mermaid && mermaidRef.current) {
      renderMermaid(attackData.mermaid)
    }
  }, [attackData])

  const renderMermaid = async (graphDefinition) => {
    try {
      const { svg } = await mermaid.render('mermaid-graph', graphDefinition)
      mermaidRef.current.innerHTML = svg
    } catch (err) {
      console.error('Mermaid render error:', err)
      mermaidRef.current.innerHTML = '<p style="color: #ff6b6b;">Error rendering diagram</p>'
    }
  }

  const searchCves = async () => {
    if (!searchTerm.trim()) return
    
    setLoading(true)
    setError(null)
    setResults(null)
    setSelectedCve(null)
    setAttackData(null)
    
    try {
      const endpoint = searchType === 'product' 
        ? `/search?product=${encodeURIComponent(searchTerm)}&limit=10`
        : `/cve/${encodeURIComponent(searchTerm.toUpperCase())}`
      
      const response = await fetch(`${API_BASE}${endpoint}`)
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`)
      }
      
      const data = await response.json()
      setResults(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const getAttackMapping = async (cveId) => {
    setLoading(true)
    setError(null)
    setSelectedCve(cveId)
    
    try {
      const response = await fetch(`${API_BASE}/attack/${cveId}`)
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`)
      }
      
      const data = await response.json()
      setAttackData(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      searchCves()
    }
  }

  return (
    <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '20px' }}>
      {/* Header */}
      <header style={{ 
        textAlign: 'center', 
        marginBottom: '40px',
        padding: '40px 0',
        borderBottom: '1px solid rgba(255,255,255,0.1)'
      }}>
        <h1 style={{ 
          fontSize: '3rem', 
          background: 'linear-gradient(90deg, #00d4ff, #7c3aed)',
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent',
          marginBottom: '10px'
        }}>
          ⚔️ VulnKillChain
        </h1>
        <p style={{ color: '#888', fontSize: '1.1rem' }}>
          CVE Vulnerability Intelligence → MITRE ATT&CK Kill Chain
        </p>
      </header>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: '10px', marginBottom: '30px' }}>
        <button
          onClick={() => setActiveTab('search')}
          style={{
            padding: '12px 24px',
            background: activeTab === 'search' ? 'linear-gradient(90deg, #00d4ff, #7c3aed)' : 'rgba(255,255,255,0.05)',
            border: 'none',
            borderRadius: '8px',
            color: '#fff',
            cursor: 'pointer',
            fontSize: '1rem',
            fontWeight: '600'
          }}
        >
          🔍 CVE Search
        </button>
        <button
          onClick={() => setActiveTab('cisa-kev')}
          style={{
            padding: '12px 24px',
            background: activeTab === 'cisa-kev' ? 'linear-gradient(90deg, #00d4ff, #7c3aed)' : 'rgba(255,255,255,0.05)',
            border: 'none',
            borderRadius: '8px',
            color: '#fff',
            cursor: 'pointer',
            fontSize: '1rem',
            fontWeight: '600'
          }}
        >
          ⚠️ CISA KEV
        </button>
      </div>

      {activeTab === 'search' && (
        <>
          {/* Search Box */}
          <div style={{ 
            background: 'rgba(255,255,255,0.05)', 
            padding: '30px', 
            borderRadius: '16px',
            marginBottom: '30px'
          }}>
            <div style={{ display: 'flex', gap: '10px', marginBottom: '15px' }}>
              <button
                onClick={() => setSearchType('product')}
                style={{
                  padding: '8px 16px',
                  background: searchType === 'product' ? '#00d4ff' : 'transparent',
                  border: '1px solid #444',
                  borderRadius: '6px',
                  color: '#fff',
                  cursor: 'pointer'
                }}
              >
                By Product
              </button>
              <button
                onClick={() => setSearchType('cve')}
                style={{
                  padding: '8px 16px',
                  background: searchType === 'cve' ? '#00d4ff' : 'transparent',
                  border: '1px solid #444',
                  borderRadius: '6px',
                  color: '#fff',
                  cursor: 'pointer'
                }}
              >
                By CVE ID
              </button>
            </div>
            
            <div style={{ display: 'flex', gap: '10px' }}>
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                onKeyPress={handleKeyPress}
                placeholder={searchType === 'product' ? 'e.g., log4j, exchange, cisco ios' : 'e.g., CVE-2021-44228'}
                style={{
                  flex: 1,
                  padding: '16px 20px',
                  fontSize: '1.1rem',
                  background: 'rgba(0,0,0,0.3)',
                  border: '1px solid #333',
                  borderRadius: '10px',
                  color: '#fff',
                  outline: 'none'
                }}
              />
              <button
                onClick={searchCves}
                disabled={loading}
                style={{
                  padding: '16px 32px',
                  fontSize: '1.1rem',
                  background: 'linear-gradient(90deg, #00d4ff, #7c3aed)',
                  border: 'none',
                  borderRadius: '10px',
                  color: '#fff',
                  cursor: loading ? 'not-allowed' : 'pointer',
                  opacity: loading ? 0.7 : 1,
                  fontWeight: '600'
                }}
              >
                {loading ? 'Searching...' : 'Search'}
              </button>
            </div>
          </div>

          {/* Error Display */}
          {error && (
            <div style={{ 
              background: 'rgba(255,107,107,0.1)', 
              border: '1px solid #ff6b6b',
              padding: '20px', 
              borderRadius: '12px',
              marginBottom: '30px',
              color: '#ff6b6b'
            }}>
              ⚠️ Error: {error}
            </div>
          )}

          {/* Results */}
          {results && (
            <div style={{ marginBottom: '40px' }}>
              <h2 style={{ marginBottom: '20px', color: '#00d4ff' }}>
                {results.count || 1} Result{results.count !== 1 ? 's' : ''}
                {results.product && ` for "${results.product}"`}
              </h2>
              
              {/* CVE List or Single CVE */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
                {(results.cves || [results]).map((cve, idx) => (
                  <div
                    key={cve.id || idx}
                    onClick={() => cve.id && getAttackMapping(cve.id)}
                    style={{
                      background: 'rgba(255,255,255,0.05)',
                      padding: '20px',
                      borderRadius: '12px',
                      cursor: cve.id ? 'pointer' : 'default',
                      transition: 'all 0.2s',
                      border: selectedCve === cve.id ? '1px solid #00d4ff' : '1px solid transparent'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                      <h3 style={{ color: '#00d4ff', fontSize: '1.3rem' }}>{cve.id}</h3>
                      {cve.cvss_score && (
                        <span style={{
                          padding: '4px 12px',
                          borderRadius: '20px',
                          background: cve.cvss_score >= 9 ? '#ff4757' : cve.cvss_score >= 7 ? '#ffa502' : '#2ed573',
                          fontSize: '0.9rem',
                          fontWeight: 'bold'
                        }}>
                          {cve.cvss_score}
                        </span>
                      )}
                    </div>
                    <p style={{ color: '#aaa', lineHeight: '1.6' }}>
                      {cve.description?.substring(0, 300)}...
                    </p>
                    {cve.id && (
                      <p style={{ color: '#666', fontSize: '0.9rem', marginTop: '10px' }}>
                        Click to view ATT&CK kill chain →
                      </p>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Attack Mapping & Kill Chain */}
          {attackData && (
            <div style={{ marginTop: '40px' }}>
              <div style={{ 
                background: 'rgba(255,255,255,0.05)', 
                padding: '30px', 
                borderRadius: '16px' 
              }}>
                <h2 style={{ color: '#00d4ff', marginBottom: '10px' }}>
                  🎯 Kill Chain: {attackData.cve_id}
                </h2>
                <p style={{ color: '#888', marginBottom: '30px', lineHeight: '1.6' }}>
                  {attackData.description?.substring(0, 500)}
                </p>

                {/* Techniques */}
                {attackData.kill_chain?.length > 0 && (
                  <div style={{ marginBottom: '30px' }}>
                    <h3 style={{ marginBottom: '15px', color: '#7c3aed' }}>ATT&CK Tactics & Techniques</h3>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px' }}>
                      {attackData.kill_chain.map((item, idx) => (
                        <div
                          key={idx}
                          style={{
                            background: 'linear-gradient(135deg, #7c3aed22, #00d4ff22)',
                            padding: '12px 20px',
                            borderRadius: '8px',
                            border: '1px solid #7c3aed'
                          }}
                        >
                          <span style={{ color: '#00d4ff', fontWeight: 'bold' }}>
                            Phase {item.phase}
                          </span>
                          <span style={{ margin: '0 10px', color: '#666' }}>→</span>
                          <span style={{ color: '#fff' }}>{item.tactic_name}</span>
                          <span style={{ margin: '0 10px', color: '#666' }}>→</span>
                          <span style={{ color: '#7c3aed', fontFamily: 'monospace' }}>{item.technique_id}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Mermaid Kill Chain */}
                <div style={{ marginTop: '30px' }}>
                  <h3 style={{ marginBottom: '15px', color: '#7c3aed' }}>📊 Kill Chain Visualization</h3>
                  <div 
                    ref={mermaidRef}
                    style={{ 
                      background: 'rgba(0,0,0,0.3)', 
                      padding: '20px', 
                      borderRadius: '12px',
                      minHeight: '300px',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center'
                    }}
                  />
                  
                  {/* Mermaid Code for mermaid.live */}
                  <details style={{ marginTop: '20px' }}>
                    <summary style={{ cursor: 'pointer', color: '#666' }}>
                      View Mermaid Code
                    </summary>
                    <pre style={{ 
                      background: 'rgba(0,0,0,0.5)', 
                      padding: '15px', 
                      borderRadius: '8px',
                      overflow: 'auto',
                      marginTop: '10px',
                      fontSize: '0.85rem'
                    }}>
                      {attackData.mermaid}
                    </pre>
                  </details>
                </div>
              </div>
            </div>
          )}
        </>
      )}

      {activeTab === 'cisa-kev' && (
        <CisaKevList />
      )}

      {/* Footer */}
      <footer style={{ 
        textAlign: 'center', 
        marginTop: '60px', 
        padding: '20px',
        color: '#666',
        borderTop: '1px solid rgba(255,255,255,0.1)'
      }}>
        <p>Data sources: NVD, CISA KEV, EPSS</p>
        <p style={{ fontSize: '0.85rem', marginTop: '10px' }}>
          <a 
            href="https://mermaid.live" 
            target="_blank" 
            rel="noopener noreferrer"
            style={{ color: '#00d4ff' }}
          >
            Open in mermaid.live
          </a>
        </p>
      </footer>
    </div>
  )
}

function CisaKevList() {
  const [vulns, setVulns] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    fetch(`${API_BASE}/cisa-kev?limit=20`)
      .then(res => res.json())
      .then(data => setVulns(data.vulnerabilities || []))
      .catch(err => setError(err.message))
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <p style={{ textAlign: 'center', color: '#666' }}>Loading CISA KEV...</p>
  if (error) return <p style={{ color: '#ff6b6b' }}>Error: {error}</p>

  return (
    <div>
      <h2 style={{ marginBottom: '20px', color: '#ffa502' }}>
        ⚠️ CISA Known Exploited Vulnerabilities
      </h2>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
        {vulns.map((vuln, idx) => (
          <div
            key={idx}
            style={{
              background: 'rgba(255,255,255,0.05)',
              padding: '20px',
              borderRadius: '12px',
              borderLeft: '4px solid #ffa502'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3 style={{ color: '#ffa502' }}>{vuln.cve_id}</h3>
              <span style={{ color: '#666', fontSize: '0.9rem' }}>
                Added: {vuln.date_added}
              </span>
            </div>
            <p style={{ color: '#aaa', marginTop: '10px' }}>
              {vuln.vendor} → {vuln.product}
            </p>
            <p style={{ color: '#666', marginTop: '8px', fontSize: '0.9rem' }}>
              {vuln.short_description}
            </p>
          </div>
        ))}
      </div>
    </div>
  )
}

export default App
