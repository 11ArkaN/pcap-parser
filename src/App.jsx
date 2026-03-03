import React, { useState, useCallback, useMemo } from 'react';
import DropZone from './components/DropZone';
import DataTable from './components/DataTable';
import Charts from './components/Charts';
import LoadingOverlay from './components/LoadingOverlay';
import { parsePcap } from './utils/pcapParser';
import { enrichIpData } from './utils/whoisApi';

function App() {
  // Check if API is available
  React.useEffect(() => {
    if (!window.electronAPI) {
      console.error('electronAPI is not available!');
    } else if (!window.electronAPI.lookupIp) {
      console.error('lookupIp is not available in electronAPI!');
    } else {
      console.log('electronAPI.lookupIp is available');
    }
  }, []);

  const [fileData, setFileData] = useState(null);
  const [connections, setConnections] = useState([]);
  const [ipData, setIpData] = useState({});
  const [loading, setLoading] = useState(false);
  const [loadingProgress, setLoadingProgress] = useState({ current: 0, total: 0, text: '' });
  const [activeTab, setActiveTab] = useState('public');
  const [error, setError] = useState(null);

  const handleFileDrop = useCallback(async (buffer, fileName) => {
    try {
      setLoading(true);
      setError(null);
      setLoadingProgress({ current: 0, total: 0, text: 'Parsowanie pliku PCAP...' });

      const parsed = await parsePcap(buffer);
      
      if (parsed.length === 0) {
        throw new Error('Nie znaleziono polaczen IP w pliku');
      }

      setFileData({ name: fileName, packetCount: parsed.length });
      setConnections(parsed);

      const uniqueIps = [...new Set(parsed.flatMap(c => [c.src, c.dst]))];
      const publicIps = uniqueIps.filter(isPublicIp);

      setLoadingProgress({ 
        current: 0, 
        total: publicIps.length, 
        text: `Pobieranie danych WHOIS dla ${publicIps.length} adresow IP...` 
      });

      const enriched = {};
      for (let i = 0; i < publicIps.length; i++) {
        const ip = publicIps[i];
        enriched[ip] = await enrichIpData(ip);
        setLoadingProgress({ 
          current: i + 1, 
          total: publicIps.length, 
          text: `Pobieranie danych WHOIS dla ${publicIps.length} adresow IP...` 
        });
        
        if (i < publicIps.length - 1) {
          await new Promise(resolve => setTimeout(resolve, 100));
        }
      }

      setIpData(enriched);
      setLoading(false);
    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
  }, []);

  const publicConnections = useMemo(() => {
    return connections.filter(c => isPublicIp(c.src) || isPublicIp(c.dst));
  }, [connections]);

  const localConnections = useMemo(() => {
    return connections.filter(c => !isPublicIp(c.src) && !isPublicIp(c.dst));
  }, [connections]);

  const stats = useMemo(() => {
    const uniquePublicIps = [...new Set(publicConnections.flatMap(c => {
      const ips = [];
      if (isPublicIp(c.src)) ips.push(c.src);
      if (isPublicIp(c.dst)) ips.push(c.dst);
      return ips;
    }))];

    const uniqueAsns = [...new Set(Object.values(ipData).map(d => d.asn).filter(Boolean))];
    const countries = [...new Set(Object.values(ipData).map(d => d.country).filter(Boolean))];

    return {
      totalPackets: fileData?.packetCount || 0,
      publicIps: uniquePublicIps.length,
      asns: uniqueAsns.length,
      countries: countries.length
    };
  }, [publicConnections, ipData, fileData]);

  return (
    <div className="app">
      {loading && <LoadingOverlay progress={loadingProgress} />}
      
      <header className="header">
        <div className="header-content">
          <h1>Analizator PCAP</h1>
          {fileData && (
            <div className="header-stats">
              <span>Plik: <strong>{fileData.name}</strong></span>
              <span>Pakiety: <strong>{stats.totalPackets.toLocaleString()}</strong></span>
              <span>IP publiczne: <strong>{stats.publicIps}</strong></span>
              <span>ASN: <strong>{stats.asns}</strong></span>
              <span>Kraje: <strong>{stats.countries}</strong></span>
            </div>
          )}
        </div>
      </header>

      <main className="main-content">
        {!connections.length ? (
          <DropZone onFileDrop={handleFileDrop} error={error} />
        ) : (
          <>
            <Charts 
              connections={publicConnections} 
              ipData={ipData} 
            />

            <div className="tabs">
              <button 
                className={`tab ${activeTab === 'public' ? 'active' : ''}`}
                onClick={() => setActiveTab('public')}
              >
                IP Publiczne
                <span className="tab-badge">{publicConnections.length}</span>
              </button>
              <button 
                className={`tab ${activeTab === 'local' ? 'active' : ''}`}
                onClick={() => setActiveTab('local')}
              >
                Siec lokalna
                <span className="tab-badge">{localConnections.length}</span>
              </button>
            </div>

            <DataTable 
              connections={activeTab === 'public' ? publicConnections : localConnections}
              ipData={ipData}
              isPublic={activeTab === 'public'}
            />
          </>
        )}
      </main>
    </div>
  );
}

function isPublicIp(ip) {
  if (!ip || ip === '0.0.0.0' || ip === '255.255.255.255') return false;
  
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4) return false;
  
  if (parts[0] === 10) return false;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return false;
  if (parts[0] === 192 && parts[1] === 168) return false;
  if (parts[0] === 127) return false;
  if (parts[0] === 169 && parts[1] === 254) return false;
  if (parts[0] >= 224) return false;
  
  return true;
}

export default App;
