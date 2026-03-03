import React, { useState, useMemo } from 'react';
import * as XLSX from 'xlsx';
import Papa from 'papaparse';

function DataTable({ connections, ipData, isPublic }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [sortConfig, setSortConfig] = useState({ key: null, direction: 'asc' });

  const aggregatedData = useMemo(() => {
    const grouped = {};
    
    connections.forEach(conn => {
      const key = `${conn.src}-${conn.dst}`;
      if (!grouped[key]) {
        grouped[key] = {
          src: conn.src,
          dst: conn.dst,
          protocol: conn.protocol,
          srcPort: conn.srcPort,
          dstPort: conn.dstPort,
          packetCount: 0,
          bytes: 0,
          services: new Set()
        };
      }
      grouped[key].packetCount += conn.packetCount || 1;
      grouped[key].bytes += conn.length || 0;
      if (conn.dstPort) {
        grouped[key].services.add(getServiceName(conn.dstPort));
      }
    });

    return Object.values(grouped).map(g => ({
      ...g,
      services: Array.from(g.services).join(', ')
    }));
  }, [connections]);

  const filteredData = useMemo(() => {
    let data = [...aggregatedData];
    
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      data = data.filter(row => 
        row.src.toLowerCase().includes(term) ||
        row.dst.toLowerCase().includes(term) ||
        (ipData[row.dst]?.asn?.toLowerCase().includes(term)) ||
        (ipData[row.dst]?.isp?.toLowerCase().includes(term)) ||
        (ipData[row.dst]?.country?.toLowerCase().includes(term))
      );
    }

    if (sortConfig.key) {
      data.sort((a, b) => {
        let aValue, bValue;
        const publicIpA = isPublicIp(a.dst) ? a.dst : a.src;
        const publicIpB = isPublicIp(b.dst) ? b.dst : b.src;
        const infoA = ipData[publicIpA] || {};
        const infoB = ipData[publicIpB] || {};
        
        switch (sortConfig.key) {
          case 'ip':
            aValue = publicIpA;
            bValue = publicIpB;
            break;
          case 'asn':
            aValue = infoA.asn || '';
            bValue = infoB.asn || '';
            break;
          case 'isp':
            aValue = infoA.isp || infoA.org || '';
            bValue = infoB.isp || infoB.org || '';
            break;
          case 'country':
            aValue = infoA.country || '';
            bValue = infoB.country || '';
            break;
          case 'packets':
            aValue = a.packetCount;
            bValue = b.packetCount;
            break;
          case 'bytes':
            aValue = a.bytes;
            bValue = b.bytes;
            break;
          default:
            aValue = a[sortConfig.key] || '';
            bValue = b[sortConfig.key] || '';
        }

        // Handle numeric vs string comparison
        if (typeof aValue === 'number' && typeof bValue === 'number') {
          return sortConfig.direction === 'asc' ? aValue - bValue : bValue - aValue;
        }
        
        // String comparison
        const aStr = String(aValue).toLowerCase();
        const bStr = String(bValue).toLowerCase();
        
        if (aStr < bStr) return sortConfig.direction === 'asc' ? -1 : 1;
        if (aStr > bStr) return sortConfig.direction === 'asc' ? 1 : -1;
        return 0;
      });
    }

    return data;
  }, [aggregatedData, searchTerm, sortConfig, ipData]);

  const handleSort = (key) => {
    setSortConfig(current => ({
      key,
      direction: current.key === key && current.direction === 'asc' ? 'desc' : 'asc'
    }));
  };

  const getSortIndicator = (key) => {
    if (sortConfig.key !== key) return '⇅';
    return sortConfig.direction === 'asc' ? '↑' : '↓';
  };

  const exportToCSV = () => {
    const exportData = prepareExportData(filteredData, ipData, isPublic);
    const csv = Papa.unparse(exportData);
    downloadFile(csv, 'analiza-pcap.csv', 'text/csv');
  };

  const exportToJSON = () => {
    const exportData = prepareExportData(filteredData, ipData, isPublic);
    const json = JSON.stringify(exportData, null, 2);
    downloadFile(json, 'analiza-pcap.json', 'application/json');
  };

  const exportToExcel = () => {
    const exportData = prepareExportData(filteredData, ipData, isPublic);
    const ws = XLSX.utils.json_to_sheet(exportData);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Analiza PCAP');
    XLSX.writeFile(wb, 'analiza-pcap.xlsx');
  };

  if (!connections.length) {
    return (
      <div className="empty-state">
        <div className="empty-state-icon"></div>
        <h3>Brak danych</h3>
        <p>Wczytaj plik PCAP aby zobaczyć analizę</p>
      </div>
    );
  }

  return (
    <div className="table-container">
      <div className="table-toolbar">
        <div className="table-search">
          <input
            type="text"
            placeholder="Szukaj po IP, ASN, ISP, Kraju..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
        <div className="export-buttons">
          <button className="btn btn-secondary" onClick={exportToCSV}>
            CSV
          </button>
          <button className="btn btn-secondary" onClick={exportToJSON}>
            JSON
          </button>
          <button className="btn btn-primary" onClick={exportToExcel}>
            Excel
          </button>
        </div>
      </div>

      <div className="data-table-wrapper">
        <table className="data-table">
          <thead>
            <tr>
              {isPublic && <>
                <th onClick={() => handleSort('ip')} style={{cursor: 'pointer'}}>
                  Adres IP {getSortIndicator('ip')}
                </th>
                <th onClick={() => handleSort('asn')} style={{cursor: 'pointer'}}>
                  ASN {getSortIndicator('asn')}
                </th>
                <th onClick={() => handleSort('isp')} style={{cursor: 'pointer'}}>
                  ISP / Organizacja {getSortIndicator('isp')}
                </th>
                <th onClick={() => handleSort('country')} style={{cursor: 'pointer'}}>
                  Lokalizacja {getSortIndicator('country')}
                </th>
                <th>Blok CIDR</th>
              </>}
              {!isPublic && <>
                <th>IP Źródłowe</th>
                <th>IP Docelowe</th>
              </>}
              <th>Usługa</th>
              <th onClick={() => handleSort('packets')} style={{cursor: 'pointer'}}>
                Pakiety {getSortIndicator('packets')}
              </th>
              <th onClick={() => handleSort('bytes')} style={{cursor: 'pointer'}}>
                Bajty {getSortIndicator('bytes')}
              </th>
              {isPublic && <th>Bezpieczeństwo</th>}
            </tr>
          </thead>
          <tbody>
            {filteredData.map((row, index) => {
              const publicIp = isPublicIp(row.dst) ? row.dst : row.src;
              const info = ipData[publicIp] || {};
              
              return (
                <tr key={index}>
                  {isPublic && <>
                    <td>
                      <span className="ip-address">{publicIp}</span>
                    </td>
                    <td>
                      {info.asn && (
                        <span className="asn-badge">{info.asn}</span>
                      )}
                    </td>
                    <td>{info.isp || info.org || 'Nieznane'}</td>
                    <td>
                      <div className="country-flag">
                        <span className="flag">{info.country && getFlagEmoji(info.country)}</span>
                        <div>
                          <div className="country-name">{info.country || 'Nieznane'}</div>
                          {info.city && <div className="country-city">{info.city}</div>}
                        </div>
                      </div>
                    </td>
                    <td>
                      <span className="cidr-block">{info.cidr || info.range || 'N/D'}</span>
                    </td>
                  </>}
                  {!isPublic && <>
                    <td><span className="ip-address ip-local">{row.src}</span></td>
                    <td><span className="ip-address ip-local">{row.dst}</span></td>
                  </>}
                  
                  <td>
                    <div className="service-info">
                      <span className="service-name">{row.services || 'Nieznane'}</span>
                      {row.dstPort && (
                        <span className="port-number">Port {row.dstPort}</span>
                      )}
                      <span className={`protocol-badge ${row.protocol.toLowerCase()}`}>
                        {row.protocol}
                      </span>
                    </div>
                  </td>
                  
                  <td>{row.packetCount.toLocaleString()}</td>
                  <td>{formatBytes(row.bytes)}</td>
                  
                  {isPublic && (
                    <td>
                      <SecurityAnalysis 
                        port={row.dstPort} 
                        protocol={row.protocol}
                        isp={info.isp}
                      />
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function SecurityAnalysis({ port, protocol, isp }) {
  let analysis = [];
  let level = 'safe';

  if (port === 443 || port === 8443) {
    analysis.push('HTTPS Szyfrowane');
  } else if (port === 80) {
    analysis.push('HTTP Nieszyfrowane');
    level = 'warning';
  } else if (port === 53) {
    analysis.push('DNS Standard');
    level = protocol === 'UDP' ? 'warning' : 'safe';
  } else if (port === 22) {
    analysis.push('SSH Bezpieczne');
  } else if (port > 49152) {
    analysis.push('Port Dynamiczny');
    level = 'warning';
  }

  if (isp) {
    const trusted = ['microsoft', 'google', 'amazon', 'cloudflare', 'akamai'];
    const isTrusted = trusted.some(t => isp.toLowerCase().includes(t));
    if (isTrusted) {
      analysis.push('Zaufany Dostawca');
    }
  }

  const className = `security-info security-${level}`;
  
  return (
    <div className={className}>
      {analysis.join(' / ') || 'Ruch Standardowy'}
    </div>
  );
}

function getServiceName(port) {
  const services = {
    20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
    25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
    143: 'IMAP', 443: 'HTTPS', 465: 'SMTPS', 587: 'SMTP',
    993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL', 3389: 'RDP',
    5432: 'PostgreSQL', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
  };
  return services[port] || `Port-${port}`;
}

function getFlagEmoji(countryCode) {
  const codePoints = countryCode
    .toUpperCase()
    .split('')
    .map(char =>  127397 + char.charCodeAt());
  return String.fromCodePoint(...codePoints);
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
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

function prepareExportData(data, ipData, isPublic) {
  return data.map(row => {
    const publicIp = isPublicIp(row.dst) ? row.dst : row.src;
    const info = ipData[publicIp] || {};
    
    return {
      'Adres IP': publicIp,
      'ASN': info.asn || 'N/D',
      'ISP/Organizacja': info.isp || info.org || 'Nieznane',
      'Kraj': info.country || 'Nieznane',
      'Miasto': info.city || 'N/D',
      'Blok CIDR': info.cidr || info.range || 'N/D',
      'Usługa': row.services || 'Nieznane',
      'Port': row.dstPort || 'N/D',
      'Protokół': row.protocol,
      'Pakiety': row.packetCount,
      'Bajty': row.bytes,
      'IP Źródłowe': row.src,
      'IP Docelowe': row.dst
    };
  });
}

function downloadFile(content, filename, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export default DataTable;
