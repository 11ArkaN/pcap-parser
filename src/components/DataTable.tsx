import React, { useEffect, useMemo, useRef, useState } from 'react';
import Papa from 'papaparse';
import * as XLSX from 'xlsx';
import type { IpLookupData, ParsedConnection } from '../types';
import { createWorkbookWithMetadata } from '../utils/excelWorkbook';

const SearchIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="11" cy="11" r="8" />
    <line x1="21" y1="21" x2="16.65" y2="16.65" />
  </svg>
);

interface DataTableProps {
  connections: ParsedConnection[];
  ipData: Record<string, IpLookupData>;
  isPublic: boolean;
  focusRequest?: { ip: string; requestId: number } | null;
}

type SortKey = 'ip' | 'asn' | 'isp' | 'country' | 'packets' | 'bytes' | null;

interface SortConfig {
  key: SortKey;
  direction: 'asc' | 'desc';
}

interface GroupedRow {
  src: string;
  dst: string;
  protocol: string;
  srcPort: number | null;
  dstPort: number | null;
  packetCount: number;
  bytes: number;
  services: Set<string>;
}

export interface AggregatedRow {
  src: string;
  dst: string;
  protocol: string;
  srcPort: number | null;
  dstPort: number | null;
  packetCount: number;
  bytes: number;
  services: string;
}

export interface ExportRow {
  'Adres IP': string;
  ASN: string;
  'ISP/Organizacja': string;
  Kraj: string;
  Miasto: string;
  'Blok CIDR': string;
  Usluga: string;
  Port: number | string;
  Protokol: string;
  Pakiety: number;
  Bajty: number;
  'IP Zrodlowe': string;
  'IP Docelowe': string;
}

function DataTable({ connections, ipData, isPublic, focusRequest = null }: DataTableProps) {
  const [searchTerm, setSearchTerm] = useState('');
  const [sortConfig, setSortConfig] = useState<SortConfig>({ key: null, direction: 'asc' });
  const [highlightIp, setHighlightIp] = useState<string | null>(null);
  const tableWrapperRef = useRef<HTMLDivElement | null>(null);

  const aggregatedData = useMemo(() => aggregateConnections(connections), [connections]);

  const filteredData = useMemo(() => {
    let data = [...aggregatedData];

    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      data = data.filter(
        (row) =>
          row.src.toLowerCase().includes(term) ||
          row.dst.toLowerCase().includes(term) ||
          ipData[row.dst]?.asn?.toLowerCase().includes(term) ||
          ipData[row.dst]?.isp?.toLowerCase().includes(term) ||
          ipData[row.dst]?.country?.toLowerCase().includes(term)
      );
    }

    if (sortConfig.key) {
      data.sort((a, b) => {
        let aValue: string | number = '';
        let bValue: string | number = '';

        const publicIpA = isPublicIp(a.dst) ? a.dst : a.src;
        const publicIpB = isPublicIp(b.dst) ? b.dst : b.src;
        const infoA: Partial<IpLookupData> = ipData[publicIpA] ?? {};
        const infoB: Partial<IpLookupData> = ipData[publicIpB] ?? {};

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
            break;
        }

        if (typeof aValue === 'number' && typeof bValue === 'number') {
          return sortConfig.direction === 'asc' ? aValue - bValue : bValue - aValue;
        }

        const aStr = String(aValue).toLowerCase();
        const bStr = String(bValue).toLowerCase();

        if (aStr < bStr) return sortConfig.direction === 'asc' ? -1 : 1;
        if (aStr > bStr) return sortConfig.direction === 'asc' ? 1 : -1;
        return 0;
      });
    }

    return data;
  }, [aggregatedData, searchTerm, sortConfig, ipData]);

  useEffect(() => {
    if (!focusRequest || !isPublic) return;
    const targetIp = focusRequest.ip.trim();
    if (!targetIp) return;

    setSearchTerm(targetIp);
    setHighlightIp(targetIp);

    const scrollToTarget = () => {
      const rows = tableWrapperRef.current?.querySelectorAll<HTMLTableRowElement>('tr[data-public-ip]');
      if (!rows?.length) return;
      for (const row of rows) {
        if (row.dataset.publicIp === targetIp) {
          row.scrollIntoView({ behavior: 'smooth', block: 'center' });
          break;
        }
      }
    };

    window.requestAnimationFrame(() => {
      window.requestAnimationFrame(scrollToTarget);
    });

    const timer = window.setTimeout(() => {
      setHighlightIp((current) => (current === targetIp ? null : current));
    }, 2600);
    return () => window.clearTimeout(timer);
  }, [focusRequest?.requestId, focusRequest?.ip, isPublic]);

  const handleSort = (key: Exclude<SortKey, null>) => {
    setSortConfig((current) => ({
      key,
      direction: current.key === key && current.direction === 'asc' ? 'desc' : 'asc'
    }));
  };

  const getSortIndicator = (key: Exclude<SortKey, null>) => {
    if (sortConfig.key !== key) return '<>';
    return sortConfig.direction === 'asc' ? '^' : 'v';
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
    ws['!cols'] = buildExcelColumnWidths(exportData);
    const wb = createWorkbookWithMetadata();
    XLSX.utils.book_append_sheet(wb, ws, 'Analiza PCAP');
    XLSX.writeFile(wb, 'analiza-pcap.xlsx');
  };

  if (!connections.length) {
    return (
      <div className="empty-state">
        <div className="empty-state-icon">No data</div>
        <h3>Brak danych</h3>
        <p>Wczytaj plik PCAP aby zobaczyc analize</p>
      </div>
    );
  }

  return (
    <div className="table-container fade-in">
      <div className="table-toolbar">
        <div className="table-search">
          <span className="search-icon">
            <SearchIcon />
          </span>
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

      <div className="data-table-wrapper" ref={tableWrapperRef}>
        <table className="data-table">
          <thead>
            <tr>
              {isPublic && (
                <>
                  <th onClick={() => handleSort('ip')}>Adres IP {getSortIndicator('ip')}</th>
                  <th onClick={() => handleSort('asn')}>ASN {getSortIndicator('asn')}</th>
                  <th onClick={() => handleSort('isp')}>ISP / Organizacja {getSortIndicator('isp')}</th>
                  <th onClick={() => handleSort('country')}>Lokalizacja {getSortIndicator('country')}</th>
                  <th className="cidr-col">Blok CIDR</th>
                </>
              )}
              {!isPublic && (
                <>
                  <th>IP Zrodlowe</th>
                  <th>IP Docelowe</th>
                </>
              )}
              <th>Usluga</th>
              <th onClick={() => handleSort('packets')}>Pakiety {getSortIndicator('packets')}</th>
              <th onClick={() => handleSort('bytes')}>Bajty {getSortIndicator('bytes')}</th>
              {isPublic && <th>Bezpieczenstwo</th>}
            </tr>
          </thead>
          <tbody>
            {filteredData.map((row, index) => {
              const publicIp = isPublicIp(row.dst) ? row.dst : row.src;
              const info: Partial<IpLookupData> = ipData[publicIp] ?? {};

              return (
                <tr key={index} data-public-ip={publicIp} className={highlightIp === publicIp ? 'pcap-focus-row' : undefined}>
                  {isPublic && (
                    <>
                      <td>
                        <span className="ip-address">{publicIp}</span>
                      </td>
                      <td>{info.asn && <span className="asn-badge">{info.asn}</span>}</td>
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
                      <td className="cidr-col">
                        <span className="cidr-block cidr-block-pcap">{(info.cidr as string) || (info.range as string) || 'N/D'}</span>
                      </td>
                    </>
                  )}
                  {!isPublic && (
                    <>
                      <td>
                        <span className="ip-address ip-local">{row.src}</span>
                      </td>
                      <td>
                        <span className="ip-address ip-local">{row.dst}</span>
                      </td>
                    </>
                  )}

                  <td>
                    <div className="service-info">
                      <span className="service-name">{row.services || 'Nieznane'}</span>
                      {row.dstPort && <span className="port-number">Port {row.dstPort}</span>}
                      <span className={`protocol-badge ${row.protocol.toLowerCase()}`}>{row.protocol}</span>
                    </div>
                  </td>

                  <td style={{ fontFamily: "'Fira Code', monospace", fontSize: '0.8125rem' }}>
                    {row.packetCount.toLocaleString()}
                  </td>
                  <td style={{ fontFamily: "'Fira Code', monospace", fontSize: '0.8125rem' }}>{formatBytes(row.bytes)}</td>

                  {isPublic && (
                    <td>
                      <SecurityAnalysis port={row.dstPort} protocol={row.protocol} isp={info.isp as string | undefined} />
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

interface SecurityAnalysisProps {
  port: number | null;
  protocol: string;
  isp?: string;
}

function SecurityAnalysis({ port, protocol, isp }: SecurityAnalysisProps) {
  const analysis: string[] = [];
  let level: 'safe' | 'warning' = 'safe';

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
  } else if (port && port > 49152) {
    analysis.push('Port Dynamiczny');
    level = 'warning';
  }

  if (isp) {
    const trusted = ['microsoft', 'google', 'amazon', 'cloudflare', 'akamai'];
    const isTrusted = trusted.some((t) => isp.toLowerCase().includes(t));
    if (isTrusted) {
      analysis.push('Zaufany Dostawca');
    }
  }

  const className = `security-info security-${level}`;

  return <div className={className}>{analysis.join(' / ') || 'Ruch Standardowy'}</div>;
}

function getServiceName(port: number): string {
  const services: Record<number, string> = {
    20: 'FTP-Data',
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    465: 'SMTPS',
    587: 'SMTP',
    993: 'IMAPS',
    995: 'POP3S',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt'
  };
  return services[port] || `Port-${port}`;
}

function getFlagEmoji(countryCode: string): string {
  const codePoints = countryCode
    .toUpperCase()
    .split('')
    .map((char) => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

export function isPublicIp(ip: string): boolean {
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

export function aggregateConnections(connections: ParsedConnection[]): AggregatedRow[] {
  const grouped: Record<string, GroupedRow> = {};

  connections.forEach((conn) => {
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
        services: new Set<string>()
      };
    }

    grouped[key].packetCount += conn.packetCount || 1;
    grouped[key].bytes += conn.length || 0;
    if (conn.dstPort) {
      grouped[key].services.add(getServiceName(conn.dstPort));
    }
  });

  return Object.values(grouped).map((group) => ({
    src: group.src,
    dst: group.dst,
    protocol: group.protocol,
    srcPort: group.srcPort,
    dstPort: group.dstPort,
    packetCount: group.packetCount,
    bytes: group.bytes,
    services: Array.from(group.services).join(', ')
  }));
}

export function prepareExportData(
  data: AggregatedRow[],
  ipData: Record<string, IpLookupData>,
  _isPublic: boolean
): ExportRow[] {
  return data.map((row) => {
    const publicIp = isPublicIp(row.dst) ? row.dst : row.src;
    const info: Partial<IpLookupData> = ipData[publicIp] ?? {};

    return {
      'Adres IP': publicIp,
      ASN: (info.asn as string) || 'N/D',
      'ISP/Organizacja': (info.isp as string) || (info.org as string) || 'Nieznane',
      Kraj: (info.country as string) || 'Nieznane',
      Miasto: (info.city as string) || 'N/D',
      'Blok CIDR': (info.cidr as string) || (info.range as string) || 'N/D',
      Usluga: row.services || 'Nieznane',
      Port: row.dstPort || 'N/D',
      Protokol: row.protocol,
      Pakiety: row.packetCount,
      Bajty: row.bytes,
      'IP Zrodlowe': row.src,
      'IP Docelowe': row.dst
    };
  });
}

function buildExcelColumnWidths(rows: ExportRow[]) {
  const minWidth = 10;
  if (!rows.length) return [];

  const headers = Object.keys(rows[0]) as Array<keyof ExportRow>;
  return headers.map((header) => {
    let longest = header.length;

    for (const row of rows) {
      const value = row[header];
      const width = String(value ?? '').length;
      if (width > longest) longest = width;
    }

    return { wch: Math.max(minWidth, longest + 2) };
  });
}

function downloadFile(content: string, filename: string, type: string) {
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
