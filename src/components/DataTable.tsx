import React, { useEffect, useMemo, useRef, useState } from 'react';
import Papa from 'papaparse';
import * as XLSX from 'xlsx';
import type { IpLookupData, ParsedConnection, ResolvedServiceResult } from '../types';
import { createWorkbookWithMetadata } from '../utils/excelWorkbook';
import {
  formatResolvedServiceNameWithFallback,
  formatResolvedServicePort,
  formatResolvedServiceRfc,
  resolveConnectionServices
} from '../utils/serviceResolver';

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

type AggregationMode = 'connections' | 'uniqueIps';
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
  serviceLabels: Set<string>;
  servicePorts: Set<string>;
  serviceRfcs: Set<string>;
  serviceConfidence: ResolvedServiceResult['confidence'];
  serviceResolution: ResolvedServiceResult;
  primaryServicePort: number | null;
}

export interface AggregatedRow {
  kind: 'connection';
  ip: string;
  src: string;
  dst: string;
  protocol: string;
  srcPort: number | null;
  dstPort: number | null;
  packetCount: number;
  bytes: number;
  services: string;
  servicePorts: string;
  serviceConfidence: ResolvedServiceResult['confidence'];
  serviceRfc: string;
  serviceResolution: ResolvedServiceResult;
  primaryServicePort: number | null;
}

interface GroupedIpRow {
  ip: string;
  peers: Set<string>;
  protocolCounts: Record<string, number>;
  packetCount: number;
  bytes: number;
  serviceLabels: Set<string>;
  servicePorts: Set<string>;
  serviceRfcs: Set<string>;
  serviceConfidence: ResolvedServiceResult['confidence'];
  serviceResolution: ResolvedServiceResult;
  primaryServicePort: number | null;
}

export interface AggregatedIpRow {
  kind: 'ip';
  ip: string;
  peers: string;
  peerCount: number;
  protocol: string;
  primaryProtocol: string;
  packetCount: number;
  bytes: number;
  services: string;
  servicePorts: string;
  serviceConfidence: ResolvedServiceResult['confidence'];
  serviceRfc: string;
  serviceResolution: ResolvedServiceResult;
  primaryServicePort: number | null;
}

type TableRow = AggregatedRow | AggregatedIpRow;

export interface ExportRow {
  'Adres IP': string;
  ASN: string;
  'ISP/Organizacja': string;
  Kraj: string;
  Miasto: string;
  'Blok CIDR': string;
  Usluga: string;
  Port: number | string;
  'Port uslugi': string;
  Pewnosc: string;
  RFC: string;
  Protokol: string;
  Pakiety: number;
  Bajty: number;
  'IP Zrodlowe'?: string;
  'IP Docelowe'?: string;
  'Komunikuje sie z'?: string;
  'Liczba peerow'?: number;
}

function DataTable({ connections, ipData, isPublic, focusRequest = null }: DataTableProps) {
  const [searchTerm, setSearchTerm] = useState('');
  const [sortConfig, setSortConfig] = useState<SortConfig>({ key: null, direction: 'asc' });
  const [highlightIp, setHighlightIp] = useState<string | null>(null);
  const [aggregationMode, setAggregationMode] = useState<AggregationMode>('connections');
  const tableWrapperRef = useRef<HTMLDivElement | null>(null);

  const connectionRows = useMemo(() => aggregateConnections(connections), [connections]);
  const uniqueIpRows = useMemo(() => aggregateConnectionsByIp(connections, isPublic), [connections, isPublic]);
  const aggregatedData = useMemo<TableRow[]>(
    () => (aggregationMode === 'connections' ? connectionRows : uniqueIpRows),
    [aggregationMode, connectionRows, uniqueIpRows]
  );

  const filteredData = useMemo(() => {
    let data = [...aggregatedData];

    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      data = data.filter(
        (row) =>
          row.ip.toLowerCase().includes(term) ||
          ('src' in row && row.src.toLowerCase().includes(term)) ||
          ('dst' in row && row.dst.toLowerCase().includes(term)) ||
          ('peers' in row && row.peers.toLowerCase().includes(term)) ||
          row.services.toLowerCase().includes(term) ||
          row.servicePorts.toLowerCase().includes(term) ||
          ipData[row.ip]?.asn?.toLowerCase().includes(term) ||
          ipData[row.ip]?.isp?.toLowerCase().includes(term) ||
          ipData[row.ip]?.country?.toLowerCase().includes(term)
      );
    }

    if (sortConfig.key) {
      data.sort((a, b) => {
        let aValue: string | number = '';
        let bValue: string | number = '';

        const infoA: Partial<IpLookupData> = ipData[a.ip] ?? {};
        const infoB: Partial<IpLookupData> = ipData[b.ip] ?? {};

        switch (sortConfig.key) {
          case 'ip':
            aValue = a.ip;
            bValue = b.ip;
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
    const exportData = prepareExportData(filteredData, ipData, isPublic, aggregationMode);
    const csv = Papa.unparse(exportData);
    downloadFile(csv, 'analiza-pcap.csv', 'text/csv');
  };

  const exportToJSON = () => {
    const exportData = prepareExportData(filteredData, ipData, isPublic, aggregationMode);
    const json = JSON.stringify(exportData, null, 2);
    downloadFile(json, 'analiza-pcap.json', 'application/json');
  };

  const exportToExcel = () => {
    const exportData = prepareExportData(filteredData, ipData, isPublic, aggregationMode);
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
          <button
            className={`btn ${aggregationMode === 'connections' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setAggregationMode('connections')}
          >
            Relacje
          </button>
          <button
            className={`btn ${aggregationMode === 'uniqueIps' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setAggregationMode('uniqueIps')}
          >
            Unikalne IP
          </button>
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
                  <th>Adres IP</th>
                  {aggregationMode === 'connections' ? <th>IP Docelowe</th> : <th>Komunikuje sie z</th>}
                </>
              )}
              {aggregationMode === 'uniqueIps' && <th>Peerzy</th>}
              <th>Usluga</th>
              <th onClick={() => handleSort('packets')}>Pakiety {getSortIndicator('packets')}</th>
              <th onClick={() => handleSort('bytes')}>Bajty {getSortIndicator('bytes')}</th>
              {isPublic && <th>Bezpieczenstwo</th>}
            </tr>
          </thead>
          <tbody>
            {filteredData.map((row, index) => {
              const info: Partial<IpLookupData> = ipData[row.ip] ?? {};
              const protocolBadge = row.kind === 'ip' ? row.primaryProtocol : row.protocol;
              const publicIp = row.ip;

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
                        <span className="ip-address ip-local">{row.ip}</span>
                      </td>
                      <td>
                        <span className="ip-address ip-local">{row.kind === 'connection' ? row.dst : row.peers || '-'}</span>
                      </td>
                    </>
                  )}

                  {aggregationMode === 'uniqueIps' && (
                    <td style={{ maxWidth: 260 }}>
                      <span title={row.kind === 'ip' ? row.peers : ''}>{row.kind === 'ip' ? row.peerCount : '-'}</span>
                    </td>
                  )}

                  <td>
                    <div className="service-info">
                      <span className="service-name">{row.services || 'Nieznane'}</span>
                      {row.servicePorts !== 'N/D' && <span className="port-number">Port {row.servicePorts}</span>}
                      <span className={`protocol-badge ${protocolBadge.toLowerCase()}`}>{row.protocol}</span>
                    </div>
                  </td>

                  <td style={{ fontFamily: "'Fira Code', monospace", fontSize: '0.8125rem' }}>
                    {row.packetCount.toLocaleString()}
                  </td>
                  <td style={{ fontFamily: "'Fira Code', monospace", fontSize: '0.8125rem' }}>{formatBytes(row.bytes)}</td>

                  {isPublic && (
                    <td>
                      <SecurityAnalysis
                        port={row.primaryServicePort}
                        protocol={protocolBadge}
                        serviceConfidence={row.serviceConfidence}
                        isp={info.isp as string | undefined}
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

interface SecurityAnalysisProps {
  port: number | null;
  protocol: string;
  serviceConfidence: ResolvedServiceResult['confidence'];
  isp?: string;
}

function SecurityAnalysis({ port, protocol, serviceConfidence, isp }: SecurityAnalysisProps) {
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

  if (serviceConfidence !== 'high') {
    analysis.push('Usluga niejednoznaczna');
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
    const serviceResolution = resolveConnectionServices(conn);
    if (!grouped[key]) {
      grouped[key] = {
        src: conn.src,
        dst: conn.dst,
        protocol: conn.protocol,
        srcPort: conn.srcPort,
        dstPort: conn.dstPort,
        packetCount: 0,
        bytes: 0,
        serviceLabels: new Set<string>(),
        servicePorts: new Set<string>(),
        serviceRfcs: new Set<string>(),
        serviceConfidence: serviceResolution.confidence,
        serviceResolution,
        primaryServicePort: serviceResolution.primaryCandidate?.port ?? null
      };
    }

    grouped[key].packetCount += conn.packetCount || 1;
    grouped[key].bytes += conn.length || 0;

    const group = grouped[key];
    group.serviceConfidence = mergeConfidence(group.serviceConfidence, serviceResolution.confidence);

    const serviceLabel = formatResolvedServiceNameWithFallback(serviceResolution, conn.srcPort, conn.dstPort);
    const servicePort = formatResolvedServicePort(serviceResolution, conn.srcPort, conn.dstPort);
    const serviceRfc = formatResolvedServiceRfc(serviceResolution);

    if (serviceLabel !== 'Niezidentyfikowana') {
      group.serviceLabels.add(serviceLabel);
    }
    if (servicePort !== 'N/D') {
      group.servicePorts.add(servicePort);
    }
    if (serviceRfc !== 'N/D') {
      group.serviceRfcs.add(serviceRfc);
    }

    if (!group.serviceResolution.primaryCandidate && serviceResolution.primaryCandidate) {
      group.serviceResolution = serviceResolution;
      group.primaryServicePort = serviceResolution.primaryCandidate.port;
    }
  });

  return Object.values(grouped).map((group) => ({
    kind: 'connection',
    ip: isPublicIp(group.dst) ? group.dst : group.src,
    src: group.src,
    dst: group.dst,
    protocol: group.protocol,
    srcPort: group.srcPort,
    dstPort: group.dstPort,
    packetCount: group.packetCount,
    bytes: group.bytes,
    services: Array.from(group.serviceLabels).join(', ') || 'Niezidentyfikowana',
    servicePorts: Array.from(group.servicePorts).join(', ') || 'N/D',
    serviceConfidence: group.serviceConfidence,
    serviceRfc: Array.from(group.serviceRfcs).join(', ') || 'N/D',
    serviceResolution: group.serviceResolution,
    primaryServicePort: group.primaryServicePort
  }));
}

export function aggregateConnectionsByIp(connections: ParsedConnection[], isPublicView: boolean): AggregatedIpRow[] {
  const grouped: Record<string, GroupedIpRow> = {};

  connections.forEach((conn) => {
    const targets = collectTargetIps(conn, isPublicView);
    if (!targets.length) return;

    const serviceResolution = resolveConnectionServices(conn);

    for (const ip of targets) {
      const peers = collectPeerIps(conn, ip);
      const portBuckets = buildIpPortBuckets(conn, ip, peers, serviceResolution);

      for (const portBucket of portBuckets) {
        const key = portBucket.key;

        if (!grouped[key]) {
          grouped[key] = {
            ip,
            peers: new Set<string>(),
            protocolCounts: {},
            packetCount: 0,
            bytes: 0,
            serviceLabels: new Set<string>(),
            servicePorts: new Set<string>(),
            serviceRfcs: new Set<string>(),
            serviceConfidence: portBucket.serviceConfidence,
            serviceResolution: portBucket.serviceResolution,
            primaryServicePort: portBucket.primaryServicePort
          };
        }

        const group = grouped[key];
        group.packetCount += conn.packetCount || 1;
        group.bytes += conn.length || 0;
        group.protocolCounts[conn.protocol] = (group.protocolCounts[conn.protocol] || 0) + (conn.packetCount || 1);
        group.serviceConfidence = mergeConfidence(group.serviceConfidence, portBucket.serviceConfidence);
        for (const peer of peers) {
          group.peers.add(peer);
        }
        if (portBucket.serviceLabel !== 'N/D') {
          group.serviceLabels.add(portBucket.serviceLabel);
        }
        if (portBucket.servicePort !== 'N/D') {
          group.servicePorts.add(portBucket.servicePort);
        }
        if (portBucket.serviceRfc !== 'N/D') {
          group.serviceRfcs.add(portBucket.serviceRfc);
        }
        if (!group.serviceResolution.primaryCandidate && portBucket.serviceResolution.primaryCandidate) {
          group.serviceResolution = portBucket.serviceResolution;
          group.primaryServicePort = portBucket.primaryServicePort;
        }
      }
    }
  });

  return Object.values(grouped)
    .map((group) => {
      const protocols = Object.entries(group.protocolCounts)
        .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
        .map(([protocol]) => protocol);

      return {
        kind: 'ip',
        ip: group.ip,
        peers: Array.from(group.peers).sort().join(', '),
        peerCount: group.peers.size,
        protocol: protocols.join(', ') || 'N/D',
        primaryProtocol: protocols[0] || 'other',
        packetCount: group.packetCount,
        bytes: group.bytes,
        services: Array.from(group.serviceLabels).join(', ') || 'Niezidentyfikowana',
        servicePorts: Array.from(group.servicePorts).join(', ') || 'N/D',
        serviceConfidence: group.serviceConfidence,
        serviceRfc: Array.from(group.serviceRfcs).join(', ') || 'N/D',
        serviceResolution: group.serviceResolution,
        primaryServicePort: group.primaryServicePort
      } satisfies AggregatedIpRow;
    })
    .sort((left, right) => right.packetCount - left.packetCount || left.ip.localeCompare(right.ip));
}

export function prepareExportData(
  data: TableRow[],
  ipData: Record<string, IpLookupData>,
  _isPublic: boolean,
  aggregationMode: AggregationMode = 'connections'
): ExportRow[] {
  if (aggregationMode === 'uniqueIps') {
    return data.map((row) => {
      const info: Partial<IpLookupData> = ipData[row.ip] ?? {};
      const ipRow = row as AggregatedIpRow;

      return {
        'Adres IP': ipRow.ip,
        ASN: (info.asn as string) || 'N/D',
        'ISP/Organizacja': (info.isp as string) || (info.org as string) || 'Nieznane',
        Kraj: (info.country as string) || 'Nieznane',
        Miasto: (info.city as string) || 'N/D',
        'Blok CIDR': (info.cidr as string) || (info.range as string) || 'N/D',
        Usluga: ipRow.services || 'Nieznane',
        Port: ipRow.servicePorts,
        'Port uslugi': ipRow.servicePorts,
        Pewnosc: ipRow.serviceConfidence,
        RFC: ipRow.serviceRfc,
        Protokol: ipRow.protocol,
        Pakiety: ipRow.packetCount,
        Bajty: ipRow.bytes,
        'Komunikuje sie z': ipRow.peers || '-',
        'Liczba peerow': ipRow.peerCount
      };
    });
  }

  return data.map((row) => {
    const relationRow = row as AggregatedRow;
    const publicIp = relationRow.ip;
    const info: Partial<IpLookupData> = ipData[publicIp] ?? {};

    return {
      'Adres IP': publicIp,
      ASN: (info.asn as string) || 'N/D',
      'ISP/Organizacja': (info.isp as string) || (info.org as string) || 'Nieznane',
      Kraj: (info.country as string) || 'Nieznane',
      Miasto: (info.city as string) || 'N/D',
      'Blok CIDR': (info.cidr as string) || (info.range as string) || 'N/D',
      Usluga: relationRow.services || 'Nieznane',
      Port: relationRow.dstPort || 'N/D',
      'Port uslugi': relationRow.servicePorts,
      Pewnosc: relationRow.serviceConfidence,
      RFC: relationRow.serviceRfc,
      Protokol: relationRow.protocol,
      Pakiety: relationRow.packetCount,
      Bajty: relationRow.bytes,
      'IP Zrodlowe': relationRow.src,
      'IP Docelowe': relationRow.dst
    };
  });
}

function mergeConfidence(
  current: ResolvedServiceResult['confidence'],
  next: ResolvedServiceResult['confidence']
): ResolvedServiceResult['confidence'] {
  const order: Record<ResolvedServiceResult['confidence'], number> = {
    low: 0,
    medium: 1,
    high: 2
  };

  return order[next] > order[current] ? next : current;
}

function collectTargetIps(conn: ParsedConnection, isPublicView: boolean): string[] {
  const candidates = [conn.src, conn.dst].filter(Boolean);
  return Array.from(
    new Set(candidates.filter((ip) => (isPublicView ? isPublicIp(ip) : !isPublicIp(ip))))
  );
}

function collectPeerIps(conn: ParsedConnection, targetIp: string): string[] {
  const peers: string[] = [];
  if (conn.src === targetIp && conn.dst) {
    peers.push(conn.dst);
  }
  if (conn.dst === targetIp && conn.src) {
    peers.push(conn.src);
  }
  return Array.from(new Set(peers.filter(Boolean)));
}

function buildIpPortBuckets(
  conn: ParsedConnection,
  targetIp: string,
  peers: string[],
  serviceResolution: ResolvedServiceResult
): Array<{
  key: string;
  serviceLabel: string;
  servicePort: string;
  serviceRfc: string;
  serviceConfidence: ResolvedServiceResult['confidence'];
  serviceResolution: ResolvedServiceResult;
  primaryServicePort: number | null;
}> {
  const peerKey = peers.length ? peers.slice().sort().join('|') : '-';
  const relationKey = `${conn.src}|${conn.srcPort ?? '-'}|${conn.dst}|${conn.dstPort ?? '-'}|${conn.protocol}`;
  const observedPorts = Array.from(
    new Set([conn.srcPort, conn.dstPort].filter((value): value is number => Number.isInteger(value) && value > 0))
  );

  if (!observedPorts.length) {
    return [
      {
        key: `${targetIp}|${peerKey}|${relationKey}|N/D`,
        serviceLabel: 'N/D',
        servicePort: 'N/D',
        serviceRfc: 'N/D',
        serviceConfidence: 'low',
        serviceResolution: {
          candidates: [],
          primaryCandidate: null,
          confidence: 'low',
          reason: 'target-port-unidentified'
        },
        primaryServicePort: null
      }
    ];
  }

  return observedPorts.map((port) => {
    const candidate = serviceResolution.candidates.find((item) => item.port === port) ?? null;
    if (candidate) {
      return {
        key: `${targetIp}|${peerKey}|${relationKey}|${candidate.port}`,
        serviceLabel: candidate.displayName,
        servicePort: String(candidate.port),
        serviceRfc: candidate.rfcRefs.length ? candidate.rfcRefs.join(', ') : 'N/D',
        serviceConfidence: serviceResolution.confidence,
        serviceResolution: {
          candidates: [candidate],
          primaryCandidate: candidate,
          confidence: serviceResolution.confidence,
          reason: serviceResolution.reason
        },
        primaryServicePort: candidate.port
      };
    }

    const fallbackPort = String(port);
    return {
      key: `${targetIp}|${peerKey}|${relationKey}|${fallbackPort}`,
      serviceLabel: fallbackPort,
      servicePort: fallbackPort,
      serviceRfc: 'N/D',
      serviceConfidence: 'low',
      serviceResolution: {
        candidates: [],
        primaryCandidate: null,
        confidence: 'low',
        reason: 'target-port-unidentified'
      },
      primaryServicePort: port
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
