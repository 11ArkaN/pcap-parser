import React, { useEffect, useMemo, useState } from 'react';
import type {
  PcapStreamCatalog,
  StreamPacketMeta,
  StreamPayloadRef,
  StreamPayloadView,
  StreamsViewState
} from '../types';
import { filterStreams } from '../utils/streamFilter';
import { exportStreamsToExcel } from '../utils/streamsExcelExport';

interface StreamsPanelProps {
  active: boolean;
  filePath?: string;
  catalog: PcapStreamCatalog | null;
  loading: boolean;
  error: string | null;
  viewState: StreamsViewState;
  onViewStateChange: (patch: Partial<StreamsViewState>) => void;
  onReload: () => void;
  onRequestPayload: (filePath: string, payloadRef: StreamPayloadRef, maxBytes?: number) => Promise<StreamPayloadView>;
  onGoToPcapIp?: (ip: string) => void;
}

interface PayloadState {
  loading: boolean;
  data: StreamPayloadView | null;
  error: string | null;
}

const INITIAL_MAX_PAYLOAD_BYTES = 64 * 1024;

const SearchIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ width: 16, height: 16 }}>
    <circle cx="11" cy="11" r="8" />
    <line x1="21" y1="21" x2="16.65" y2="16.65" />
  </svg>
);

function StreamsPanel({
  active,
  filePath,
  catalog,
  loading,
  error,
  viewState,
  onViewStateChange,
  onReload,
  onRequestPayload,
  onGoToPcapIp
}: StreamsPanelProps) {
  const { search, protocolFilter, selectedStreamId, selectedPacketNo } = viewState;
  const [payloadStates, setPayloadStates] = useState<Record<string, PayloadState>>({});
  const [isExcelExporting, setIsExcelExporting] = useState(false);
  const [excelExportError, setExcelExportError] = useState<string | null>(null);

  const streamList = useMemo(() => catalog?.streams ?? [], [catalog]);

  const protocolOptions = useMemo(() => {
    const values = Array.from(new Set<string>(streamList.map((stream) => stream.protocol)));
    values.sort((a, b) => a.localeCompare(b));
    return values;
  }, [streamList]);

  const filteredStreams = useMemo(() => {
    return filterStreams(streamList, search, protocolFilter).sort((a, b) => b.packets - a.packets || b.bytes - a.bytes);
  }, [streamList, protocolFilter, search]);

  const toggleSearchToken = (token: string) => {
    const parts = search
      .split(/\s+/)
      .map((item) => item.trim())
      .filter(Boolean);
    const idx = parts.indexOf(token);
    if (idx >= 0) {
      const next = parts.filter((_, i) => i !== idx).join(' ');
      onViewStateChange({ search: next });
      return;
    }
    const next = [...parts, token].join(' ');
    onViewStateChange({ search: next });
  };

  const exportToExcel = async () => {
    if (!catalog) return;
    setExcelExportError(null);
    setIsExcelExporting(true);
    try {
      await exportStreamsToExcel({
        fileName: extractFileName(filePath),
        generatedAt: new Date(),
        searchQuery: search,
        protocolFilter,
        totalPackets: catalog.totalPackets,
        droppedPackets: catalog.droppedPackets,
        filteredStreams,
        packetsByStream: catalog.packetsByStream,
        selectedStreamId
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setExcelExportError(`Nie udalo sie wyeksportowac Excela: ${message}`);
    } finally {
      setIsExcelExporting(false);
    }
  };

  useEffect(() => {
    if (!filteredStreams.length) {
      if (selectedStreamId !== null) onViewStateChange({ selectedStreamId: null, selectedPacketNo: null });
      return;
    }
    const exists = filteredStreams.some((s) => s.streamId === selectedStreamId);
    if (!exists) onViewStateChange({ selectedStreamId: filteredStreams[0].streamId, selectedPacketNo: null });
  }, [filteredStreams, selectedStreamId, onViewStateChange]);

  const selectedStream = useMemo(
    () => filteredStreams.find((s) => s.streamId === selectedStreamId) ?? null,
    [filteredStreams, selectedStreamId]
  );

  const selectedPackets = useMemo(() => {
    if (!catalog || !selectedStreamId) return [];
    return catalog.packetsByStream[selectedStreamId] ?? [];
  }, [catalog, selectedStreamId]);

  useEffect(() => {
    if (!selectedPackets.length) {
      if (selectedPacketNo !== null) onViewStateChange({ selectedPacketNo: null });
      return;
    }
    const exists = selectedPackets.some((p) => p.packetNo === selectedPacketNo);
    if (!exists) onViewStateChange({ selectedPacketNo: selectedPackets[0].packetNo });
  }, [selectedPackets, selectedPacketNo, onViewStateChange]);

  const selectedPacket = useMemo(
    () => selectedPackets.find((p) => p.packetNo === selectedPacketNo) ?? null,
    [selectedPackets, selectedPacketNo]
  );

  const selectedPacketKey = selectedPacket ? `${selectedPacket.streamId}:${selectedPacket.packetNo}` : null;
  const selectedPayloadState = selectedPacketKey ? payloadStates[selectedPacketKey] : undefined;

  const loadPayload = async (packet: StreamPacketMeta, maxBytes = INITIAL_MAX_PAYLOAD_BYTES) => {
    if (!filePath) return;
    const key = `${packet.streamId}:${packet.packetNo}`;
    setPayloadStates((cur) => ({ ...cur, [key]: { loading: true, data: cur[key]?.data ?? null, error: null } }));
    try {
      const payload = await onRequestPayload(filePath, packet.payloadRef, maxBytes);
      setPayloadStates((cur) => ({ ...cur, [key]: { loading: false, data: payload, error: null } }));
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setPayloadStates((cur) => ({ ...cur, [key]: { loading: false, data: null, error: msg } }));
    }
  };

  useEffect(() => {
    if (!active || !selectedPacket || !filePath) return;
    const key = `${selectedPacket.streamId}:${selectedPacket.packetNo}`;
    if (!payloadStates[key]) void loadPayload(selectedPacket, INITIAL_MAX_PAYLOAD_BYTES);
  }, [active, selectedPacket, filePath]);

  if (loading) {
    return (
      <div className="streams-panel streams-state-box">
        <div className="loading-spinner" style={{ width: 36, height: 36 }} />
        <p>Budowanie katalogu streamow...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="streams-panel streams-state-box">
        <div className="analysis-warning">{error}</div>
        <button className="btn btn-secondary" onClick={onReload}>Sprobuj ponownie</button>
      </div>
    );
  }

  if (!catalog) {
    return (
      <div className="streams-panel streams-state-box">
        <p className="streams-muted">Katalog streamow nie zostal jeszcze zaladowany.</p>
        <button className="btn btn-primary" onClick={onReload}>Wczytaj streamy</button>
      </div>
    );
  }

  return (
    <section className="streams-panel fade-in">
      <div className="streams-toolbar">
        <div className="table-search">
          <span className="search-icon"><SearchIcon /></span>
          <input
            type="text"
            placeholder="Szukaj: service:http ip:1.1.1.1 port:443 proto:tcp id:TCP-1 packets:>10 bytes:>5kb !udp"
            value={search}
            onChange={(e) => onViewStateChange({ search: e.target.value })}
          />
        </div>
        <div className="streams-toolbar-right">
          <select value={protocolFilter} onChange={(e) => onViewStateChange({ protocolFilter: e.target.value })}>
            <option value="all">Wszystkie protokoly</option>
            {protocolOptions.map((p) => <option key={p} value={p}>{p}</option>)}
          </select>
          <button className="btn btn-secondary" onClick={() => void exportToExcel()} disabled={isExcelExporting}>
            {isExcelExporting ? 'Tworzenie Excel...' : 'Excel'}
          </button>
          <span className="streams-pill">{filteredStreams.length.toLocaleString()} streamow</span>
          <span className="streams-pill">{catalog.totalPackets.toLocaleString()} pakietow</span>
          {catalog.droppedPackets > 0 && (
            <span className="streams-pill streams-pill-warn">Pominiete: {catalog.droppedPackets.toLocaleString()}</span>
          )}
        </div>
      </div>
      {excelExportError && <div className="analysis-warning">{excelExportError}</div>}
      <div className="streams-quick-filters">
        <button
          type="button"
          className={`streams-filter-chip ${search.includes('service:http') ? 'active' : ''}`}
          onClick={() => toggleSearchToken('service:http')}
        >
          HTTP
        </button>
        <button
          type="button"
          className={`streams-filter-chip ${search.includes('service:https') ? 'active' : ''}`}
          onClick={() => toggleSearchToken('service:https')}
        >
          HTTPS
        </button>
        <button
          type="button"
          className={`streams-filter-chip ${search.includes('service:dns') ? 'active' : ''}`}
          onClick={() => toggleSearchToken('service:dns')}
        >
          DNS
        </button>
        <button
          type="button"
          className="streams-filter-chip"
          onClick={() => onViewStateChange({ search: '' })}
        >
          Wyczysc
        </button>
      </div>

      <div className="streams-layout">
        <div className="streams-list">
          {filteredStreams.map((stream) => {
            const isSelected = stream.streamId === selectedStreamId;
            return (
              <div
                key={stream.streamId}
                className={`stream-card ${isSelected ? 'selected' : ''}`}
                onClick={() => onViewStateChange({ selectedStreamId: stream.streamId })}
              >
                <div className="stream-card-top">
                  <span className={`protocol-badge ${stream.protocol.toLowerCase()}`}>{stream.protocol}</span>
                  <span className="stream-card-id">{stream.streamId}</span>
                  <span className="stream-card-stats">{stream.packets.toLocaleString()} pkt | {formatBytes(stream.bytes)}</span>
                </div>
                <div className="stream-card-flow">
                  <IpJumpButton ip={stream.clientIp} onGoToPcapIp={onGoToPcapIp} />
                  <span className="stream-card-port">:{stream.clientPort ?? '-'}</span>
                  <span className="stream-card-arrow">-&gt;</span>
                  <IpJumpButton ip={stream.serverIp} onGoToPcapIp={onGoToPcapIp} />
                  <span className="stream-card-port">:{stream.serverPort ?? '-'}</span>
                </div>
              </div>
            );
          })}
          {filteredStreams.length === 0 && (
            <p className="streams-muted" style={{ padding: '1rem' }}>Brak streamow pasujacych do filtra.</p>
          )}
        </div>

        <div className="streams-details">
          {selectedStream ? (
            <>
              <div className="streams-summary-grid">
                <SummaryItem label="Stream ID" value={selectedStream.streamId} mono />
                <SummaryItem label="Protokol" value={selectedStream.protocol} />
                <div className="streams-summary-item">
                  <span>Endpoint A</span>
                  <strong className="streams-mono">
                    <IpJumpButton ip={selectedStream.clientIp} onGoToPcapIp={onGoToPcapIp} />:{selectedStream.clientPort ?? '-'}
                  </strong>
                </div>
                <div className="streams-summary-item">
                  <span>Endpoint B</span>
                  <strong className="streams-mono">
                    <IpJumpButton ip={selectedStream.serverIp} onGoToPcapIp={onGoToPcapIp} />:{selectedStream.serverPort ?? '-'}
                  </strong>
                </div>
                <SummaryItem label="Pakiety" value={selectedStream.packets.toLocaleString()} />
                <SummaryItem label="Bajty" value={formatBytes(selectedStream.bytes)} />
                <SummaryItem label="Czas start" value={formatTimestampUs(selectedStream.firstSeenUs)} />
                <SummaryItem label="Czas koniec" value={formatTimestampUs(selectedStream.lastSeenUs)} />
                <SummaryItem label="Duracja" value={formatDurationUs(selectedStream.durationUs)} />
              </div>

              <div className="streams-packets-section">
                <h4>Pakiety ({selectedPackets.length})</h4>
                <div className="streams-packets-list">
                  {selectedPackets.map((pkt) => {
                    const isSel = pkt.packetNo === selectedPacketNo;
                    return (
                      <div
                        key={pkt.packetNo}
                        className={`stream-pkt-card ${isSel ? 'selected' : ''}`}
                        onClick={() => onViewStateChange({ selectedPacketNo: pkt.packetNo })}
                      >
                        <div className="stream-pkt-top">
                          <span className="stream-pkt-no">#{pkt.packetNo}</span>
                          <span className={`stream-pkt-dir ${pkt.direction === 'A->B' ? 'out' : 'in'}`}>
                            {pkt.direction}
                          </span>
                          <span className="stream-pkt-len">{pkt.originalLength} B</span>
                          {pkt.payloadLength > 0 && <span className="stream-pkt-payload">{pkt.payloadLength} B payload</span>}
                          {pkt.tcp && <span className="stream-pkt-flags">{pkt.tcp.flags}</span>}
                        </div>
                        <div className="stream-pkt-flow">
                          <IpJumpButton ip={pkt.srcIp} onGoToPcapIp={onGoToPcapIp} />
                          <span className="stream-card-port">:{pkt.srcPort ?? '-'}</span>
                          <span className="stream-card-arrow">-&gt;</span>
                          <IpJumpButton ip={pkt.dstIp} onGoToPcapIp={onGoToPcapIp} />
                          <span className="stream-card-port">:{pkt.dstPort ?? '-'}</span>
                          <span className="stream-pkt-ts">{formatTimestampUs(pkt.timestampUs)}</span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              <div className="streams-payload">
                <div className="streams-payload-head">
                  <h4>Payload</h4>
                  {selectedPacket && (
                    <div className="streams-payload-actions">
                      <span className="streams-muted">#{selectedPacket.packetNo} ({selectedPacket.capturedLength} B)</span>
                      <button className="btn btn-secondary" onClick={() => void loadPayload(selectedPacket, INITIAL_MAX_PAYLOAD_BYTES)}>
                        Odswiez
                      </button>
                      {selectedPayloadState?.data?.truncated && (
                        <button className="btn btn-secondary" onClick={() => void loadPayload(selectedPacket, selectedPacket.capturedLength)}>
                          Calosc
                        </button>
                      )}
                    </div>
                  )}
                </div>

                {!selectedPacket && <p className="streams-muted">Wybierz pakiet, aby zobaczyc payload.</p>}
                {selectedPacket && selectedPayloadState?.loading && <p className="streams-muted">Ladowanie...</p>}
                {selectedPacket && selectedPayloadState?.error && (
                  <p className="analysis-warning">{selectedPayloadState.error}</p>
                )}
                {selectedPacket && selectedPayloadState?.data && (
                  <div className="streams-payload-content">
                    <div>
                      <h5>HEX</h5>
                      <pre>{selectedPayloadState.data.hex || '(pusty payload)'}</pre>
                    </div>
                    <div>
                      <h5>ASCII</h5>
                      <pre>{selectedPayloadState.data.ascii || '(pusty payload)'}</pre>
                    </div>
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="streams-state-box" style={{ minHeight: 200 }}>
              <p className="streams-muted">Brak streamow do wyswietlenia.</p>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

function SummaryItem({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="streams-summary-item">
      <span>{label}</span>
      <strong className={mono ? 'streams-mono' : ''}>{value}</strong>
    </div>
  );
}

function IpJumpButton({ ip, onGoToPcapIp }: { ip: string; onGoToPcapIp?: (ip: string) => void }) {
  if (!ip || !onGoToPcapIp) return <>{ip || '-'}</>;
  return (
    <button
      type="button"
      className="streams-ip-jump"
      onClick={(e) => { e.stopPropagation(); onGoToPcapIp(ip); }}
      title={`Przejdz do ${ip} w widoku PCAP`}
    >
      {ip}
    </button>
  );
}

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let size = bytes;
  let i = 0;
  while (size >= 1024 && i < units.length - 1) {
    size /= 1024;
    i += 1;
  }
  return `${size.toFixed(size >= 10 ? 1 : 2)} ${units[i]}`;
}

function formatDurationUs(value: number | null): string {
  if (value === null || !Number.isFinite(value)) return '-';
  if (value < 1_000) return `${value} us`;
  if (value < 1_000_000) return `${(value / 1_000).toFixed(2)} ms`;
  return `${(value / 1_000_000).toFixed(2)} s`;
}

function formatTimestampUs(value: number | null): string {
  if (value === null || !Number.isFinite(value) || value <= 0) return '-';
  const ms = Math.floor(value / 1000);
  if (ms > 946684800000 && ms < 4102444800000) {
    return new Date(ms).toLocaleString('pl-PL', {
      hour12: false,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  }
  return `${value} us`;
}

export default StreamsPanel;

function extractFileName(filePath?: string): string {
  if (!filePath) return 'nieznany-plik.pcap';
  const normalized = filePath.replace(/\\/g, '/');
  const parts = normalized.split('/');
  return parts[parts.length - 1] || filePath;
}
