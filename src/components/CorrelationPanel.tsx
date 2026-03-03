import React, { useEffect, useMemo, useRef, useState } from 'react';
import { summarizeCorrelation } from '../utils/correlationSummary';
import type {
  CorrelationJobStatus,
  CorrelationMatch,
  CorrelationReportV1,
  CorrelationUnmatchedProcmonEvent,
  CorrelationUnmatchedSession,
  IpLookupData,
  ProcmonAttachment
} from '../types';

interface CorrelationPanelProps {
  pcapFilePath?: string;
  procmonFiles: ProcmonAttachment[];
  correlationJob: CorrelationJobStatus | null;
  correlationResult: CorrelationReportV1 | null;
  ipData: Record<string, IpLookupData>;
  onEnsureIpMetadata?: (ips: string[]) => void;
  onGoToPcapIp?: (ip: string) => void;
  onAddProcmonFiles: () => void;
  onRemoveProcmonFile: (filePath: string) => void;
  onRunCorrelation: () => void;
  onCancelCorrelation: () => void;
}

function CorrelationPanel({
  pcapFilePath,
  procmonFiles,
  correlationJob,
  correlationResult,
  ipData,
  onEnsureIpMetadata,
  onGoToPcapIp,
  onAddProcmonFiles,
  onRemoveProcmonFile,
  onRunCorrelation,
  onCancelCorrelation
}: CorrelationPanelProps) {
  const [activeTab, setActiveTab] = useState<'results' | 'debug'>('results');
  const [activeResultsView, setActiveResultsView] = useState<'matches' | 'unmatched_sessions' | 'unmatched_events'>('matches');
  const debugListRef = useRef<HTMLDivElement | null>(null);

  const summary = useMemo(() => (correlationResult ? summarizeCorrelation(correlationResult) : null), [correlationResult]);
  const isRunning = correlationJob?.state === 'queued' || correlationJob?.state === 'running';
  const canRun = Boolean(pcapFilePath && procmonFiles.length > 0 && !isRunning);
  const debugEntries = correlationJob?.debugEntries ?? [];
  const topMatches = useMemo(() => (correlationResult ? [...correlationResult.matches].sort((a, b) => b.score - a.score).slice(0, 200) : []), [correlationResult]);
  const topUnmatchedSessions = useMemo(
    () => (correlationResult ? [...correlationResult.unmatchedSessions].sort((a, b) => b.packets - a.packets).slice(0, 200) : []),
    [correlationResult]
  );
  const topUnmatchedEvents = useMemo(
    () => (correlationResult ? [...correlationResult.unmatchedProcmonEvents].sort((a, b) => b.tsUs - a.tsUs).slice(0, 200) : []),
    [correlationResult]
  );

  const missingIps = useMemo(() => {
    if (!correlationResult) return [];
    const set = new Set<string>();
    for (const row of [...topMatches, ...topUnmatchedSessions, ...topUnmatchedEvents]) {
      for (const ip of listPublicIpCandidatesGeneric(row)) {
        if (!lookupIpInfo(ipData, ip)) set.add(ip);
      }
    }
    return Array.from(set).slice(0, 150);
  }, [correlationResult, topMatches, topUnmatchedSessions, topUnmatchedEvents, ipData]);

  useEffect(() => {
    if (!debugListRef.current || activeTab !== 'debug') return;
    debugListRef.current.scrollTop = debugListRef.current.scrollHeight;
  }, [activeTab, debugEntries]);

  useEffect(() => {
    if (correlationResult) {
      setActiveTab('results');
      setActiveResultsView('matches');
    }
  }, [correlationResult]);

  useEffect(() => {
    if (!onEnsureIpMetadata || missingIps.length === 0) return;
    onEnsureIpMetadata(missingIps);
  }, [missingIps, onEnsureIpMetadata]);

  return (
    <section className="correlation-panel fade-in">
      <div className="correlation-panel-header">
        <div>
          <h3>Korelacja z Process Monitor</h3>
          <p>
            Przypisz ruch sieciowy do procesow na podstawie logow <code>.pml</code> z Procmon.
          </p>
        </div>
        <div className="correlation-actions">
          <button className="btn btn-secondary" onClick={onAddProcmonFiles}>
            + Dodaj pliki PML
          </button>
          <button className="btn btn-primary" onClick={onRunCorrelation} disabled={!canRun}>
            Uruchom korelacje
          </button>
          {isRunning && (
            <button className="btn btn-secondary btn-cancel" onClick={onCancelCorrelation}>
              Anuluj
            </button>
          )}
        </div>
      </div>

      {!pcapFilePath && <div className="analysis-warning">Korelacja wymaga pliku otwartego z dysku (dialog "Otworz plik").</div>}

      <div className="correlation-files">
        {procmonFiles.length === 0 ? (
          <p className="correlation-muted">Brak dolaczonych plikow Procmon - dodaj co najmniej jeden plik .pml.</p>
        ) : (
          procmonFiles.map((file) => (
            <div key={file.filePath} className="correlation-file-chip">
              <span className="correlation-file-name">{file.fileName}</span>
              <button onClick={() => onRemoveProcmonFile(file.filePath)} aria-label={`Usun ${file.fileName}`}>
                x
              </button>
            </div>
          ))
        )}
      </div>

      {correlationJob && (
        <div className="correlation-job">
          <div className="correlation-job-top">
            <span className={`correlation-state correlation-${correlationJob.state}`}>{statusLabel(correlationJob.state)}</span>
            <span className="correlation-stage-msg">{userFriendlyMessage(correlationJob)}</span>
            {isRunning && <span className="correlation-live-dot" aria-hidden="true" />}
          </div>
          <div className="progress-bar" style={{ marginTop: '0.5rem' }}>
            <div className="progress-fill" style={{ width: `${overallProgressPercent(correlationJob)}%` }} />
          </div>
          {isRunning && (
            <p className="correlation-running-hint">
              Etap: {stageLabel(correlationJob.progress.stage)} - moze potrwac kilka minut dla duzych plikow.
            </p>
          )}
          {correlationJob.error && <div className="analysis-warning">{correlationJob.error}</div>}
        </div>
      )}

      {(correlationJob || correlationResult) && (
        <div className="correlation-subtabs">
          <button className={`correlation-subtab ${activeTab === 'results' ? 'active' : ''}`} onClick={() => setActiveTab('results')}>
            Wyniki
          </button>
          <button className={`correlation-subtab ${activeTab === 'debug' ? 'active' : ''}`} onClick={() => setActiveTab('debug')}>
            Logi
            {isRunning && <span className="tab-badge">LIVE</span>}
          </button>
        </div>
      )}

      {activeTab === 'results' && (
        <>
          {summary && correlationResult ? (
            <div className="correlation-result">
              <div className="correlation-summary-grid">
                <SummaryBox
                  label="Dopasowane sesje"
                  value={summary.totalMatches.toLocaleString()}
                  accent="bright"
                  active={activeResultsView === 'matches'}
                  onClick={() => setActiveResultsView('matches')}
                />
                <SummaryBox label="Wysoka pewnosc" value={summary.highConfidence.toLocaleString()} accent="emerald" />
                <SummaryBox label="Srednia pewnosc" value={summary.mediumConfidence.toLocaleString()} accent="amber" />
                <SummaryBox label="Niska pewnosc" value={summary.lowConfidence.toLocaleString()} accent="orange" />
                <SummaryBox
                  label="Niedopasowane sesje"
                  value={summary.unmatchedSessions.toLocaleString()}
                  accent="muted"
                  active={activeResultsView === 'unmatched_sessions'}
                  onClick={() => setActiveResultsView('unmatched_sessions')}
                />
                <SummaryBox
                  label="Niedopasowane eventy"
                  value={summary.unmatchedEvents.toLocaleString()}
                  accent="muted"
                  active={activeResultsView === 'unmatched_events'}
                  onClick={() => setActiveResultsView('unmatched_events')}
                />
              </div>

              <div className="correlation-diagnostics">
                <span>
                  Przesuniecie czasu: <strong>{formatDurationUs(correlationResult.diagnostics.timeOffsetUs)}</strong>
                </span>
                <span>
                  Tryb: <strong>{parserModeLabel(correlationResult.diagnostics.parserMode)}</strong>
                </span>
                <span>
                  Widok: <strong>{resultsViewLabel(activeResultsView)}</strong>
                </span>
              </div>

              <div className="corr-cards">
                {activeResultsView === 'matches' && topMatches.map((row) => renderMatchCard(row, ipData, onGoToPcapIp))}
                {activeResultsView === 'unmatched_sessions' &&
                  topUnmatchedSessions.map((row) => renderUnmatchedSessionCard(row, ipData, onGoToPcapIp))}
                {activeResultsView === 'unmatched_events' &&
                  topUnmatchedEvents.map((row) => renderUnmatchedEventCard(row, ipData, onGoToPcapIp))}
              </div>

              {activeResultsView === 'matches' && topMatches.length === 0 && (
                <p className="correlation-muted" style={{ marginTop: '0.75rem' }}>
                  Brak dopasowan spelniajacych kryteria pewnosci.
                </p>
              )}
              {activeResultsView === 'unmatched_sessions' && topUnmatchedSessions.length === 0 && (
                <p className="correlation-muted" style={{ marginTop: '0.75rem' }}>
                  Brak niedopasowanych sesji.
                </p>
              )}
              {activeResultsView === 'unmatched_events' && topUnmatchedEvents.length === 0 && (
                <p className="correlation-muted" style={{ marginTop: '0.75rem' }}>
                  Brak niedopasowanych eventow.
                </p>
              )}
            </div>
          ) : (
            <div className="correlation-empty-results">
              <p>Brak wynikow korelacji.</p>
              <p className="correlation-muted">Dodaj pliki PML i uruchom korelacje, aby zobaczyc wyniki.</p>
            </div>
          )}
        </>
      )}

      {activeTab === 'debug' && (
        <div className="correlation-debug">
          <div className="correlation-debug-head">
            <span>Log zdarzen</span>
            <span>{debugEntries.length.toLocaleString()} wpisow</span>
          </div>
          <div className="correlation-debug-list" ref={debugListRef}>
            {debugEntries.length === 0 ? (
              <div className="correlation-debug-empty">
                {isRunning ? 'Oczekiwanie na pierwsze zdarzenia...' : 'Brak logow dla tego zadania.'}
              </div>
            ) : (
              debugEntries.map((entry, index) => (
                <div key={`${entry.ts}-${index}`} className={`correlation-debug-row level-${entry.level}`}>
                  <span className="debug-ts">{formatDebugTs(entry.ts)}</span>
                  <span className={`debug-level level-${entry.level}`}>{debugLevelLabel(entry.level)}</span>
                  <span className="debug-stage">{entry.stage ? stageLabel(entry.stage) : ''}</span>
                  <span className="debug-msg">{entry.message}</span>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </section>
  );
}

function renderMatchCard(match: CorrelationMatch, ipData: Record<string, IpLookupData>, onGoToPcapIp?: (ip: string) => void) {
  const { ip: publicIp, info } = resolveDisplayIp(match, ipData);
  return (
    <div key={`${match.sessionId}:${match.eventId}`} className="corr-card">
      <div className="corr-card-header">
        <div className="corr-card-process">
          <strong>{match.processName || '-'}</strong>
          <span className="corr-card-pid">PID {match.pid ?? '-'}</span>
        </div>
        <div className="corr-card-header-right">
          <span className={`confidence-badge confidence-${match.confidence}`}>{confidenceLabel(match.confidence)}</span>
        </div>
      </div>
      <div className="corr-card-fields">
        <div className="corr-field">
          <span className="corr-field-label">IP</span>
          {publicIp ? (
            <button className="ip-address ip-address-button" onClick={() => onGoToPcapIp?.(publicIp)} title={`Przejdz do ${publicIp} w widoku PCAP`}>
              {publicIp}
            </button>
          ) : (
            <span className="corr-field-empty">-</span>
          )}
        </div>
        <div className="corr-field">
          <span className="corr-field-label">ASN</span>
          {info?.asn ? <span className="asn-badge">{info.asn}</span> : <span className="corr-field-empty">-</span>}
        </div>
        <div className="corr-field">
          <span className="corr-field-label">ISP</span>
          <span className="corr-field-value">{info?.isp || info?.org || '-'}</span>
        </div>
      </div>
      <div className="corr-card-meta">
        <span className={`protocol-badge ${match.protocol.toLowerCase()}`}>{match.protocol}</span>
        <span className="corr-meta-item">{serviceLabel(match)}</span>
        <span className="corr-meta-sep">·</span>
        <span className="corr-meta-item corr-meta-mono">{match.packets.toLocaleString()} pkt</span>
        <span className="corr-meta-sep">·</span>
        <span className="corr-meta-item corr-meta-mono">{formatBytes(match.bytes)}</span>
      </div>
    </div>
  );
}

function renderUnmatchedSessionCard(
  session: CorrelationUnmatchedSession,
  ipData: Record<string, IpLookupData>,
  onGoToPcapIp?: (ip: string) => void
) {
  const { ip: publicIp, info } = resolveDisplayIpForUnmatchedSession(session, ipData);
  return (
    <div key={`unmatched-session:${session.sessionId}`} className="corr-card">
      <div className="corr-card-header">
        <div className="corr-card-process">
          <strong>Sesja bez dopasowania</strong>
          <span className="corr-card-pid">ID {session.sessionId}</span>
        </div>
        <div className="corr-card-header-right">
          <span className="corr-reason-badge">{session.reason || 'Brak powodu'}</span>
        </div>
      </div>
      <div className="corr-card-fields">
        <div className="corr-field">
          <span className="corr-field-label">IP</span>
          {publicIp ? (
            <button className="ip-address ip-address-button" onClick={() => onGoToPcapIp?.(publicIp)} title={`Przejdz do ${publicIp} w widoku PCAP`}>
              {publicIp}
            </button>
          ) : (
            <span className="corr-field-empty">-</span>
          )}
        </div>
        <div className="corr-field">
          <span className="corr-field-label">ASN</span>
          {info?.asn ? <span className="asn-badge">{info.asn}</span> : <span className="corr-field-empty">-</span>}
        </div>
        <div className="corr-field">
          <span className="corr-field-label">ISP</span>
          <span className="corr-field-value">{info?.isp || info?.org || '-'}</span>
        </div>
      </div>
      <div className="corr-card-meta">
        <span className={`protocol-badge ${session.protocol.toLowerCase()}`}>{session.protocol}</span>
        <span className="corr-meta-item">{serviceLabelByPort(session.dstPort)}</span>
        <span className="corr-meta-sep">·</span>
        <span className="corr-meta-item corr-meta-mono">{session.packets.toLocaleString()} pkt</span>
        <span className="corr-meta-sep">·</span>
        <span className="corr-meta-item corr-meta-mono">{formatBytes(session.bytes)}</span>
      </div>
    </div>
  );
}

function renderUnmatchedEventCard(
  event: CorrelationUnmatchedProcmonEvent,
  ipData: Record<string, IpLookupData>,
  onGoToPcapIp?: (ip: string) => void
) {
  const { ip: publicIp, info } = resolveDisplayIpForUnmatchedEvent(event, ipData);
  return (
    <div key={`unmatched-event:${event.eventId}`} className="corr-card">
      <div className="corr-card-header">
        <div className="corr-card-process">
          <strong>{event.processName || 'Nieznany proces'}</strong>
          <span className="corr-card-pid">PID {event.pid ?? '-'}</span>
        </div>
        <div className="corr-card-header-right">
          <span className="corr-reason-badge">{event.reason || 'Brak powodu'}</span>
        </div>
      </div>
      <div className="corr-card-fields">
        <div className="corr-field">
          <span className="corr-field-label">IP</span>
          {publicIp ? (
            <button className="ip-address ip-address-button" onClick={() => onGoToPcapIp?.(publicIp)} title={`Przejdz do ${publicIp} w widoku PCAP`}>
              {publicIp}
            </button>
          ) : (
            <span className="corr-field-empty">-</span>
          )}
        </div>
        <div className="corr-field">
          <span className="corr-field-label">ASN</span>
          {info?.asn ? <span className="asn-badge">{info.asn}</span> : <span className="corr-field-empty">-</span>}
        </div>
        <div className="corr-field">
          <span className="corr-field-label">ISP</span>
          <span className="corr-field-value">{info?.isp || info?.org || '-'}</span>
        </div>
      </div>
      <div className="corr-card-meta">
        <span className="corr-meta-item">{event.operation || 'Zdarzenie sieciowe'}</span>
        <span className="corr-meta-sep">·</span>
        <span className="corr-meta-item">{serviceLabelByPort(event.remotePort)}</span>
        <span className="corr-meta-sep">·</span>
        <span className="corr-meta-item corr-meta-mono">{formatTimestampUs(event.tsUs)}</span>
      </div>
    </div>
  );
}

function SummaryBox({
  label,
  value,
  accent = 'bright',
  active = false,
  onClick
}: {
  label: string;
  value: string;
  accent?: string;
  active?: boolean;
  onClick?: () => void;
}) {
  return (
    <button
      type="button"
      className={`correlation-summary-box accent-${accent} ${onClick ? 'clickable' : ''} ${active ? 'active' : ''}`}
      onClick={onClick}
    >
      <span>{label}</span>
      <strong>{value}</strong>
    </button>
  );
}

function userFriendlyMessage(job: CorrelationJobStatus): string {
  if (job.state === 'completed') return 'Korelacja zakonczona pomyslnie.';
  if (job.state === 'failed') return 'Korelacja zakonczyla sie bledem.';
  if (job.state === 'cancelled') return 'Korelacja anulowana.';
  const stage = stageLabel(job.progress.stage);
  const pct = job.progress.total > 0 ? ` (${Math.round((job.progress.current / job.progress.total) * 100)}%)` : '';
  return `${stage}${pct}`;
}

function stageLabel(stage: CorrelationJobStatus['progress']['stage']): string {
  switch (stage) {
    case 'prepare':
      return 'Przygotowanie';
    case 'ingest_pcap':
      return 'Odczyt PCAP';
    case 'ingest_procmon':
      return 'Odczyt Procmon';
    case 'align':
      return 'Synchronizacja czasu';
    case 'match':
      return 'Dopasowywanie';
    case 'finalize':
      return 'Finalizacja';
    default:
      return stage;
  }
}

function statusLabel(state: CorrelationJobStatus['state']): string {
  switch (state) {
    case 'queued':
      return 'Kolejka';
    case 'running':
      return 'Trwa';
    case 'completed':
      return 'Gotowe';
    case 'failed':
      return 'Blad';
    case 'cancelled':
      return 'Anulowano';
    default:
      return state;
  }
}

function confidenceLabel(confidence: CorrelationMatch['confidence']): string {
  switch (confidence) {
    case 'high':
      return 'Wysoka';
    case 'medium':
      return 'Srednia';
    case 'low':
      return 'Niska';
    default:
      return confidence;
  }
}

function parserModeLabel(mode: CorrelationReportV1['diagnostics']['parserMode']): string {
  switch (mode) {
    case 'hybrid':
      return 'Hybrydowy';
    case 'xml_only':
      return 'XML';
    case 'parser_only':
      return 'Parser';
    default:
      return mode;
  }
}

function resultsViewLabel(view: 'matches' | 'unmatched_sessions' | 'unmatched_events'): string {
  switch (view) {
    case 'matches':
      return 'Dopasowane sesje';
    case 'unmatched_sessions':
      return 'Niedopasowane sesje';
    case 'unmatched_events':
      return 'Niedopasowane eventy';
    default:
      return view;
  }
}

function overallProgressPercent(job: CorrelationJobStatus): number {
  const ranges: Record<CorrelationJobStatus['progress']['stage'], [number, number]> = {
    prepare: [0, 8],
    ingest_pcap: [8, 28],
    ingest_procmon: [28, 68],
    align: [68, 82],
    match: [82, 97],
    finalize: [97, 100]
  };
  const [start, end] = ranges[job.progress.stage] ?? [0, 100];
  const total = job.progress.total > 0 ? job.progress.total : 1;
  const part = Math.max(0, Math.min(1, job.progress.current / total));
  if (job.state === 'completed') return 100;
  if (job.state === 'failed' || job.state === 'cancelled') return Math.max(start, 5);
  return start + (end - start) * part;
}

function formatDebugTs(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleTimeString('pl-PL', { hour12: false });
}

function debugLevelLabel(level: 'info' | 'warning' | 'error'): string {
  if (level === 'warning') return 'WARN';
  if (level === 'error') return 'BLAD';
  return 'INFO';
}

function resolveDisplayIp(match: CorrelationMatch, ipData: Record<string, IpLookupData>) {
  return resolveFromCandidates(collectPublicIps([match.dstIp, match.srcIp, match.eventRemoteIp]), ipData);
}

function resolveDisplayIpForUnmatchedSession(session: CorrelationUnmatchedSession, ipData: Record<string, IpLookupData>) {
  return resolveFromCandidates(collectPublicIps([session.dstIp, session.srcIp]), ipData);
}

function resolveDisplayIpForUnmatchedEvent(event: CorrelationUnmatchedProcmonEvent, ipData: Record<string, IpLookupData>) {
  return resolveFromCandidates(collectPublicIps([event.remoteIp]), ipData);
}

function resolveFromCandidates(candidates: string[], ipData: Record<string, IpLookupData>): { ip: string | null; info: IpLookupData | undefined } {
  for (const ip of candidates) {
    const info = lookupIpInfo(ipData, ip);
    if (info) return { ip, info };
  }
  return { ip: candidates[0] ?? null, info: undefined };
}

function listPublicIpCandidatesGeneric(record: CorrelationMatch | CorrelationUnmatchedSession | CorrelationUnmatchedProcmonEvent): string[] {
  if ('tsUs' in record) return collectPublicIps([record.remoteIp]);
  if ('matchedAtUs' in record) return collectPublicIps([record.dstIp, record.srcIp, record.eventRemoteIp]);
  return collectPublicIps([record.dstIp, record.srcIp]);
}

function collectPublicIps(values: Array<string | null | undefined>): string[] {
  const unique: string[] = [];
  const seen = new Set<string>();
  for (const raw of values) {
    if (!raw || !isPublicIp(raw)) continue;
    const ip = raw.trim().toLowerCase();
    if (seen.has(ip)) continue;
    seen.add(ip);
    unique.push(ip);
  }
  return unique;
}

function lookupIpInfo(ipData: Record<string, IpLookupData>, ip: string): IpLookupData | undefined {
  const normalized = ip.trim().toLowerCase();
  return ipData[normalized] ?? ipData[normalized.toLowerCase()];
}

function isPublicIp(ip: string): boolean {
  if (!ip || ip === '0.0.0.0' || ip === '255.255.255.255') return false;
  if (ip.includes(':')) {
    const n = ip.toLowerCase();
    if (n === '::1' || n.startsWith('fe80:') || n.startsWith('fc') || n.startsWith('fd')) return false;
    return true;
  }
  const p = ip.split('.').map(Number);
  if (p.length !== 4) return false;
  if (p[0] === 10 || p[0] === 127) return false;
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return false;
  if (p[0] === 192 && p[1] === 168) return false;
  if (p[0] === 169 && p[1] === 254) return false;
  if (p[0] >= 224) return false;
  return true;
}

function formatDurationUs(value: number): string {
  const sign = value < 0 ? '-' : '';
  const abs = Math.abs(value);
  if (abs >= 1_000_000) return `${sign}${(abs / 1_000_000).toFixed(2)} s`;
  if (abs >= 1000) return `${sign}${(abs / 1000).toFixed(2)} ms`;
  return `${sign}${abs} us`;
}

function formatTimestampUs(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return '-';
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
  return formatDurationUs(value);
}

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let size = bytes;
  let idx = 0;
  while (size >= 1024 && idx < units.length - 1) {
    size /= 1024;
    idx += 1;
  }
  return `${size.toFixed(size >= 10 ? 1 : 2)} ${units[idx]}`;
}

function serviceLabel(match: CorrelationMatch): string {
  return serviceLabelByPort(match.dstPort);
}

function serviceLabelByPort(port: number | null): string {
  if (typeof port !== 'number') return '-';
  if (port === 80) return 'HTTP';
  if (port === 443) return 'HTTPS';
  if (port === 53) return 'DNS';
  if (port === 22) return 'SSH';
  return `Port ${port}`;
}

export default CorrelationPanel;
