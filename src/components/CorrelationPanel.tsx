import React, { useEffect, useMemo, useRef, useState } from 'react';
import { summarizeCorrelation } from '../utils/correlationSummary';
import type { CorrelationJobStatus, CorrelationMatch, CorrelationReportV1, ProcmonAttachment } from '../types';

interface CorrelationPanelProps {
  pcapFilePath?: string;
  procmonFiles: ProcmonAttachment[];
  correlationJob: CorrelationJobStatus | null;
  correlationResult: CorrelationReportV1 | null;
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
  onAddProcmonFiles,
  onRemoveProcmonFile,
  onRunCorrelation,
  onCancelCorrelation
}: CorrelationPanelProps) {
  const [activeTab, setActiveTab] = useState<'results' | 'debug'>('debug');
  const debugListRef = useRef<HTMLDivElement | null>(null);
  const summary = useMemo(
    () => (correlationResult ? summarizeCorrelation(correlationResult) : null),
    [correlationResult]
  );

  const isRunning = correlationJob?.state === 'queued' || correlationJob?.state === 'running';
  const canRun = Boolean(pcapFilePath && procmonFiles.length > 0 && !isRunning);
  const topMatches = useMemo(() => {
    if (!correlationResult) return [];
    return [...correlationResult.matches].sort((a, b) => b.score - a.score).slice(0, 40);
  }, [correlationResult]);
  const progress = correlationJob ? overallProgressPercent(correlationJob) : 0;
  const debugEntries = correlationJob?.debugEntries ?? [];

  useEffect(() => {
    if (correlationResult) {
      setActiveTab((current) => (current === 'debug' ? current : 'results'));
    }
  }, [correlationResult]);

  useEffect(() => {
    if (!debugListRef.current || activeTab !== 'debug') return;
    debugListRef.current.scrollTop = debugListRef.current.scrollHeight;
  }, [debugEntries, activeTab]);

  return (
    <section className="correlation-panel">
      <div className="correlation-panel-header">
        <div>
          <h3>Korelacja Process Monitor</h3>
          <p>
            Polacz sesje sieciowe z PCAP z procesami/PID na podstawie logow <code>.pml</code>.
          </p>
        </div>
        <div className="correlation-actions">
          <button className="btn btn-secondary" onClick={onAddProcmonFiles}>
            Dodaj pliki PML
          </button>
          <button className="btn btn-primary" onClick={onRunCorrelation} disabled={!canRun}>
            Uruchom korelacje
          </button>
          {isRunning && (
            <button className="btn btn-secondary" onClick={onCancelCorrelation}>
              Anuluj
            </button>
          )}
        </div>
      </div>

      {!pcapFilePath && (
        <div className="analysis-warning">
          Korelacja wymaga pliku otwartego z dysku. Dla plikow bez sciezki (drag-and-drop z buforem) uruchom analize po
          wskazaniu pliku przez dialog.
        </div>
      )}

      <div className="correlation-files">
        {procmonFiles.length === 0 ? (
          <p className="correlation-muted">Brak zalaczonych plikow Procmon.</p>
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
            <span>{correlationJob.progress.message}</span>
            {isRunning && <span className="correlation-live-dot" aria-hidden="true" />}
            <span className="correlation-last-event">Ostatni event: {formatEventAge(correlationJob.lastEventAt)}</span>
          </div>
          <div className="progress-bar">
            <div
              className="progress-fill"
              style={{
                width: `${progress}%`
              }}
            />
          </div>
          {isRunning && (
            <div className="correlation-running-hint">
              Trwa analiza. Etap "{stageLabel(correlationJob.progress.stage)}" moze potrwac kilka minut dla duzych plikow.
            </div>
          )}
          {correlationJob.error && <div className="analysis-warning">Blad korelacji: {correlationJob.error}</div>}
        </div>
      )}

      {(correlationJob || correlationResult) && (
        <div className="correlation-subtabs">
          <button className={`correlation-subtab ${activeTab === 'results' ? 'active' : ''}`} onClick={() => setActiveTab('results')}>
            Wyniki
          </button>
          <button className={`correlation-subtab ${activeTab === 'debug' ? 'active' : ''}`} onClick={() => setActiveTab('debug')}>
            Debug na zywo
            {isRunning && <span className="tab-badge">LIVE</span>}
          </button>
        </div>
      )}

      {activeTab === 'results' && (
        <>
          {summary && correlationResult ? (
            <div className="correlation-result">
              <div className="correlation-summary-grid">
                <SummaryBox label="Dopasowane sesje" value={summary.totalMatches.toLocaleString()} />
                <SummaryBox label="Wysoka pewnosc" value={summary.highConfidence.toLocaleString()} />
                <SummaryBox label="Srednia pewnosc" value={summary.mediumConfidence.toLocaleString()} />
                <SummaryBox label="Niska pewnosc" value={summary.lowConfidence.toLocaleString()} />
                <SummaryBox label="Niedopasowane sesje" value={summary.unmatchedSessions.toLocaleString()} />
                <SummaryBox label="Niedopasowane eventy" value={summary.unmatchedEvents.toLocaleString()} />
              </div>

              <div className="correlation-diagnostics">
                <span>
                  Offset czasu: <strong>{formatDurationUs(correlationResult.diagnostics.timeOffsetUs)}</strong>
                </span>
                <span>
                  Tryb parsera: <strong>{parserModeLabel(correlationResult.diagnostics.parserMode)}</strong>
                </span>
                <span>
                  Drift: <strong>{correlationResult.diagnostics.drift.toFixed(4)}</strong>
                </span>
              </div>

              <div className="correlation-table-wrapper">
                <table className="data-table correlation-table">
                  <thead>
                    <tr>
                      <th>Proces</th>
                      <th>PID</th>
                      <th>Polaczenie</th>
                      <th>Ocena</th>
                      <th>Pewnosc</th>
                      <th>Offset</th>
                      <th>Operacja</th>
                    </tr>
                  </thead>
                  <tbody>
                    {topMatches.map((match) => (
                      <MatchRow key={`${match.sessionId}:${match.eventId}`} match={match} />
                    ))}
                  </tbody>
                </table>
              </div>
              {topMatches.length === 0 && <p className="correlation-muted">Brak dopasowan high/medium/low dla aktualnych progow.</p>}
            </div>
          ) : (
            <p className="correlation-muted">Brak wynikow korelacji. Uruchom zadanie i sprawdz postep w zakladce Debug na zywo.</p>
          )}
        </>
      )}

      {activeTab === 'debug' && (
        <div className="correlation-debug">
          <div className="correlation-debug-head">
            <span>Log zdarzen korelacji</span>
            <span>{debugEntries.length.toLocaleString()} wpisow</span>
          </div>
          <div className="correlation-debug-list" ref={debugListRef}>
            {debugEntries.length === 0 ? (
              <div className="correlation-debug-empty">
                {isRunning
                  ? 'Oczekiwanie na pierwsze eventy sidecara...'
                  : 'Brak logow debug dla tego zadania.'}
              </div>
            ) : (
              debugEntries.map((entry, index) => (
                <div key={`${entry.ts}-${index}`} className={`correlation-debug-row level-${entry.level}`}>
                  <span className="debug-ts">{formatDebugTs(entry.ts)}</span>
                  <span className={`debug-level level-${entry.level}`}>{debugLevelLabel(entry.level)}</span>
                  <span className="debug-stage">{entry.stage ? stageLabel(entry.stage) : '-'}</span>
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

function SummaryBox({ label, value }: { label: string; value: string }) {
  return (
    <div className="correlation-summary-box">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function MatchRow({ match }: { match: CorrelationMatch }) {
  return (
    <tr>
      <td>{match.processName || 'N/D'}</td>
      <td>{match.pid ?? 'N/D'}</td>
      <td>
        <code>
          {match.srcIp}:{match.srcPort ?? '-'} {'->'} {match.dstIp}:{match.dstPort ?? '-'}
        </code>
      </td>
      <td>{match.score}</td>
      <td>
        <span className={`confidence-badge confidence-${match.confidence}`}>{confidenceLabel(match.confidence)}</span>
      </td>
      <td>{formatDurationUs(match.offsetUs)}</td>
      <td>{match.operation || 'N/D'}</td>
    </tr>
  );
}

function stageLabel(stage: CorrelationJobStatus['progress']['stage']): string {
  switch (stage) {
    case 'prepare':
      return 'przygotowanie';
    case 'ingest_pcap':
      return 'odczyt PCAP';
    case 'ingest_procmon':
      return 'odczyt Procmon';
    case 'align':
      return 'synchronizacja czasu';
    case 'match':
      return 'dopasowanie';
    case 'finalize':
      return 'finalizacja';
    default:
      return stage;
  }
}

function statusLabel(state: CorrelationJobStatus['state']): string {
  switch (state) {
    case 'queued':
      return 'W KOLEJCE';
    case 'running':
      return 'TRWA';
    case 'completed':
      return 'ZAKONCZONO';
    case 'failed':
      return 'BLAD';
    case 'cancelled':
      return 'ANULOWANO';
    default:
      return state;
  }
}

function confidenceLabel(confidence: CorrelationMatch['confidence']): string {
  switch (confidence) {
    case 'high':
      return 'WYSOKA';
    case 'medium':
      return 'SREDNIA';
    case 'low':
      return 'NISKA';
    default:
      return confidence;
  }
}

function parserModeLabel(mode: CorrelationReportV1['diagnostics']['parserMode']): string {
  switch (mode) {
    case 'hybrid':
      return 'hybrydowy';
    case 'xml_only':
      return 'tylko XML';
    case 'parser_only':
      return 'tylko parser';
    default:
      return mode;
  }
}

function overallProgressPercent(job: CorrelationJobStatus): number {
  const stageRanges: Record<CorrelationJobStatus['progress']['stage'], [number, number]> = {
    prepare: [0, 8],
    ingest_pcap: [8, 28],
    ingest_procmon: [28, 68],
    align: [68, 82],
    match: [82, 97],
    finalize: [97, 100]
  };

  const [start, end] = stageRanges[job.progress.stage] ?? [0, 100];
  const span = end - start;
  const total = job.progress.total > 0 ? job.progress.total : 1;
  const subProgress = Math.max(0, Math.min(1, job.progress.current / total));

  if (job.state === 'completed') return 100;
  if (job.state === 'failed' || job.state === 'cancelled') return Math.max(start, 5);

  return start + span * subProgress;
}

function formatDebugTs(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleTimeString('pl-PL', { hour12: false });
}

function formatEventAge(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'brak';
  const deltaMs = Date.now() - date.getTime();
  if (deltaMs < 2000) return 'przed chwila';
  if (deltaMs < 60_000) return `${Math.floor(deltaMs / 1000)} s temu`;
  return `${Math.floor(deltaMs / 60_000)} min temu`;
}

function debugLevelLabel(level: 'info' | 'warning' | 'error'): string {
  switch (level) {
    case 'info':
      return 'INFO';
    case 'warning':
      return 'OSTRZEZENIE';
    case 'error':
      return 'BLAD';
    default:
      return level;
  }
}

function formatDurationUs(value: number): string {
  const sign = value < 0 ? '-' : '';
  const abs = Math.abs(value);
  if (abs >= 1_000_000) {
    return `${sign}${(abs / 1_000_000).toFixed(2)} s`;
  }
  if (abs >= 1000) {
    return `${sign}${(abs / 1000).toFixed(2)} ms`;
  }
  return `${sign}${abs} us`;
}

export default CorrelationPanel;
