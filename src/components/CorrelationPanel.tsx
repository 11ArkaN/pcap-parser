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
    const [expandedRows, setExpandedRows] = useState<Record<string, boolean>>({});
    const debugListRef = useRef<HTMLDivElement | null>(null);

    const summary = useMemo(() => (correlationResult ? summarizeCorrelation(correlationResult) : null), [correlationResult]);
    const isRunning = correlationJob?.state === 'queued' || correlationJob?.state === 'running';
    const canRun = Boolean(pcapFilePath && procmonFiles.length > 0 && !isRunning);
    const debugEntries = correlationJob?.debugEntries ?? [];

    const topMatches = useMemo(() => {
        if (!correlationResult) return [];
        return [...correlationResult.matches].sort((a, b) => b.score - a.score).slice(0, 200);
    }, [correlationResult]);

    const topUnmatchedSessions = useMemo(() => {
        if (!correlationResult) return [];
        return [...correlationResult.unmatchedSessions].sort((a, b) => b.packets - a.packets).slice(0, 200);
    }, [correlationResult]);

    const topUnmatchedEvents = useMemo(() => {
        if (!correlationResult) return [];
        return [...correlationResult.unmatchedProcmonEvents].sort((a, b) => b.tsUs - a.tsUs).slice(0, 200);
    }, [correlationResult]);

    const missingIps = useMemo(() => {
        if (!correlationResult) return [];
        const pending = new Set<string>();
        for (const record of [...topMatches, ...topUnmatchedSessions, ...topUnmatchedEvents]) {
            const candidates = listPublicIpCandidatesGeneric(record);
            for (const candidate of candidates) {
                if (!lookupIpInfo(ipData, candidate)) {
                    pending.add(candidate);
                }
            }
        }
        return Array.from(pending).slice(0, 150);
    }, [correlationResult, topMatches, topUnmatchedSessions, topUnmatchedEvents, ipData]);

    const progress = correlationJob ? overallProgressPercent(correlationJob) : 0;

    useEffect(() => {
        if (correlationResult) {
            setActiveTab('results');
            setActiveResultsView('matches');
        }
    }, [correlationResult]);

    useEffect(() => {
        if (!debugListRef.current || activeTab !== 'debug') return;
        debugListRef.current.scrollTop = debugListRef.current.scrollHeight;
    }, [debugEntries, activeTab]);

    useEffect(() => {
        setExpandedRows({});
    }, [correlationResult?.generatedAt, activeResultsView]);

    useEffect(() => {
        if (!onEnsureIpMetadata || missingIps.length === 0) return;
        onEnsureIpMetadata(missingIps);
    }, [missingIps, onEnsureIpMetadata]);

    const toggleExpanded = (rowKey: string) => {
        setExpandedRows((current) => ({ ...current, [rowKey]: !current[rowKey] }));
    };

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
                        <div className="progress-fill" style={{ width: `${progress}%` }} />
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
                                {activeResultsView === 'matches' &&
                                    topMatches.map((match) => renderMatchCard(match, ipData, expandedRows, toggleExpanded, onGoToPcapIp))}
                                {activeResultsView === 'unmatched_sessions' &&
                                    topUnmatchedSessions.map((session) =>
                                        renderUnmatchedSessionCard(session, ipData, expandedRows, toggleExpanded, onGoToPcapIp)
                                    )}
                                {activeResultsView === 'unmatched_events' &&
                                    topUnmatchedEvents.map((event) => renderUnmatchedEventCard(event, ipData, expandedRows, toggleExpanded, onGoToPcapIp))}
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

function DetailItem({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
    return (
        <div className="correlation-detail-item">
            <span>{label}</span>
            <strong className={mono ? 'mono' : ''}>{value}</strong>
        </div>
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

function formatTimestampUs(value: number): string {
    if (!Number.isFinite(value) || value <= 0) return '-';
    const ms = Math.floor(value / 1000);
    if (ms > 946684800000 && ms < 4102444800000) {
        const date = new Date(ms);
        return date.toLocaleString('pl-PL', {
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

function formatDurationUs(value: number): string {
    const sign = value < 0 ? '-' : '';
    const abs = Math.abs(value);
    if (abs >= 1_000_000) return `${sign}${(abs / 1_000_000).toFixed(2)} s`;
    if (abs >= 1000) return `${sign}${(abs / 1000).toFixed(2)} ms`;
    return `${sign}${abs} us`;
}

function formatDebugTs(value: string): string {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleTimeString('pl-PL', { hour12: false });
}

function debugLevelLabel(level: 'info' | 'warning' | 'error'): string {
    switch (level) {
        case 'info':
            return 'INFO';
        case 'warning':
            return 'WARN';
        case 'error':
            return 'BLAD';
        default:
            return level;
    }
}

function formatOptionalNumber(value: number | null | undefined): string {
    if (typeof value !== 'number') return '-';
    return value.toString();
}

function resolveDisplayIp(match: CorrelationMatch, ipData: Record<string, IpLookupData>): { ip: string | null; info: IpLookupData | undefined } {
    const candidates = listPublicIpCandidates(match);
    for (const ip of candidates) {
        const info = lookupIpInfo(ipData, ip);
        if (info) {
            return { ip, info };
        }
    }
    if (candidates.length > 0) {
        return { ip: candidates[0], info: undefined };
    }
    return { ip: null, info: undefined };
}

function resolveDisplayIpForUnmatchedSession(
    session: CorrelationUnmatchedSession,
    ipData: Record<string, IpLookupData>
): { ip: string | null; info: IpLookupData | undefined } {
    const candidates = collectPublicIps([session.dstIp, session.srcIp]);
    for (const ip of candidates) {
        const info = lookupIpInfo(ipData, ip);
        if (info) return { ip, info };
    }
    return { ip: candidates[0] ?? null, info: undefined };
}

function resolveDisplayIpForUnmatchedEvent(
    event: CorrelationUnmatchedProcmonEvent,
    ipData: Record<string, IpLookupData>
): { ip: string | null; info: IpLookupData | undefined } {
    const candidates = collectPublicIps([event.remoteIp]);
    for (const ip of candidates) {
        const info = lookupIpInfo(ipData, ip);
        if (info) return { ip, info };
    }
    return { ip: candidates[0] ?? null, info: undefined };
}

function listPublicIpCandidates(match: CorrelationMatch): string[] {
    return collectPublicIps([match.dstIp, match.srcIp]);
}

function listPublicIpCandidatesGeneric(record: CorrelationMatch | CorrelationUnmatchedSession | CorrelationUnmatchedProcmonEvent): string[] {
    if ('tsUs' in record) return collectPublicIps([record.remoteIp]);
    if ('matchedAtUs' in record) return collectPublicIps([record.dstIp, record.srcIp]);
    return collectPublicIps([record.dstIp, record.srcIp]);
}

function collectPublicIps(values: Array<string | null | undefined>): string[] {
    const unique: string[] = [];
    const seen = new Set<string>();
    for (const raw of values) {
        if (!raw || !isPublicIp(raw)) continue;
        const normalized = normalizeIp(raw);
        if (!normalized || seen.has(normalized)) continue;
        seen.add(normalized);
        unique.push(normalized);
    }
    return unique;
}

function renderMatchCard(
    match: CorrelationMatch,
    ipData: Record<string, IpLookupData>,
    expandedRows: Record<string, boolean>,
    toggleExpanded: (rowKey: string) => void,
    onGoToPcapIp?: (ip: string) => void
) {
    const rowKey = `match:${match.sessionId}:${match.eventId}`;
    const expanded = Boolean(expandedRows[rowKey]);
    const { ip: publicIp, info } = resolveDisplayIp(match, ipData);

    return (
        <div key={rowKey} className={`corr-card ${expanded ? 'expanded' : ''}`}>
            <div className="corr-card-header">
                <div className="corr-card-process">
                    <strong>{match.processName || '—'}</strong>
                    <span className="corr-card-pid">PID {match.pid ?? '—'}</span>
                </div>
                <div className="corr-card-header-right">
                    <span className={`confidence-badge confidence-${match.confidence}`}>{confidenceLabel(match.confidence)}</span>
                    <button className="corr-card-toggle" onClick={() => toggleExpanded(rowKey)}>
                        {expanded ? '▾' : '▸'}
                    </button>
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
                        <span className="corr-field-empty">—</span>
                    )}
                </div>
                <div className="corr-field">
                    <span className="corr-field-label">ASN</span>
                    {info?.asn ? <span className="asn-badge">{info.asn}</span> : <span className="corr-field-empty">—</span>}
                </div>
                <div className="corr-field">
                    <span className="corr-field-label">ISP</span>
                    <span className="corr-field-value">{info?.isp || info?.org || '—'}</span>
                </div>
                <div className="corr-field">
                    <span className="corr-field-label">Lokalizacja</span>
                    {info?.country ? (
                        <div className="country-flag">
                            <span className="flag">{getFlagEmoji(info.country)}</span>
                            <span className="country-name">{info.country}{info.city ? `, ${info.city}` : ''}</span>
                        </div>
                    ) : <span className="corr-field-empty">—</span>}
                </div>
                <div className="corr-field">
                    <span className="corr-field-label">CIDR</span>
                    <span className="cidr-block">{(info?.cidr as string) || (info?.range as string) || '—'}</span>
                </div>
            </div>

            <div className="corr-card-meta">
                <span className={`protocol-badge ${match.protocol.toLowerCase()}`}>{match.protocol}</span>
                <span className="corr-meta-item">{serviceLabel(match)}</span>
                <span className="corr-meta-sep">·</span>
                <span className="corr-meta-item corr-meta-mono">{match.packets.toLocaleString()} pkt</span>
                <span className="corr-meta-sep">·</span>
                <span className="corr-meta-item corr-meta-mono">{formatBytes(match.bytes)}</span>
                <span className="corr-meta-sep">·</span>
                <span className="corr-meta-item corr-meta-mono">{formatTimestampUs(match.firstSeenUs)}</span>
            </div>

            {expanded && (
                <div className="corr-card-details">
                    <DetailItem label="Sciezka procesu" value={match.processPath || '—'} />
                    <DetailItem label="Linia polecen" value={match.commandLine || '—'} />
                    <DetailItem label="Uzytkownik" value={match.userName || '—'} />
                    <DetailItem label="Firma" value={match.company || '—'} />
                    <DetailItem label="PID rodzica" value={formatOptionalNumber(match.parentPid)} />
                    <DetailItem label="Integralnosc" value={match.integrityLevel || '—'} />
                    <DetailItem label="Podpis" value={match.signer || '—'} />
                    <DetailItem label="Hash" value={match.imageHash || '—'} mono />
                    <DetailItem label="Operacja" value={match.operation || '—'} />
                    <DetailItem label="Wynik" value={match.result || '—'} />
                    <DetailItem
                        label="Endpoint"
                        value={`${match.eventLocalIp || '—'}:${match.eventLocalPort ?? '—'} → ${match.eventRemoteIp || '—'}:${match.eventRemotePort ?? '—'}`}
                        mono
                    />
                    <DetailItem label="Kierunek" value={match.eventDirection || '—'} />
                    <DetailItem label="Czas start" value={formatTimestampUs(match.firstSeenUs)} />
                    <DetailItem label="Czas koniec" value={formatTimestampUs(match.lastSeenUs)} />
                    <DetailItem label="Delta czasu" value={formatDurationUs(match.offsetUs)} />
                    <DetailItem label="Powody" value={formatReasons(match)} />
                </div>
            )}
        </div>
    );
}

function renderUnmatchedSessionCard(
    session: CorrelationUnmatchedSession,
    ipData: Record<string, IpLookupData>,
    expandedRows: Record<string, boolean>,
    toggleExpanded: (rowKey: string) => void,
    onGoToPcapIp?: (ip: string) => void
) {
    const rowKey = `unmatched-session:${session.sessionId}`;
    const expanded = Boolean(expandedRows[rowKey]);
    const { ip: publicIp, info } = resolveDisplayIpForUnmatchedSession(session, ipData);

    return (
        <div key={rowKey} className={`corr-card ${expanded ? 'expanded' : ''}`}>
            <div className="corr-card-header">
                <div className="corr-card-process">
                    <strong>Sesja bez dopasowania</strong>
                    <span className="corr-card-pid">ID {session.sessionId}</span>
                </div>
                <div className="corr-card-header-right">
                    <span className="corr-reason-badge">{session.reason || 'Brak powodu'}</span>
                    <button className="corr-card-toggle" onClick={() => toggleExpanded(rowKey)}>
                        {expanded ? '▾' : '▸'}
                    </button>
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
                        <span className="corr-field-empty">—</span>
                    )}
                </div>
                <div className="corr-field">
                    <span className="corr-field-label">ASN</span>
                    {info?.asn ? <span className="asn-badge">{info.asn}</span> : <span className="corr-field-empty">—</span>}
                </div>
                <div className="corr-field">
                    <span className="corr-field-label">ISP</span>
                    <span className="corr-field-value">{info?.isp || info?.org || '—'}</span>
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

            {expanded && (
                <div className="corr-card-details">
                    <DetailItem label="ID sesji" value={session.sessionId} mono />
                    <DetailItem label="Powod" value={session.reason || '—'} />
                    <DetailItem label="Src" value={`${session.srcIp}:${session.srcPort ?? '—'}`} mono />
                    <DetailItem label="Dst" value={`${session.dstIp}:${session.dstPort ?? '—'}`} mono />
                    <DetailItem label="Czas start" value={formatTimestampUs(session.firstSeenUs)} />
                    <DetailItem label="Czas koniec" value={formatTimestampUs(session.lastSeenUs)} />
                </div>
            )}
        </div>
    );
}

function renderUnmatchedEventCard(
    event: CorrelationUnmatchedProcmonEvent,
    ipData: Record<string, IpLookupData>,
    expandedRows: Record<string, boolean>,
    toggleExpanded: (rowKey: string) => void,
    onGoToPcapIp?: (ip: string) => void
) {
    const rowKey = `unmatched-event:${event.eventId}`;
    const expanded = Boolean(expandedRows[rowKey]);
    const { ip: publicIp, info } = resolveDisplayIpForUnmatchedEvent(event, ipData);

    return (
        <div key={rowKey} className={`corr-card ${expanded ? 'expanded' : ''}`}>
            <div className="corr-card-header">
                <div className="corr-card-process">
                    <strong>{event.processName || 'Nieznany proces'}</strong>
                    <span className="corr-card-pid">PID {event.pid ?? '—'}</span>
                </div>
                <div className="corr-card-header-right">
                    <span className="corr-reason-badge">{event.reason || 'Brak powodu'}</span>
                    <button className="corr-card-toggle" onClick={() => toggleExpanded(rowKey)}>
                        {expanded ? '▾' : '▸'}
                    </button>
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
                        <span className="corr-field-empty">—</span>
                    )}
                </div>
                <div className="corr-field">
                    <span className="corr-field-label">ASN</span>
                    {info?.asn ? <span className="asn-badge">{info.asn}</span> : <span className="corr-field-empty">—</span>}
                </div>
                <div className="corr-field">
                    <span className="corr-field-label">ISP</span>
                    <span className="corr-field-value">{info?.isp || info?.org || '—'}</span>
                </div>
            </div>

            <div className="corr-card-meta">
                <span className="corr-meta-item">{event.operation || 'Zdarzenie sieciowe'}</span>
                <span className="corr-meta-sep">·</span>
                <span className="corr-meta-item">{serviceLabelByPort(event.remotePort)}</span>
                <span className="corr-meta-sep">·</span>
                <span className="corr-meta-item corr-meta-mono">{formatTimestampUs(event.tsUs)}</span>
            </div>

            {expanded && (
                <div className="corr-card-details">
                    <DetailItem label="ID eventu" value={event.eventId} mono />
                    <DetailItem label="Proces" value={event.processPath || event.processName || '—'} />
                    <DetailItem label="Operacja" value={event.operation || '—'} />
                    <DetailItem label="Kierunek" value={event.eventDirection || '—'} />
                    <DetailItem label="Lokalny endpoint" value={`${event.eventLocalIp || '—'}:${event.eventLocalPort ?? '—'}`} mono />
                    <DetailItem label="Zdalny endpoint" value={`${event.remoteIp || '—'}:${event.remotePort ?? '—'}`} mono />
                    <DetailItem label="Czas" value={formatTimestampUs(event.tsUs)} />
                </div>
            )}
        </div>
    );
}

function lookupIpInfo(ipData: Record<string, IpLookupData>, ip: string): IpLookupData | undefined {
    const normalized = normalizeIp(ip);
    if (!normalized) return undefined;
    return ipData[normalized] ?? ipData[normalized.toLowerCase()];
}

function normalizeIp(ip: string): string {
    return ip.trim().toLowerCase();
}

function isPublicIp(ip: string): boolean {
    if (!ip || ip === '0.0.0.0' || ip === '255.255.255.255') return false;
    if (ip.includes(':')) {
        const normalized = ip.toLowerCase();
        if (normalized === '::1') return false;
        if (normalized.startsWith('fe80:')) return false;
        if (normalized.startsWith('fc') || normalized.startsWith('fd')) return false;
        return true;
    }

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

function getFlagEmoji(countryCode: string): string {
    const codePoints = countryCode
        .toUpperCase()
        .split('')
        .map((char) => 127397 + char.charCodeAt(0));
    return String.fromCodePoint(...codePoints);
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
    if (typeof match.dstPort === 'number') {
        if (match.dstPort === 80) return 'HTTP';
        if (match.dstPort === 443) return 'HTTPS';
        if (match.dstPort === 53) return 'DNS';
        if (match.dstPort === 22) return 'SSH';
        return `Port ${match.dstPort}`;
    }
    return '-';
}

function serviceLabelByPort(port: number | null): string {
    if (typeof port !== 'number') return '-';
    if (port === 80) return 'HTTP';
    if (port === 443) return 'HTTPS';
    if (port === 53) return 'DNS';
    if (port === 22) return 'SSH';
    return `Port ${port}`;
}

function formatReasons(match: CorrelationMatch): string {
    if (!match.reasons?.length) return '-';
    return match.reasons.map((reason) => `${reason.code} (+${reason.score})`).join(', ');
}

export default CorrelationPanel;
