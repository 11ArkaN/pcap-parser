import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import React, { useEffect, useMemo, useRef, useState } from 'react';
import { summarizeCorrelation } from '../utils/correlationSummary';
function CorrelationPanel({ pcapFilePath, procmonFiles, correlationJob, correlationResult, ipData, onEnsureIpMetadata, onGoToPcapIp, onAddProcmonFiles, onRemoveProcmonFile, onRunCorrelation, onCancelCorrelation }) {
    const [activeTab, setActiveTab] = useState('results');
    const [activeResultsView, setActiveResultsView] = useState('matches');
    const [expandedRows, setExpandedRows] = useState({});
    const debugListRef = useRef(null);
    const summary = useMemo(() => (correlationResult ? summarizeCorrelation(correlationResult) : null), [correlationResult]);
    const isRunning = correlationJob?.state === 'queued' || correlationJob?.state === 'running';
    const canRun = Boolean(pcapFilePath && procmonFiles.length > 0 && !isRunning);
    const debugEntries = correlationJob?.debugEntries ?? [];
    const topMatches = useMemo(() => {
        if (!correlationResult)
            return [];
        return [...correlationResult.matches].sort((a, b) => b.score - a.score).slice(0, 200);
    }, [correlationResult]);
    const topUnmatchedSessions = useMemo(() => {
        if (!correlationResult)
            return [];
        return [...correlationResult.unmatchedSessions].sort((a, b) => b.packets - a.packets).slice(0, 200);
    }, [correlationResult]);
    const topUnmatchedEvents = useMemo(() => {
        if (!correlationResult)
            return [];
        return [...correlationResult.unmatchedProcmonEvents].sort((a, b) => b.tsUs - a.tsUs).slice(0, 200);
    }, [correlationResult]);
    const missingIps = useMemo(() => {
        if (!correlationResult)
            return [];
        const pending = new Set();
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
        if (!debugListRef.current || activeTab !== 'debug')
            return;
        debugListRef.current.scrollTop = debugListRef.current.scrollHeight;
    }, [debugEntries, activeTab]);
    useEffect(() => {
        setExpandedRows({});
    }, [correlationResult?.generatedAt, activeResultsView]);
    useEffect(() => {
        if (!onEnsureIpMetadata || missingIps.length === 0)
            return;
        onEnsureIpMetadata(missingIps);
    }, [missingIps, onEnsureIpMetadata]);
    const toggleExpanded = (rowKey) => {
        setExpandedRows((current) => ({ ...current, [rowKey]: !current[rowKey] }));
    };
    return (_jsxs("section", { className: "correlation-panel fade-in", children: [_jsxs("div", { className: "correlation-panel-header", children: [_jsxs("div", { children: [_jsx("h3", { children: "Korelacja z Process Monitor" }), _jsxs("p", { children: ["Przypisz ruch sieciowy do procesow na podstawie logow ", _jsx("code", { children: ".pml" }), " z Procmon."] })] }), _jsxs("div", { className: "correlation-actions", children: [_jsx("button", { className: "btn btn-secondary", onClick: onAddProcmonFiles, children: "+ Dodaj pliki PML" }), _jsx("button", { className: "btn btn-primary", onClick: onRunCorrelation, disabled: !canRun, children: "Uruchom korelacje" }), isRunning && (_jsx("button", { className: "btn btn-secondary btn-cancel", onClick: onCancelCorrelation, children: "Anuluj" }))] })] }), !pcapFilePath && _jsx("div", { className: "analysis-warning", children: "Korelacja wymaga pliku otwartego z dysku (dialog \"Otworz plik\")." }), _jsx("div", { className: "correlation-files", children: procmonFiles.length === 0 ? (_jsx("p", { className: "correlation-muted", children: "Brak dolaczonych plikow Procmon - dodaj co najmniej jeden plik .pml." })) : (procmonFiles.map((file) => (_jsxs("div", { className: "correlation-file-chip", children: [_jsx("span", { className: "correlation-file-name", children: file.fileName }), _jsx("button", { onClick: () => onRemoveProcmonFile(file.filePath), "aria-label": `Usun ${file.fileName}`, children: "x" })] }, file.filePath)))) }), correlationJob && (_jsxs("div", { className: "correlation-job", children: [_jsxs("div", { className: "correlation-job-top", children: [_jsx("span", { className: `correlation-state correlation-${correlationJob.state}`, children: statusLabel(correlationJob.state) }), _jsx("span", { className: "correlation-stage-msg", children: userFriendlyMessage(correlationJob) }), isRunning && _jsx("span", { className: "correlation-live-dot", "aria-hidden": "true" })] }), _jsx("div", { className: "progress-bar", style: { marginTop: '0.5rem' }, children: _jsx("div", { className: "progress-fill", style: { width: `${progress}%` } }) }), isRunning && (_jsxs("p", { className: "correlation-running-hint", children: ["Etap: ", stageLabel(correlationJob.progress.stage), " - moze potrwac kilka minut dla duzych plikow."] })), correlationJob.error && _jsx("div", { className: "analysis-warning", children: correlationJob.error })] })), (correlationJob || correlationResult) && (_jsxs("div", { className: "correlation-subtabs", children: [_jsx("button", { className: `correlation-subtab ${activeTab === 'results' ? 'active' : ''}`, onClick: () => setActiveTab('results'), children: "Wyniki" }), _jsxs("button", { className: `correlation-subtab ${activeTab === 'debug' ? 'active' : ''}`, onClick: () => setActiveTab('debug'), children: ["Logi", isRunning && _jsx("span", { className: "tab-badge", children: "LIVE" })] })] })), activeTab === 'results' && (_jsx(_Fragment, { children: summary && correlationResult ? (_jsxs("div", { className: "correlation-result", children: [_jsxs("div", { className: "correlation-summary-grid", children: [_jsx(SummaryBox, { label: "Dopasowane sesje", value: summary.totalMatches.toLocaleString(), accent: "bright", active: activeResultsView === 'matches', onClick: () => setActiveResultsView('matches') }), _jsx(SummaryBox, { label: "Wysoka pewnosc", value: summary.highConfidence.toLocaleString(), accent: "emerald" }), _jsx(SummaryBox, { label: "Srednia pewnosc", value: summary.mediumConfidence.toLocaleString(), accent: "amber" }), _jsx(SummaryBox, { label: "Niska pewnosc", value: summary.lowConfidence.toLocaleString(), accent: "orange" }), _jsx(SummaryBox, { label: "Niedopasowane sesje", value: summary.unmatchedSessions.toLocaleString(), accent: "muted", active: activeResultsView === 'unmatched_sessions', onClick: () => setActiveResultsView('unmatched_sessions') }), _jsx(SummaryBox, { label: "Niedopasowane eventy", value: summary.unmatchedEvents.toLocaleString(), accent: "muted", active: activeResultsView === 'unmatched_events', onClick: () => setActiveResultsView('unmatched_events') })] }), _jsxs("div", { className: "correlation-diagnostics", children: [_jsxs("span", { children: ["Przesuniecie czasu: ", _jsx("strong", { children: formatDurationUs(correlationResult.diagnostics.timeOffsetUs) })] }), _jsxs("span", { children: ["Tryb: ", _jsx("strong", { children: parserModeLabel(correlationResult.diagnostics.parserMode) })] }), _jsxs("span", { children: ["Widok: ", _jsx("strong", { children: resultsViewLabel(activeResultsView) })] })] }), _jsxs("div", { className: "corr-cards", children: [activeResultsView === 'matches' &&
                                    topMatches.map((match) => renderMatchCard(match, ipData, expandedRows, toggleExpanded, onGoToPcapIp)), activeResultsView === 'unmatched_sessions' &&
                                    topUnmatchedSessions.map((session) => renderUnmatchedSessionCard(session, ipData, expandedRows, toggleExpanded, onGoToPcapIp)), activeResultsView === 'unmatched_events' &&
                                    topUnmatchedEvents.map((event) => renderUnmatchedEventCard(event, ipData, expandedRows, toggleExpanded, onGoToPcapIp))] }), activeResultsView === 'matches' && topMatches.length === 0 && (_jsx("p", { className: "correlation-muted", style: { marginTop: '0.75rem' }, children: "Brak dopasowan spelniajacych kryteria pewnosci." })), activeResultsView === 'unmatched_sessions' && topUnmatchedSessions.length === 0 && (_jsx("p", { className: "correlation-muted", style: { marginTop: '0.75rem' }, children: "Brak niedopasowanych sesji." })), activeResultsView === 'unmatched_events' && topUnmatchedEvents.length === 0 && (_jsx("p", { className: "correlation-muted", style: { marginTop: '0.75rem' }, children: "Brak niedopasowanych eventow." }))] })) : (_jsxs("div", { className: "correlation-empty-results", children: [_jsx("p", { children: "Brak wynikow korelacji." }), _jsx("p", { className: "correlation-muted", children: "Dodaj pliki PML i uruchom korelacje, aby zobaczyc wyniki." })] })) })), activeTab === 'debug' && (_jsxs("div", { className: "correlation-debug", children: [_jsxs("div", { className: "correlation-debug-head", children: [_jsx("span", { children: "Log zdarzen" }), _jsxs("span", { children: [debugEntries.length.toLocaleString(), " wpisow"] })] }), _jsx("div", { className: "correlation-debug-list", ref: debugListRef, children: debugEntries.length === 0 ? (_jsx("div", { className: "correlation-debug-empty", children: isRunning ? 'Oczekiwanie na pierwsze zdarzenia...' : 'Brak logow dla tego zadania.' })) : (debugEntries.map((entry, index) => (_jsxs("div", { className: `correlation-debug-row level-${entry.level}`, children: [_jsx("span", { className: "debug-ts", children: formatDebugTs(entry.ts) }), _jsx("span", { className: `debug-level level-${entry.level}`, children: debugLevelLabel(entry.level) }), _jsx("span", { className: "debug-stage", children: entry.stage ? stageLabel(entry.stage) : '' }), _jsx("span", { className: "debug-msg", children: entry.message })] }, `${entry.ts}-${index}`)))) })] }))] }));
}
function SummaryBox({ label, value, accent = 'bright', active = false, onClick }) {
    return (_jsxs("button", { type: "button", className: `correlation-summary-box accent-${accent} ${onClick ? 'clickable' : ''} ${active ? 'active' : ''}`, onClick: onClick, children: [_jsx("span", { children: label }), _jsx("strong", { children: value })] }));
}
function DetailItem({ label, value, mono = false }) {
    return (_jsxs("div", { className: "correlation-detail-item", children: [_jsx("span", { children: label }), _jsx("strong", { className: mono ? 'mono' : '', children: value })] }));
}
function userFriendlyMessage(job) {
    if (job.state === 'completed')
        return 'Korelacja zakonczona pomyslnie.';
    if (job.state === 'failed')
        return 'Korelacja zakonczyla sie bledem.';
    if (job.state === 'cancelled')
        return 'Korelacja anulowana.';
    const stage = stageLabel(job.progress.stage);
    const pct = job.progress.total > 0 ? ` (${Math.round((job.progress.current / job.progress.total) * 100)}%)` : '';
    return `${stage}${pct}`;
}
function stageLabel(stage) {
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
function statusLabel(state) {
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
function confidenceLabel(confidence) {
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
function parserModeLabel(mode) {
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
function resultsViewLabel(view) {
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
function overallProgressPercent(job) {
    const stageRanges = {
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
    if (job.state === 'completed')
        return 100;
    if (job.state === 'failed' || job.state === 'cancelled')
        return Math.max(start, 5);
    return start + span * subProgress;
}
function formatTimestampUs(value) {
    if (!Number.isFinite(value) || value <= 0)
        return '-';
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
function formatDurationUs(value) {
    const sign = value < 0 ? '-' : '';
    const abs = Math.abs(value);
    if (abs >= 1_000_000)
        return `${sign}${(abs / 1_000_000).toFixed(2)} s`;
    if (abs >= 1000)
        return `${sign}${(abs / 1000).toFixed(2)} ms`;
    return `${sign}${abs} us`;
}
function formatDebugTs(value) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime()))
        return value;
    return date.toLocaleTimeString('pl-PL', { hour12: false });
}
function debugLevelLabel(level) {
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
function formatOptionalNumber(value) {
    if (typeof value !== 'number')
        return '-';
    return value.toString();
}
function resolveDisplayIp(match, ipData) {
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
function resolveDisplayIpForUnmatchedSession(session, ipData) {
    const candidates = collectPublicIps([session.dstIp, session.srcIp]);
    for (const ip of candidates) {
        const info = lookupIpInfo(ipData, ip);
        if (info)
            return { ip, info };
    }
    return { ip: candidates[0] ?? null, info: undefined };
}
function resolveDisplayIpForUnmatchedEvent(event, ipData) {
    const candidates = collectPublicIps([event.remoteIp]);
    for (const ip of candidates) {
        const info = lookupIpInfo(ipData, ip);
        if (info)
            return { ip, info };
    }
    return { ip: candidates[0] ?? null, info: undefined };
}
function listPublicIpCandidates(match) {
    return collectPublicIps([match.dstIp, match.srcIp]);
}
function listPublicIpCandidatesGeneric(record) {
    if ('tsUs' in record)
        return collectPublicIps([record.remoteIp]);
    if ('matchedAtUs' in record)
        return collectPublicIps([record.dstIp, record.srcIp]);
    return collectPublicIps([record.dstIp, record.srcIp]);
}
function collectPublicIps(values) {
    const unique = [];
    const seen = new Set();
    for (const raw of values) {
        if (!raw || !isPublicIp(raw))
            continue;
        const normalized = normalizeIp(raw);
        if (!normalized || seen.has(normalized))
            continue;
        seen.add(normalized);
        unique.push(normalized);
    }
    return unique;
}
function renderMatchCard(match, ipData, expandedRows, toggleExpanded, onGoToPcapIp) {
    const rowKey = `match:${match.sessionId}:${match.eventId}`;
    const expanded = Boolean(expandedRows[rowKey]);
    const { ip: publicIp, info } = resolveDisplayIp(match, ipData);
    return (_jsxs("div", { className: `corr-card ${expanded ? 'expanded' : ''}`, children: [_jsxs("div", { className: "corr-card-header", children: [_jsxs("div", { className: "corr-card-process", children: [_jsx("strong", { children: match.processName || '—' }), _jsxs("span", { className: "corr-card-pid", children: ["PID ", match.pid ?? '—'] })] }), _jsxs("div", { className: "corr-card-header-right", children: [_jsx("span", { className: `confidence-badge confidence-${match.confidence}`, children: confidenceLabel(match.confidence) }), _jsx("button", { className: "corr-card-toggle", onClick: () => toggleExpanded(rowKey), children: expanded ? '▾' : '▸' })] })] }), _jsxs("div", { className: "corr-card-fields", children: [_jsxs("div", { className: "corr-field", children: [_jsx("span", { className: "corr-field-label", children: "IP" }), publicIp ? (_jsx("button", { className: "ip-address ip-address-button", onClick: () => onGoToPcapIp?.(publicIp), title: `Przejdz do ${publicIp} w widoku PCAP`, children: publicIp })) : (_jsx("span", { className: "corr-field-empty", children: "\u2014" }))] }), _jsxs("div", { className: "corr-field", children: [_jsx("span", { className: "corr-field-label", children: "ASN" }), info?.asn ? _jsx("span", { className: "asn-badge", children: info.asn }) : _jsx("span", { className: "corr-field-empty", children: "\u2014" })] }), _jsxs("div", { className: "corr-field", children: [_jsx("span", { className: "corr-field-label", children: "ISP" }), _jsx("span", { className: "corr-field-value", children: info?.isp || info?.org || '—' })] }), _jsxs("div", { className: "corr-field", children: [_jsx("span", { className: "corr-field-label", children: "Lokalizacja" }), info?.country ? (_jsxs("div", { className: "country-flag", children: [_jsx("span", { className: "flag", children: getFlagEmoji(info.country) }), _jsxs("span", { className: "country-name", children: [info.country, info.city ? `, ${info.city}` : ''] })] })) : _jsx("span", { className: "corr-field-empty", children: "\u2014" })] }), _jsxs("div", { className: "corr-field", children: [_jsx("span", { className: "corr-field-label", children: "CIDR" }), _jsx("span", { className: "cidr-block", children: info?.cidr || info?.range || '—' })] })] }), _jsxs("div", { className: "corr-card-meta", children: [_jsx("span", { className: `protocol-badge ${match.protocol.toLowerCase()}`, children: match.protocol }), _jsx("span", { className: "corr-meta-item", children: serviceLabel(match) }), _jsx("span", { className: "corr-meta-sep", children: "\u00B7" }), _jsxs("span", { className: "corr-meta-item corr-meta-mono", children: [match.packets.toLocaleString(), " pkt"] }), _jsx("span", { className: "corr-meta-sep", children: "\u00B7" }), _jsx("span", { className: "corr-meta-item corr-meta-mono", children: formatBytes(match.bytes) }), _jsx("span", { className: "corr-meta-sep", children: "\u00B7" }), _jsx("span", { className: "corr-meta-item corr-meta-mono", children: formatTimestampUs(match.firstSeenUs) })] }), expanded && (_jsxs("div", { className: "corr-card-details", children: [_jsx(DetailItem, { label: "Sciezka procesu", value: match.processPath || '—' }), _jsx(DetailItem, { label: "Linia polecen", value: match.commandLine || '—' }), _jsx(DetailItem, { label: "Uzytkownik", value: match.userName || '—' }), _jsx(DetailItem, { label: "Firma", value: match.company || '—' }), _jsx(DetailItem, { label: "PID rodzica", value: formatOptionalNumber(match.parentPid) }), _jsx(DetailItem, { label: "Integralnosc", value: match.integrityLevel || '—' }), _jsx(DetailItem, { label: "Podpis", value: match.signer || '—' }), _jsx(DetailItem, { label: "Hash", value: match.imageHash || '—', mono: true }), _jsx(DetailItem, { label: "Operacja", value: match.operation || '—' }), _jsx(DetailItem, { label: "Wynik", value: match.result || '—' }), _jsx(DetailItem, { label: "Endpoint", value: `${match.eventLocalIp || '—'}:${match.eventLocalPort ?? '—'} → ${match.eventRemoteIp || '—'}:${match.eventRemotePort ?? '—'}`, mono: true }), _jsx(DetailItem, { label: "Kierunek", value: match.eventDirection || '—' }), _jsx(DetailItem, { label: "Czas start", value: formatTimestampUs(match.firstSeenUs) }), _jsx(DetailItem, { label: "Czas koniec", value: formatTimestampUs(match.lastSeenUs) }), _jsx(DetailItem, { label: "Delta czasu", value: formatDurationUs(match.offsetUs) }), _jsx(DetailItem, { label: "Powody", value: formatReasons(match) })] }))] }, rowKey));
}
function renderUnmatchedSessionCard(session, ipData, expandedRows, toggleExpanded, onGoToPcapIp) {
    const rowKey = `unmatched-session:${session.sessionId}`;
    const expanded = Boolean(expandedRows[rowKey]);
    const { ip: publicIp, info } = resolveDisplayIpForUnmatchedSession(session, ipData);
    return (_jsxs("div", { className: `corr-card ${expanded ? 'expanded' : ''}`, children: [_jsxs("div", { className: "corr-card-header", children: [_jsxs("div", { className: "corr-card-process", children: [_jsx("strong", { children: "Sesja bez dopasowania" }), _jsxs("span", { className: "corr-card-pid", children: ["ID ", session.sessionId] })] }), _jsxs("div", { className: "corr-card-header-right", children: [_jsx("span", { className: "corr-reason-badge", children: session.reason || 'Brak powodu' }), _jsx("button", { className: "corr-card-toggle", onClick: () => toggleExpanded(rowKey), children: expanded ? '▾' : '▸' })] })] }), _jsxs("div", { className: "corr-card-fields", children: [_jsxs("div", { className: "corr-field", children: [_jsx("span", { className: "corr-field-label", children: "IP" }), publicIp ? (_jsx("button", { className: "ip-address ip-address-button", onClick: () => onGoToPcapIp?.(publicIp), title: `Przejdz do ${publicIp} w widoku PCAP`, children: publicIp })) : (_jsx("span", { className: "corr-field-empty", children: "\u2014" }))] }), _jsxs("div", { className: "corr-field", children: [_jsx("span", { className: "corr-field-label", children: "ASN" }), info?.asn ? _jsx("span", { className: "asn-badge", children: info.asn }) : _jsx("span", { className: "corr-field-empty", children: "\u2014" })] }), _jsxs("div", { className: "corr-field", children: [_jsx("span", { className: "corr-field-label", children: "ISP" }), _jsx("span", { className: "corr-field-value", children: info?.isp || info?.org || '—' })] })] }), _jsxs("div", { className: "corr-card-meta", children: [_jsx("span", { className: `protocol-badge ${session.protocol.toLowerCase()}`, children: session.protocol }), _jsx("span", { className: "corr-meta-item", children: serviceLabelByPort(session.dstPort) }), _jsx("span", { className: "corr-meta-sep", children: "\u00B7" }), _jsxs("span", { className: "corr-meta-item corr-meta-mono", children: [session.packets.toLocaleString(), " pkt"] }), _jsx("span", { className: "corr-meta-sep", children: "\u00B7" }), _jsx("span", { className: "corr-meta-item corr-meta-mono", children: formatBytes(session.bytes) })] }), expanded && (_jsxs("div", { className: "corr-card-details", children: [_jsx(DetailItem, { label: "ID sesji", value: session.sessionId, mono: true }), _jsx(DetailItem, { label: "Powod", value: session.reason || '—' }), _jsx(DetailItem, { label: "Src", value: `${session.srcIp}:${session.srcPort ?? '—'}`, mono: true }), _jsx(DetailItem, { label: "Dst", value: `${session.dstIp}:${session.dstPort ?? '—'}`, mono: true }), _jsx(DetailItem, { label: "Czas start", value: formatTimestampUs(session.firstSeenUs) }), _jsx(DetailItem, { label: "Czas koniec", value: formatTimestampUs(session.lastSeenUs) })] }))] }, rowKey));
}
function renderUnmatchedEventCard(event, ipData, expandedRows, toggleExpanded, onGoToPcapIp) {
    const rowKey = `unmatched-event:${event.eventId}`;
    const expanded = Boolean(expandedRows[rowKey]);
    const { ip: publicIp, info } = resolveDisplayIpForUnmatchedEvent(event, ipData);
    return (_jsxs("div", { className: `corr-card ${expanded ? 'expanded' : ''}`, children: [_jsxs("div", { className: "corr-card-header", children: [_jsxs("div", { className: "corr-card-process", children: [_jsx("strong", { children: event.processName || 'Nieznany proces' }), _jsxs("span", { className: "corr-card-pid", children: ["PID ", event.pid ?? '—'] })] }), _jsxs("div", { className: "corr-card-header-right", children: [_jsx("span", { className: "corr-reason-badge", children: event.reason || 'Brak powodu' }), _jsx("button", { className: "corr-card-toggle", onClick: () => toggleExpanded(rowKey), children: expanded ? '▾' : '▸' })] })] }), _jsxs("div", { className: "corr-card-fields", children: [_jsxs("div", { className: "corr-field", children: [_jsx("span", { className: "corr-field-label", children: "IP" }), publicIp ? (_jsx("button", { className: "ip-address ip-address-button", onClick: () => onGoToPcapIp?.(publicIp), title: `Przejdz do ${publicIp} w widoku PCAP`, children: publicIp })) : (_jsx("span", { className: "corr-field-empty", children: "\u2014" }))] }), _jsxs("div", { className: "corr-field", children: [_jsx("span", { className: "corr-field-label", children: "ASN" }), info?.asn ? _jsx("span", { className: "asn-badge", children: info.asn }) : _jsx("span", { className: "corr-field-empty", children: "\u2014" })] }), _jsxs("div", { className: "corr-field", children: [_jsx("span", { className: "corr-field-label", children: "ISP" }), _jsx("span", { className: "corr-field-value", children: info?.isp || info?.org || '—' })] })] }), _jsxs("div", { className: "corr-card-meta", children: [_jsx("span", { className: "corr-meta-item", children: event.operation || 'Zdarzenie sieciowe' }), _jsx("span", { className: "corr-meta-sep", children: "\u00B7" }), _jsx("span", { className: "corr-meta-item", children: serviceLabelByPort(event.remotePort) }), _jsx("span", { className: "corr-meta-sep", children: "\u00B7" }), _jsx("span", { className: "corr-meta-item corr-meta-mono", children: formatTimestampUs(event.tsUs) })] }), expanded && (_jsxs("div", { className: "corr-card-details", children: [_jsx(DetailItem, { label: "ID eventu", value: event.eventId, mono: true }), _jsx(DetailItem, { label: "Proces", value: event.processPath || event.processName || '—' }), _jsx(DetailItem, { label: "Operacja", value: event.operation || '—' }), _jsx(DetailItem, { label: "Kierunek", value: event.eventDirection || '—' }), _jsx(DetailItem, { label: "Lokalny endpoint", value: `${event.eventLocalIp || '—'}:${event.eventLocalPort ?? '—'}`, mono: true }), _jsx(DetailItem, { label: "Zdalny endpoint", value: `${event.remoteIp || '—'}:${event.remotePort ?? '—'}`, mono: true }), _jsx(DetailItem, { label: "Czas", value: formatTimestampUs(event.tsUs) })] }))] }, rowKey));
}
function lookupIpInfo(ipData, ip) {
    const normalized = normalizeIp(ip);
    if (!normalized)
        return undefined;
    return ipData[normalized] ?? ipData[normalized.toLowerCase()];
}
function normalizeIp(ip) {
    return ip.trim().toLowerCase();
}
function isPublicIp(ip) {
    if (!ip || ip === '0.0.0.0' || ip === '255.255.255.255')
        return false;
    if (ip.includes(':')) {
        const normalized = ip.toLowerCase();
        if (normalized === '::1')
            return false;
        if (normalized.startsWith('fe80:'))
            return false;
        if (normalized.startsWith('fc') || normalized.startsWith('fd'))
            return false;
        return true;
    }
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4)
        return false;
    if (parts[0] === 10)
        return false;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31)
        return false;
    if (parts[0] === 192 && parts[1] === 168)
        return false;
    if (parts[0] === 127)
        return false;
    if (parts[0] === 169 && parts[1] === 254)
        return false;
    if (parts[0] >= 224)
        return false;
    return true;
}
function getFlagEmoji(countryCode) {
    const codePoints = countryCode
        .toUpperCase()
        .split('')
        .map((char) => 127397 + char.charCodeAt(0));
    return String.fromCodePoint(...codePoints);
}
function formatBytes(bytes) {
    if (!Number.isFinite(bytes) || bytes <= 0)
        return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let size = bytes;
    let idx = 0;
    while (size >= 1024 && idx < units.length - 1) {
        size /= 1024;
        idx += 1;
    }
    return `${size.toFixed(size >= 10 ? 1 : 2)} ${units[idx]}`;
}
function serviceLabel(match) {
    if (typeof match.dstPort === 'number') {
        if (match.dstPort === 80)
            return 'HTTP';
        if (match.dstPort === 443)
            return 'HTTPS';
        if (match.dstPort === 53)
            return 'DNS';
        if (match.dstPort === 22)
            return 'SSH';
        return `Port ${match.dstPort}`;
    }
    return '-';
}
function serviceLabelByPort(port) {
    if (typeof port !== 'number')
        return '-';
    if (port === 80)
        return 'HTTP';
    if (port === 443)
        return 'HTTPS';
    if (port === 53)
        return 'DNS';
    if (port === 22)
        return 'SSH';
    return `Port ${port}`;
}
function formatReasons(match) {
    if (!match.reasons?.length)
        return '-';
    return match.reasons.map((reason) => `${reason.code} (+${reason.score})`).join(', ');
}
export default CorrelationPanel;
