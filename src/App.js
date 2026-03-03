import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import Charts from './components/Charts';
import CorrelationPanel from './components/CorrelationPanel';
import DataTable from './components/DataTable';
import LoadingOverlay from './components/LoadingOverlay';
import { parsePcapDetailed } from './utils/pcapParser';
import { enrichIpData } from './utils/whoisApi';
const MAX_CONNECTIONS_PER_ANALYSIS = 400_000;
function App() {
    useEffect(() => {
        if (!window.electronAPI) {
            console.error('electronAPI is not available');
        }
        localStorage.removeItem('pcap-analyzer-session-v1');
    }, []);
    const [analyses, setAnalyses] = useState([]);
    const [activeAnalysisId, setActiveAnalysisId] = useState(null);
    const [loading, setLoading] = useState(false);
    const [loadingProgress, setLoadingProgress] = useState({ current: 0, total: 0, text: '' });
    const [error, setError] = useState(null);
    const [isWindowDragActive, setIsWindowDragActive] = useState(false);
    const dragCounterRef = useRef(0);
    const pollTimersRef = useRef({});
    const correlationLookupInFlightRef = useRef({});
    const activeAnalysis = useMemo(() => analyses.find((analysis) => analysis.id === activeAnalysisId) ?? null, [analyses, activeAnalysisId]);
    const stopCorrelationPolling = useCallback((analysisId) => {
        const timer = pollTimersRef.current[analysisId];
        if (timer !== undefined) {
            window.clearInterval(timer);
            delete pollTimersRef.current[analysisId];
        }
    }, []);
    useEffect(() => {
        return () => {
            for (const timer of Object.values(pollTimersRef.current)) {
                window.clearInterval(timer);
            }
            pollTimersRef.current = {};
        };
    }, []);
    const patchAnalysis = useCallback((analysisId, patcher) => {
        setAnalyses((current) => current.map((analysis) => (analysis.id === analysisId ? patcher(analysis) : analysis)));
    }, []);
    const buildAnalysisSession = useCallback(async (fileInput, options = {}) => {
        const inputName = fileInput.fileName || 'Nieznany plik';
        const progressPrefix = options.progressLabel ? `${options.progressLabel}: ` : '';
        setLoadingProgress({ current: 0, total: 0, text: `${progressPrefix}Parsowanie pliku ${inputName}...` });
        let connections = [];
        let truncated = false;
        let fileSize = fileInput.fileSize;
        let fileName = fileInput.fileName;
        let filePath = fileInput.filePath;
        if (fileInput.filePath) {
            const parsedByMain = await window.electronAPI.parseFile(fileInput.filePath, MAX_CONNECTIONS_PER_ANALYSIS);
            if (!parsedByMain.success) {
                throw new Error(parsedByMain.error || 'Nie udalo sie sparsowac pliku');
            }
            connections = parsedByMain.data.connections;
            truncated = parsedByMain.data.truncated;
            fileSize = parsedByMain.data.fileSize;
            fileName = parsedByMain.data.fileName;
            filePath = parsedByMain.data.filePath;
        }
        else if (fileInput.buffer) {
            const parsedLocal = await parsePcapDetailed(fileInput.buffer, { maxConnections: MAX_CONNECTIONS_PER_ANALYSIS });
            connections = parsedLocal.connections;
            truncated = parsedLocal.truncated;
        }
        else {
            throw new Error('Brak danych pliku do analizy');
        }
        if (connections.length === 0) {
            throw new Error('Nie znaleziono polaczen IP w pliku');
        }
        const uniqueIps = [...new Set(connections.flatMap((c) => [c.src, c.dst]))];
        const publicIps = uniqueIps.filter(isPublicIp);
        setLoadingProgress({
            current: 0,
            total: publicIps.length,
            text: `${progressPrefix}Pobieranie danych WHOIS dla ${publicIps.length} adresow IP...`
        });
        const enriched = {};
        const lookupDelayMs = Math.max(0, options.lookupDelayMs ?? 100);
        for (let i = 0; i < publicIps.length; i += 1) {
            const ip = publicIps[i];
            enriched[ip] = await enrichIpData(ip);
            setLoadingProgress({
                current: i + 1,
                total: publicIps.length,
                text: `${progressPrefix}Pobieranie danych WHOIS dla ${publicIps.length} adresow IP...`
            });
            if (lookupDelayMs > 0 && i < publicIps.length - 1) {
                await new Promise((resolve) => setTimeout(resolve, lookupDelayMs));
            }
        }
        const id = options.forcedId || createAnalysisId();
        const warning = truncated
            ? `Analiza obcieta do ${MAX_CONNECTIONS_PER_ANALYSIS.toLocaleString()} pakietow, zeby utrzymac stabilnosc pamieci.`
            : null;
        return {
            id,
            file: {
                name: fileName,
                path: filePath,
                packetCount: connections.length,
                fileSize,
                truncated
            },
            connections,
            ipData: enriched,
            activeView: options.activeView ?? 'public',
            activeSection: options.activeSection ?? 'pcap',
            pcapFocusRequest: null,
            procmonFiles: options.procmonFiles ?? [],
            correlationJob: null,
            correlation: null,
            warning
        };
    }, []);
    const pollCorrelationStatus = useCallback(async (analysisId, jobId) => {
        const statusResult = await window.electronAPI.getCorrelationStatus(jobId);
        if (!statusResult.success) {
            stopCorrelationPolling(analysisId);
            patchAnalysis(analysisId, (analysis) => ({
                ...analysis,
                correlationJob: analysis.correlationJob
                    ? {
                        ...analysis.correlationJob,
                        state: 'failed',
                        error: statusResult.error
                    }
                    : null
            }));
            return;
        }
        patchAnalysis(analysisId, (analysis) => ({ ...analysis, correlationJob: statusResult.status }));
        const nextState = statusResult.status.state;
        if (nextState === 'completed') {
            stopCorrelationPolling(analysisId);
            const result = await window.electronAPI.getCorrelationResult(jobId);
            if (!result.success) {
                patchAnalysis(analysisId, (analysis) => ({
                    ...analysis,
                    correlationJob: analysis.correlationJob
                        ? {
                            ...analysis.correlationJob,
                            state: 'failed',
                            error: result.error
                        }
                        : null
                }));
                return;
            }
            patchAnalysis(analysisId, (analysis) => ({
                ...analysis,
                correlation: result.data
            }));
            return;
        }
        if (nextState === 'failed' || nextState === 'cancelled') {
            stopCorrelationPolling(analysisId);
        }
    }, [patchAnalysis, stopCorrelationPolling]);
    const handleFileDrop = useCallback(async (fileInput) => {
        if (loading)
            return;
        try {
            setLoading(true);
            setError(null);
            const nextAnalysis = await buildAnalysisSession(fileInput);
            setAnalyses((current) => [...current, nextAnalysis]);
            setActiveAnalysisId(nextAnalysis.id);
        }
        catch (err) {
            const message = err instanceof Error ? err.message : String(err);
            setError(message);
        }
        finally {
            setLoading(false);
        }
    }, [buildAnalysisSession, loading]);
    const processDroppedFile = useCallback(async (file) => {
        if (file.path) {
            await handleFileDrop({
                filePath: file.path,
                fileName: extractFileName(file.path),
                fileSize: file.size
            });
            return;
        }
        const buffer = await file.arrayBuffer();
        await handleFileDrop({
            fileName: file.name,
            fileSize: file.size,
            buffer: new Uint8Array(buffer)
        });
    }, [handleFileDrop]);
    const openFileDialog = useCallback(async () => {
        try {
            const result = await window.electronAPI.openFileDialog();
            if (result.filePaths && result.filePaths.length > 0) {
                const filePath = result.filePaths[0];
                await handleFileDrop({
                    filePath,
                    fileName: extractFileName(filePath)
                });
            }
        }
        catch (err) {
            const message = err instanceof Error ? err.message : String(err);
            setError(message);
        }
    }, [handleFileDrop]);
    const addProcmonFiles = useCallback(async () => {
        if (!activeAnalysisId)
            return;
        try {
            const result = await window.electronAPI.openProcmonDialog();
            if (!result.filePaths?.length)
                return;
            patchAnalysis(activeAnalysisId, (analysis) => {
                const existing = new Set(analysis.procmonFiles.map((item) => item.filePath));
                const nextFiles = result.filePaths
                    .filter((filePath) => !existing.has(filePath))
                    .map((filePath) => ({
                    filePath,
                    fileName: extractFileName(filePath),
                    addedAt: new Date().toISOString()
                }));
                return {
                    ...analysis,
                    procmonFiles: [...analysis.procmonFiles, ...nextFiles]
                };
            });
        }
        catch (err) {
            setError(err instanceof Error ? err.message : String(err));
        }
    }, [activeAnalysisId, patchAnalysis]);
    const removeProcmonFile = useCallback((filePath) => {
        if (!activeAnalysisId)
            return;
        patchAnalysis(activeAnalysisId, (analysis) => ({
            ...analysis,
            procmonFiles: analysis.procmonFiles.filter((file) => file.filePath !== filePath)
        }));
    }, [activeAnalysisId, patchAnalysis]);
    const startCorrelation = useCallback(async () => {
        if (!activeAnalysis)
            return;
        if (!activeAnalysis.file.path) {
            setError('Korelacja wymaga pliku PCAP dostepnego pod sciezka lokalna.');
            return;
        }
        if (!activeAnalysis.procmonFiles.length) {
            setError('Dodaj co najmniej jeden plik Process Monitor (.pml).');
            return;
        }
        try {
            setError(null);
            const response = await window.electronAPI.startCorrelation({
                analysisId: activeAnalysis.id,
                pcapFilePath: activeAnalysis.file.path,
                procmonFilePaths: activeAnalysis.procmonFiles.map((file) => file.filePath),
                options: {
                    timeWindowMs: 2000,
                    maxCandidatesPerSession: 16,
                    minScore: 35
                }
            });
            if (!response.success) {
                throw new Error(response.error);
            }
            const startedAt = new Date().toISOString();
            patchAnalysis(activeAnalysis.id, (analysis) => ({
                ...analysis,
                activeSection: 'correlation',
                correlation: null,
                correlationJob: {
                    jobId: response.jobId,
                    analysisId: analysis.id,
                    state: 'queued',
                    progress: {
                        stage: 'prepare',
                        current: 0,
                        total: 1,
                        message: 'Kolejkowanie korelacji...'
                    },
                    startedAt,
                    lastEventAt: startedAt,
                    debugEntries: [
                        {
                            ts: startedAt,
                            level: 'info',
                            stage: 'prepare',
                            message: 'Zadanie korelacji utworzone po stronie aplikacji.'
                        }
                    ]
                }
            }));
            stopCorrelationPolling(activeAnalysis.id);
            pollTimersRef.current[activeAnalysis.id] = window.setInterval(() => {
                void pollCorrelationStatus(activeAnalysis.id, response.jobId);
            }, 1200);
            await pollCorrelationStatus(activeAnalysis.id, response.jobId);
        }
        catch (err) {
            setError(err instanceof Error ? err.message : String(err));
        }
    }, [activeAnalysis, patchAnalysis, pollCorrelationStatus, stopCorrelationPolling]);
    const cancelCorrelation = useCallback(async () => {
        if (!activeAnalysis?.correlationJob)
            return;
        await window.electronAPI.cancelCorrelation(activeAnalysis.correlationJob.jobId);
        stopCorrelationPolling(activeAnalysis.id);
        patchAnalysis(activeAnalysis.id, (analysis) => ({
            ...analysis,
            correlationJob: analysis.correlationJob
                ? {
                    ...analysis.correlationJob,
                    state: 'cancelled',
                    progress: {
                        ...analysis.correlationJob.progress,
                        message: 'Korelacja anulowana przez uzytkownika.'
                    }
                }
                : null
        }));
    }, [activeAnalysis, patchAnalysis, stopCorrelationPolling]);
    useEffect(() => {
        const onDragEnter = (event) => {
            if (!containsFiles(event))
                return;
            event.preventDefault();
            dragCounterRef.current += 1;
            setIsWindowDragActive(true);
        };
        const onDragOver = (event) => {
            if (!containsFiles(event))
                return;
            event.preventDefault();
            if (event.dataTransfer) {
                event.dataTransfer.dropEffect = 'copy';
            }
            setIsWindowDragActive(true);
        };
        const onDragLeave = (event) => {
            if (!containsFiles(event))
                return;
            event.preventDefault();
            dragCounterRef.current = Math.max(0, dragCounterRef.current - 1);
            if (dragCounterRef.current === 0) {
                setIsWindowDragActive(false);
            }
        };
        const onDrop = (event) => {
            if (!containsFiles(event))
                return;
            event.preventDefault();
            dragCounterRef.current = 0;
            setIsWindowDragActive(false);
            const file = event.dataTransfer?.files?.[0];
            if (file) {
                void processDroppedFile(file);
            }
        };
        window.addEventListener('dragenter', onDragEnter);
        window.addEventListener('dragover', onDragOver);
        window.addEventListener('dragleave', onDragLeave);
        window.addEventListener('drop', onDrop);
        return () => {
            window.removeEventListener('dragenter', onDragEnter);
            window.removeEventListener('dragover', onDragOver);
            window.removeEventListener('dragleave', onDragLeave);
            window.removeEventListener('drop', onDrop);
        };
    }, [processDroppedFile]);
    const closeAnalysis = useCallback((analysisId) => {
        stopCorrelationPolling(analysisId);
        delete correlationLookupInFlightRef.current[analysisId];
        setAnalyses((current) => {
            const index = current.findIndex((item) => item.id === analysisId);
            if (index === -1)
                return current;
            const next = current.filter((item) => item.id !== analysisId);
            if (activeAnalysisId === analysisId) {
                const fallback = next[Math.max(0, index - 1)]?.id ?? next[0]?.id ?? null;
                setActiveAnalysisId(fallback);
            }
            return next;
        });
    }, [activeAnalysisId, stopCorrelationPolling]);
    const setActiveDataView = useCallback((view) => {
        if (!activeAnalysisId)
            return;
        patchAnalysis(activeAnalysisId, (analysis) => ({ ...analysis, activeView: view }));
    }, [activeAnalysisId, patchAnalysis]);
    const setActiveSection = useCallback((section) => {
        if (!activeAnalysisId)
            return;
        patchAnalysis(activeAnalysisId, (analysis) => ({ ...analysis, activeSection: section }));
    }, [activeAnalysisId, patchAnalysis]);
    const goToPcapIpFromCorrelation = useCallback((ip) => {
        if (!activeAnalysisId)
            return;
        const requestId = Date.now();
        patchAnalysis(activeAnalysisId, (analysis) => ({
            ...analysis,
            activeSection: 'pcap',
            activeView: 'public',
            pcapFocusRequest: {
                ip,
                requestId
            }
        }));
    }, [activeAnalysisId, patchAnalysis]);
    const ensureCorrelationIpMetadata = useCallback(async (ips) => {
        if (!activeAnalysisId || !ips.length)
            return;
        const analysisId = activeAnalysisId;
        const targetAnalysis = analyses.find((analysis) => analysis.id === analysisId);
        if (!targetAnalysis)
            return;
        if (!correlationLookupInFlightRef.current[analysisId]) {
            correlationLookupInFlightRef.current[analysisId] = new Set();
        }
        const inFlight = correlationLookupInFlightRef.current[analysisId];
        const queue = ips
            .map((value) => value.trim())
            .filter((value, index, array) => array.indexOf(value) === index)
            .filter((value) => isPublicIp(value))
            .filter((value) => !targetAnalysis.ipData[value] && !inFlight.has(value));
        if (!queue.length)
            return;
        for (const ip of queue) {
            inFlight.add(ip);
        }
        try {
            const resolved = {};
            for (const ip of queue) {
                resolved[ip] = await enrichIpData(ip);
            }
            patchAnalysis(analysisId, (analysis) => ({
                ...analysis,
                ipData: {
                    ...analysis.ipData,
                    ...resolved
                }
            }));
        }
        finally {
            for (const ip of queue) {
                inFlight.delete(ip);
            }
        }
    }, [activeAnalysisId, analyses, patchAnalysis]);
    const publicConnections = useMemo(() => {
        if (!activeAnalysis)
            return [];
        return activeAnalysis.connections.filter((c) => isPublicIp(c.src) || isPublicIp(c.dst));
    }, [activeAnalysis]);
    const localConnections = useMemo(() => {
        if (!activeAnalysis)
            return [];
        return activeAnalysis.connections.filter((c) => !isPublicIp(c.src) && !isPublicIp(c.dst));
    }, [activeAnalysis]);
    const stats = useMemo(() => {
        if (!activeAnalysis) {
            return { totalPackets: 0, publicIps: 0, asns: 0, countries: 0 };
        }
        const uniquePublicIps = [
            ...new Set(publicConnections.flatMap((c) => {
                const ips = [];
                if (isPublicIp(c.src))
                    ips.push(c.src);
                if (isPublicIp(c.dst))
                    ips.push(c.dst);
                return ips;
            }))
        ];
        const uniqueAsns = [...new Set(Object.values(activeAnalysis.ipData).map((d) => d.asn).filter(Boolean))];
        const countries = [...new Set(Object.values(activeAnalysis.ipData).map((d) => d.country).filter(Boolean))];
        return {
            totalPackets: activeAnalysis.file.packetCount,
            publicIps: uniquePublicIps.length,
            asns: uniqueAsns.length,
            countries: countries.length
        };
    }, [activeAnalysis, publicConnections]);
    return (_jsxs("div", { className: "app", children: [loading && _jsx(LoadingOverlay, { progress: loadingProgress }), isWindowDragActive && (_jsx("div", { className: "global-drop-overlay", children: _jsxs("div", { className: "global-drop-overlay-card", children: [_jsx("h2", { children: "Upusc plik, aby dodac nowa analize" }), _jsx("p", { children: "Akceptowane: .pcap, .pcapng, .cap, .dmp" })] }) })), _jsx("header", { className: "header", children: _jsxs("div", { className: "header-content", children: [_jsxs("div", { className: "header-title-row", children: [_jsx("h1", { children: "Analizator PCAP" }), _jsx("button", { className: "btn btn-primary", onClick: openFileDialog, disabled: loading, children: "Otworz plik" })] }), activeAnalysis && (_jsxs("div", { className: "header-stats", children: [_jsxs("span", { children: ["Plik: ", _jsx("strong", { children: activeAnalysis.file.name })] }), _jsxs("span", { children: ["Pakiety: ", _jsx("strong", { children: stats.totalPackets.toLocaleString() })] }), _jsxs("span", { children: ["IP publiczne: ", _jsx("strong", { children: stats.publicIps })] }), _jsxs("span", { children: ["ASN: ", _jsx("strong", { children: stats.asns })] }), _jsxs("span", { children: ["Kraje: ", _jsx("strong", { children: stats.countries })] })] }))] }) }), _jsx("main", { className: "main-content", children: !activeAnalysis ? (_jsxs("div", { className: "empty-state", children: [_jsx("div", { className: "empty-state-icon", children: "PCAP" }), _jsx("h3", { children: "Brak aktywnych analiz" }), _jsx("p", { children: "Przeciagnij plik na okno aplikacji albo uzyj przycisku \"Otworz plik\"." }), error && _jsxs("p", { className: "error-msg", children: ["Blad: ", error] })] })) : (_jsxs(_Fragment, { children: [_jsx("div", { className: "analysis-tabs-bar", children: _jsx("div", { className: "analysis-tabs-list", children: analyses.map((analysis) => {
                                    const isActive = analysis.id === activeAnalysis.id;
                                    return (_jsxs("div", { className: `analysis-tab-chip ${isActive ? 'active' : ''}`, children: [_jsxs("button", { className: "analysis-tab-button", onClick: () => setActiveAnalysisId(analysis.id), children: [_jsx("span", { className: "analysis-tab-name", children: analysis.file.name }), _jsx("span", { className: "analysis-tab-count", children: analysis.file.packetCount.toLocaleString() })] }), _jsx("button", { className: "analysis-tab-close", onClick: () => closeAnalysis(analysis.id), "aria-label": `Zamknij ${analysis.file.name}`, title: "Zamknij karte", children: "x" })] }, analysis.id));
                                }) }) }), activeAnalysis.warning && _jsx("div", { className: "analysis-warning", children: activeAnalysis.warning }), error && _jsxs("div", { className: "analysis-warning", children: ["Blad: ", error] }), _jsxs("div", { className: "analysis-section-tabs", children: [_jsx("button", { className: `analysis-section-tab ${activeAnalysis.activeSection === 'pcap' ? 'active' : ''}`, onClick: () => setActiveSection('pcap'), children: "Widok PCAP" }), _jsxs("button", { className: `analysis-section-tab ${activeAnalysis.activeSection === 'correlation' ? 'active' : ''}`, onClick: () => setActiveSection('correlation'), children: ["Korelacja", activeAnalysis.correlationJob?.state === 'running' && _jsx("span", { className: "section-status", children: "TRWA" }), activeAnalysis.correlationJob?.state === 'completed' && _jsx("span", { className: "section-status done", children: "GOTOWE" })] })] }), activeAnalysis.activeSection === 'pcap' ? (_jsxs(_Fragment, { children: [_jsx(Charts, { connections: publicConnections, ipData: activeAnalysis.ipData }), _jsxs("div", { className: "tabs", children: [_jsxs("button", { className: `tab ${activeAnalysis.activeView === 'public' ? 'active' : ''}`, onClick: () => setActiveDataView('public'), children: ["IP Publiczne", _jsx("span", { className: "tab-badge", children: publicConnections.length })] }), _jsxs("button", { className: `tab ${activeAnalysis.activeView === 'local' ? 'active' : ''}`, onClick: () => setActiveDataView('local'), children: ["Siec lokalna", _jsx("span", { className: "tab-badge", children: localConnections.length })] })] }), _jsx(DataTable, { connections: activeAnalysis.activeView === 'public' ? publicConnections : localConnections, ipData: activeAnalysis.ipData, isPublic: activeAnalysis.activeView === 'public', focusRequest: activeAnalysis.pcapFocusRequest })] })) : (_jsx(CorrelationPanel, { pcapFilePath: activeAnalysis.file.path, procmonFiles: activeAnalysis.procmonFiles, correlationJob: activeAnalysis.correlationJob, correlationResult: activeAnalysis.correlation, ipData: activeAnalysis.ipData, onEnsureIpMetadata: ensureCorrelationIpMetadata, onGoToPcapIp: goToPcapIpFromCorrelation, onAddProcmonFiles: addProcmonFiles, onRemoveProcmonFile: removeProcmonFile, onRunCorrelation: startCorrelation, onCancelCorrelation: cancelCorrelation }))] })) })] }));
}
function containsFiles(event) {
    const types = event.dataTransfer?.types;
    if (!types)
        return false;
    return Array.from(types).includes('Files');
}
function extractFileName(filePath) {
    const normalized = filePath.replace(/\\/g, '/');
    const parts = normalized.split('/');
    return parts[parts.length - 1] || filePath;
}
function createAnalysisId() {
    if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) {
        return crypto.randomUUID();
    }
    return `analysis-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}
function isPublicIp(ip) {
    if (!ip || ip === '0.0.0.0' || ip === '255.255.255.255')
        return false;
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
export default App;
