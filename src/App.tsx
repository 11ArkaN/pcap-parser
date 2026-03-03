import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import Charts from './components/Charts';
import CorrelationPanel from './components/CorrelationPanel';
import DataTable from './components/DataTable';
import LoadingOverlay from './components/LoadingOverlay';
import { parsePcapDetailed } from './utils/pcapParser';
import { enrichIpData } from './utils/whoisApi';
import type {
  CorrelationJobStatus,
  CorrelationReportV1,
  FileInputPayload,
  IpLookupData,
  LoadingProgress,
  ParsedConnection,
  ProcmonAttachment
} from './types';

const MAX_CONNECTIONS_PER_ANALYSIS = 400_000;

interface AnalysisFileData {
  name: string;
  path?: string;
  packetCount: number;
  fileSize?: number;
  truncated?: boolean;
}

interface AnalysisSession {
  id: string;
  file: AnalysisFileData;
  connections: ParsedConnection[];
  ipData: Record<string, IpLookupData>;
  activeView: 'public' | 'local';
  activeSection: 'pcap' | 'correlation';
  procmonFiles: ProcmonAttachment[];
  correlationJob: CorrelationJobStatus | null;
  correlation: CorrelationReportV1 | null;
  warning?: string | null;
}

interface ElectronDragFile extends File {
  path?: string;
}

function App() {
  useEffect(() => {
    if (!window.electronAPI) {
      console.error('electronAPI is not available');
    }
  }, []);

  const [analyses, setAnalyses] = useState<AnalysisSession[]>([]);
  const [activeAnalysisId, setActiveAnalysisId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadingProgress, setLoadingProgress] = useState<LoadingProgress>({ current: 0, total: 0, text: '' });
  const [error, setError] = useState<string | null>(null);
  const [isWindowDragActive, setIsWindowDragActive] = useState(false);
  const dragCounterRef = useRef(0);
  const pollTimersRef = useRef<Record<string, number>>({});

  const activeAnalysis = useMemo(
    () => analyses.find((analysis) => analysis.id === activeAnalysisId) ?? null,
    [analyses, activeAnalysisId]
  );

  const stopCorrelationPolling = useCallback((analysisId: string) => {
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

  const patchAnalysis = useCallback((analysisId: string, patcher: (analysis: AnalysisSession) => AnalysisSession) => {
    setAnalyses((current) => current.map((analysis) => (analysis.id === analysisId ? patcher(analysis) : analysis)));
  }, []);

  const pollCorrelationStatus = useCallback(
    async (analysisId: string, jobId: string) => {
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
    },
    [patchAnalysis, stopCorrelationPolling]
  );

  const handleFileDrop = useCallback(
    async (fileInput: FileInputPayload) => {
      if (loading) return;

      try {
        setLoading(true);
        setError(null);

        const inputName = fileInput.fileName || 'Nieznany plik';
        setLoadingProgress({ current: 0, total: 0, text: `Parsowanie pliku ${inputName}...` });

        let connections: ParsedConnection[] = [];
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
        } else if (fileInput.buffer) {
          const parsedLocal = await parsePcapDetailed(fileInput.buffer, { maxConnections: MAX_CONNECTIONS_PER_ANALYSIS });
          connections = parsedLocal.connections;
          truncated = parsedLocal.truncated;
        } else {
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
          text: `Pobieranie danych WHOIS dla ${publicIps.length} adresow IP...`
        });

        const enriched: Record<string, IpLookupData> = {};
        for (let i = 0; i < publicIps.length; i += 1) {
          const ip = publicIps[i];
          enriched[ip] = await enrichIpData(ip);

          setLoadingProgress({
            current: i + 1,
            total: publicIps.length,
            text: `Pobieranie danych WHOIS dla ${publicIps.length} adresow IP...`
          });

          if (i < publicIps.length - 1) {
            await new Promise((resolve) => setTimeout(resolve, 100));
          }
        }

        const id = createAnalysisId();
        const warning = truncated
          ? `Analiza obcieta do ${MAX_CONNECTIONS_PER_ANALYSIS.toLocaleString()} pakietow, zeby utrzymac stabilnosc pamieci.`
          : null;

        const nextAnalysis: AnalysisSession = {
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
          activeView: 'public',
          activeSection: 'pcap',
          procmonFiles: [],
          correlationJob: null,
          correlation: null,
          warning
        };

        setAnalyses((current) => [...current, nextAnalysis]);
        setActiveAnalysisId(id);
        setLoading(false);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        setError(message);
        setLoading(false);
      }
    },
    [loading]
  );

  const processDroppedFile = useCallback(
    async (file: ElectronDragFile) => {
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
    },
    [handleFileDrop]
  );

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
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setError(message);
    }
  }, [handleFileDrop]);

  const addProcmonFiles = useCallback(async () => {
    if (!activeAnalysisId) return;
    try {
      const result = await window.electronAPI.openProcmonDialog();
      if (!result.filePaths?.length) return;

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
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, [activeAnalysisId, patchAnalysis]);

  const removeProcmonFile = useCallback(
    (filePath: string) => {
      if (!activeAnalysisId) return;
      patchAnalysis(activeAnalysisId, (analysis) => ({
        ...analysis,
        procmonFiles: analysis.procmonFiles.filter((file) => file.filePath !== filePath)
      }));
    },
    [activeAnalysisId, patchAnalysis]
  );

  const startCorrelation = useCallback(async () => {
    if (!activeAnalysis) return;
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
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, [activeAnalysis, patchAnalysis, pollCorrelationStatus, stopCorrelationPolling]);

  const cancelCorrelation = useCallback(async () => {
    if (!activeAnalysis?.correlationJob) return;
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
    const onDragEnter = (event: DragEvent) => {
      if (!containsFiles(event)) return;
      event.preventDefault();
      dragCounterRef.current += 1;
      setIsWindowDragActive(true);
    };

    const onDragOver = (event: DragEvent) => {
      if (!containsFiles(event)) return;
      event.preventDefault();
      if (event.dataTransfer) {
        event.dataTransfer.dropEffect = 'copy';
      }
      setIsWindowDragActive(true);
    };

    const onDragLeave = (event: DragEvent) => {
      if (!containsFiles(event)) return;
      event.preventDefault();
      dragCounterRef.current = Math.max(0, dragCounterRef.current - 1);
      if (dragCounterRef.current === 0) {
        setIsWindowDragActive(false);
      }
    };

    const onDrop = (event: DragEvent) => {
      if (!containsFiles(event)) return;
      event.preventDefault();
      dragCounterRef.current = 0;
      setIsWindowDragActive(false);

      const file = event.dataTransfer?.files?.[0] as ElectronDragFile | undefined;
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

  const closeAnalysis = useCallback(
    (analysisId: string) => {
      stopCorrelationPolling(analysisId);
      setAnalyses((current) => {
        const index = current.findIndex((item) => item.id === analysisId);
        if (index === -1) return current;

        const next = current.filter((item) => item.id !== analysisId);

        if (activeAnalysisId === analysisId) {
          const fallback = next[Math.max(0, index - 1)]?.id ?? next[0]?.id ?? null;
          setActiveAnalysisId(fallback);
        }

        return next;
      });
    },
    [activeAnalysisId, stopCorrelationPolling]
  );

  const setActiveDataView = useCallback(
    (view: 'public' | 'local') => {
      if (!activeAnalysisId) return;
      patchAnalysis(activeAnalysisId, (analysis) => ({ ...analysis, activeView: view }));
    },
    [activeAnalysisId, patchAnalysis]
  );

  const setActiveSection = useCallback(
    (section: 'pcap' | 'correlation') => {
      if (!activeAnalysisId) return;
      patchAnalysis(activeAnalysisId, (analysis) => ({ ...analysis, activeSection: section }));
    },
    [activeAnalysisId, patchAnalysis]
  );

  const publicConnections = useMemo(() => {
    if (!activeAnalysis) return [];
    return activeAnalysis.connections.filter((c) => isPublicIp(c.src) || isPublicIp(c.dst));
  }, [activeAnalysis]);

  const localConnections = useMemo(() => {
    if (!activeAnalysis) return [];
    return activeAnalysis.connections.filter((c) => !isPublicIp(c.src) && !isPublicIp(c.dst));
  }, [activeAnalysis]);

  const stats = useMemo(() => {
    if (!activeAnalysis) {
      return { totalPackets: 0, publicIps: 0, asns: 0, countries: 0 };
    }

    const uniquePublicIps = [
      ...new Set(
        publicConnections.flatMap((c) => {
          const ips: string[] = [];
          if (isPublicIp(c.src)) ips.push(c.src);
          if (isPublicIp(c.dst)) ips.push(c.dst);
          return ips;
        })
      )
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

  return (
    <div className="app">
      {loading && <LoadingOverlay progress={loadingProgress} />}
      {isWindowDragActive && (
        <div className="global-drop-overlay">
          <div className="global-drop-overlay-card">
            <h2>Upusc plik, aby dodac nowa analize</h2>
            <p>Akceptowane: .pcap, .pcapng, .cap, .dmp</p>
          </div>
        </div>
      )}

      <header className="header">
        <div className="header-content">
          <div className="header-title-row">
            <h1>Analizator PCAP</h1>
            <button className="btn btn-primary" onClick={openFileDialog} disabled={loading}>
              Otworz plik
            </button>
          </div>
          {activeAnalysis && (
            <div className="header-stats">
              <span>
                Plik: <strong>{activeAnalysis.file.name}</strong>
              </span>
              <span>
                Pakiety: <strong>{stats.totalPackets.toLocaleString()}</strong>
              </span>
              <span>
                IP publiczne: <strong>{stats.publicIps}</strong>
              </span>
              <span>
                ASN: <strong>{stats.asns}</strong>
              </span>
              <span>
                Kraje: <strong>{stats.countries}</strong>
              </span>
            </div>
          )}
        </div>
      </header>

      <main className="main-content">
        {!activeAnalysis ? (
          <div className="empty-state">
            <div className="empty-state-icon">PCAP</div>
            <h3>Brak aktywnych analiz</h3>
            <p>Przeciagnij plik na okno aplikacji albo uzyj przycisku "Otworz plik".</p>
            {error && <p className="error-msg">Blad: {error}</p>}
          </div>
        ) : (
          <>
            <div className="analysis-tabs-bar">
              <div className="analysis-tabs-list">
                {analyses.map((analysis) => {
                  const isActive = analysis.id === activeAnalysis.id;
                  return (
                    <div key={analysis.id} className={`analysis-tab-chip ${isActive ? 'active' : ''}`}>
                      <button className="analysis-tab-button" onClick={() => setActiveAnalysisId(analysis.id)}>
                        <span className="analysis-tab-name">{analysis.file.name}</span>
                        <span className="analysis-tab-count">{analysis.file.packetCount.toLocaleString()}</span>
                      </button>
                      <button
                        className="analysis-tab-close"
                        onClick={() => closeAnalysis(analysis.id)}
                        aria-label={`Zamknij ${analysis.file.name}`}
                        title="Zamknij karte"
                      >
                        x
                      </button>
                    </div>
                  );
                })}
              </div>
            </div>

            {activeAnalysis.warning && <div className="analysis-warning">{activeAnalysis.warning}</div>}
            {error && <div className="analysis-warning">Blad: {error}</div>}

            <div className="analysis-section-tabs">
              <button
                className={`analysis-section-tab ${activeAnalysis.activeSection === 'pcap' ? 'active' : ''}`}
                onClick={() => setActiveSection('pcap')}
              >
                Widok PCAP
              </button>
              <button
                className={`analysis-section-tab ${activeAnalysis.activeSection === 'correlation' ? 'active' : ''}`}
                onClick={() => setActiveSection('correlation')}
              >
                Korelacja
                {activeAnalysis.correlationJob?.state === 'running' && <span className="section-status">TRWA</span>}
                {activeAnalysis.correlationJob?.state === 'completed' && <span className="section-status done">GOTOWE</span>}
              </button>
            </div>

            {activeAnalysis.activeSection === 'pcap' ? (
              <>
                <Charts connections={publicConnections} ipData={activeAnalysis.ipData} />

                <div className="tabs">
                  <button
                    className={`tab ${activeAnalysis.activeView === 'public' ? 'active' : ''}`}
                    onClick={() => setActiveDataView('public')}
                  >
                    IP Publiczne
                    <span className="tab-badge">{publicConnections.length}</span>
                  </button>
                  <button
                    className={`tab ${activeAnalysis.activeView === 'local' ? 'active' : ''}`}
                    onClick={() => setActiveDataView('local')}
                  >
                    Siec lokalna
                    <span className="tab-badge">{localConnections.length}</span>
                  </button>
                </div>

                <DataTable
                  connections={activeAnalysis.activeView === 'public' ? publicConnections : localConnections}
                  ipData={activeAnalysis.ipData}
                  isPublic={activeAnalysis.activeView === 'public'}
                />
              </>
            ) : (
              <CorrelationPanel
                pcapFilePath={activeAnalysis.file.path}
                procmonFiles={activeAnalysis.procmonFiles}
                correlationJob={activeAnalysis.correlationJob}
                correlationResult={activeAnalysis.correlation}
                onAddProcmonFiles={addProcmonFiles}
                onRemoveProcmonFile={removeProcmonFile}
                onRunCorrelation={startCorrelation}
                onCancelCorrelation={cancelCorrelation}
              />
            )}
          </>
        )}
      </main>
    </div>
  );
}

function containsFiles(event: DragEvent): boolean {
  const types = event.dataTransfer?.types;
  if (!types) return false;
  return Array.from(types).includes('Files');
}

function extractFileName(filePath: string): string {
  const normalized = filePath.replace(/\\/g, '/');
  const parts = normalized.split('/');
  return parts[parts.length - 1] || filePath;
}

function createAnalysisId(): string {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) {
    return crypto.randomUUID();
  }
  return `analysis-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

function isPublicIp(ip: string): boolean {
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
