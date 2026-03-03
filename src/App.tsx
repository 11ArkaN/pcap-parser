import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import Charts from './components/Charts';
import DataTable from './components/DataTable';
import LoadingOverlay from './components/LoadingOverlay';
import { parsePcapDetailed } from './utils/pcapParser';
import { enrichIpData } from './utils/whoisApi';
import type { FileInputPayload, IpLookupData, LoadingProgress, ParsedConnection } from './types';

const MAX_CONNECTIONS_PER_ANALYSIS = 400_000;

interface AnalysisFileData {
  name: string;
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

  const activeAnalysis = useMemo(
    () => analyses.find((analysis) => analysis.id === activeAnalysisId) ?? null,
    [analyses, activeAnalysisId]
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

        if (fileInput.filePath) {
          const parsedByMain = await window.electronAPI.parseFile(fileInput.filePath, MAX_CONNECTIONS_PER_ANALYSIS);
          if (!parsedByMain.success) {
            throw new Error(parsedByMain.error || 'Nie udalo sie sparsowac pliku');
          }
          connections = parsedByMain.data.connections;
          truncated = parsedByMain.data.truncated;
          fileSize = parsedByMain.data.fileSize;
          fileName = parsedByMain.data.fileName;
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
            packetCount: connections.length,
            fileSize,
            truncated
          },
          connections,
          ipData: enriched,
          activeView: 'public',
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
    [activeAnalysisId]
  );

  const setActiveDataView = useCallback(
    (view: 'public' | 'local') => {
      if (!activeAnalysisId) return;
      setAnalyses((current) =>
        current.map((analysis) => (analysis.id === activeAnalysisId ? { ...analysis, activeView: view } : analysis))
      );
    },
    [activeAnalysisId]
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
