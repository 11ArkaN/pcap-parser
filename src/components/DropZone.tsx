import React, { useCallback, useState } from 'react';
import type { FileInputPayload } from '../types';

type ElectronDragFile = File;

interface DropZoneProps {
  onFileDrop: (fileInput: FileInputPayload) => Promise<void> | void;
  error: string | null;
  compact?: boolean;
}

function DropZone({ onFileDrop, error, compact = false }: DropZoneProps) {
  const [isDragActive, setIsDragActive] = useState(false);

  const handleDragEnter = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(false);
  }, []);

  const handleDragOver = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
  }, []);

  const processFile = useCallback(
    async (file: ElectronDragFile) => {
      if (file.path) {
        await onFileDrop({
          filePath: file.path,
          fileName: extractFileName(file.path),
          fileSize: file.size
        });
        return;
      }

      const reader = new FileReader();
      reader.onload = (event) => {
        const arrayBuffer = event.target?.result;
        if (arrayBuffer instanceof ArrayBuffer) {
          void onFileDrop({
            fileName: file.name,
            fileSize: file.size,
            buffer: new Uint8Array(arrayBuffer)
          });
        }
      };
      reader.readAsArrayBuffer(file);
    },
    [onFileDrop]
  );

  const handleDrop = useCallback(
    async (e: React.DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      e.stopPropagation();
      setIsDragActive(false);

      const files = e.dataTransfer.files;
      if (files.length > 0) {
        await processFile(files[0] as ElectronDragFile);
      }
    },
    [processFile]
  );

  const handleClick = useCallback(async () => {
    try {
      const result = await window.electronAPI.openFileDialog();
      if (result.filePaths && result.filePaths.length > 0) {
        const selectedPath = result.filePaths[0];
        await onFileDrop({
          filePath: selectedPath,
          fileName: extractFileName(selectedPath)
        });
      }
    } catch (err) {
      console.error('Blad otwierania pliku:', err);
    }
  }, [onFileDrop]);

  return (
    <div
      className={`drop-zone ${compact ? 'drop-zone-compact' : ''} ${isDragActive ? 'active' : ''}`}
      onDragEnter={handleDragEnter}
      onDragLeave={handleDragLeave}
      onDragOver={handleDragOver}
      onDrop={handleDrop}
      onClick={handleClick}
    >
      <div className="drop-zone-icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
          <polyline points="17 8 12 3 7 8" />
          <line x1="12" y1="3" x2="12" y2="15" />
        </svg>
      </div>
      <h2>{compact ? 'Nowa analiza: upusc lub kliknij' : 'Upusc plik PCAP lub kliknij aby przegladac'}</h2>
      {!compact && <p>Obsluguje pliki .pcap, .pcapng, .cap z Wiresharka</p>}
      {!compact && <div className="hint">captures/Wifi.pcapng</div>}
      {error && <p className="error-msg">Blad: {error}</p>}
    </div>
  );
}

function extractFileName(filePath: string): string {
  const normalized = filePath.replace(/\\/g, '/');
  const parts = normalized.split('/');
  return parts[parts.length - 1] || filePath;
}

export default DropZone;
