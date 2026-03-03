import React, { useState, useCallback } from 'react';

function DropZone({ onFileDrop, error }) {
  const [isDragActive, setIsDragActive] = useState(false);

  const handleDragEnter = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(true);
  }, []);

  const handleDragLeave = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(false);
  }, []);

  const handleDragOver = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
  }, []);

  const handleDrop = useCallback(async (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(false);

    const files = e.dataTransfer.files;
    if (files.length > 0) {
      await processFile(files[0]);
    }
  }, []);

  const handleClick = useCallback(async () => {
    try {
      const result = await window.electronAPI.openFileDialog();
      if (result.filePaths && result.filePaths.length > 0) {
        const fileResult = await window.electronAPI.readFile(result.filePaths[0]);
        if (fileResult.success) {
          onFileDrop(new Uint8Array(fileResult.buffer), fileResult.fileName);
        }
      }
    } catch (err) {
      console.error('Blad otwierania pliku:', err);
    }
  }, [onFileDrop]);

  const processFile = async (file) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const arrayBuffer = e.target.result;
      onFileDrop(new Uint8Array(arrayBuffer), file.name);
    };
    reader.readAsArrayBuffer(file);
  };

  return (
    <div
      className={`drop-zone ${isDragActive ? 'active' : ''}`}
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
      <h2>Upusc plik PCAP lub kliknij aby przegladac</h2>
      <p>Obsluguje pliki .pcap, .pcapng, .cap z Wiresharka</p>
      <div className="hint">captures/Wifi.pcapng</div>
      {error && (
        <p className="error-msg">Blad: {error}</p>
      )}
    </div>
  );
}

export default DropZone;
