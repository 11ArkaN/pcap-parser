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
      <div className="drop-zone-icon" />
      <h2>Upusc plik PCAP lub kliknij aby przegladac</h2>
      <p>Obsluguje pliki .pcap, .pcapng, .cap z Wiresharka</p>
      <div className="hint">
        Plik testowy: captures/Wifi.pcapng
      </div>
      {error && (
        <p style={{ color: '#ff6b35', marginTop: '1rem', fontWeight: 500 }}>
          Blad: {error}
        </p>
      )}
    </div>
  );
}

export default DropZone;
