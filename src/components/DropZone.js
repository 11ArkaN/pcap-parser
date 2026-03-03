import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import React, { useCallback, useState } from 'react';
function DropZone({ onFileDrop, error, compact = false }) {
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
    const processFile = useCallback(async (file) => {
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
    }, [onFileDrop]);
    const handleDrop = useCallback(async (e) => {
        e.preventDefault();
        e.stopPropagation();
        setIsDragActive(false);
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            await processFile(files[0]);
        }
    }, [processFile]);
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
        }
        catch (err) {
            console.error('Blad otwierania pliku:', err);
        }
    }, [onFileDrop]);
    return (_jsxs("div", { className: `drop-zone ${compact ? 'drop-zone-compact' : ''} ${isDragActive ? 'active' : ''}`, onDragEnter: handleDragEnter, onDragLeave: handleDragLeave, onDragOver: handleDragOver, onDrop: handleDrop, onClick: handleClick, children: [_jsx("div", { className: "drop-zone-icon", children: _jsxs("svg", { viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "1.5", strokeLinecap: "round", strokeLinejoin: "round", children: [_jsx("path", { d: "M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" }), _jsx("polyline", { points: "17 8 12 3 7 8" }), _jsx("line", { x1: "12", y1: "3", x2: "12", y2: "15" })] }) }), _jsx("h2", { children: compact ? 'Nowa analiza: upusc lub kliknij' : 'Upusc plik PCAP lub kliknij aby przegladac' }), !compact && _jsx("p", { children: "Obsluguje pliki .pcap, .pcapng, .cap z Wiresharka" }), !compact && _jsx("div", { className: "hint", children: "captures/Wifi.pcapng" }), error && _jsxs("p", { className: "error-msg", children: ["Blad: ", error] })] }));
}
function extractFileName(filePath) {
    const normalized = filePath.replace(/\\/g, '/');
    const parts = normalized.split('/');
    return parts[parts.length - 1] || filePath;
}
export default DropZone;
