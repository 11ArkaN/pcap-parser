import { contextBridge, ipcRenderer } from 'electron';
contextBridge.exposeInMainWorld('electronAPI', {
    openFileDialog: () => ipcRenderer.invoke('open-file-dialog'),
    openProcmonDialog: () => ipcRenderer.invoke('open-procmon-dialog'),
    readFile: (filePath) => ipcRenderer.invoke('read-file', filePath),
    parseFile: (filePath, maxConnections) => ipcRenderer.invoke('parse-file', filePath, maxConnections),
    lookupIp: (ip) => ipcRenderer.invoke('lookup-ip', ip),
    startCorrelation: (payload) => ipcRenderer.invoke('start-correlation', payload),
    getCorrelationStatus: (jobId) => ipcRenderer.invoke('get-correlation-status', jobId),
    cancelCorrelation: (jobId) => ipcRenderer.invoke('cancel-correlation', jobId),
    getCorrelationResult: (jobId) => ipcRenderer.invoke('get-correlation-result', jobId)
});
