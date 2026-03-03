import { contextBridge, ipcRenderer } from 'electron';

contextBridge.exposeInMainWorld('electronAPI', {
  openFileDialog: () => ipcRenderer.invoke('open-file-dialog'),
  openProcmonDialog: () => ipcRenderer.invoke('open-procmon-dialog'),
  readFile: (filePath: string) => ipcRenderer.invoke('read-file', filePath),
  parseFile: (filePath: string, maxConnections?: number) => ipcRenderer.invoke('parse-file', filePath, maxConnections),
  lookupIp: (ip: string) => ipcRenderer.invoke('lookup-ip', ip),
  startCorrelation: (payload: unknown) => ipcRenderer.invoke('start-correlation', payload),
  getCorrelationStatus: (jobId: string) => ipcRenderer.invoke('get-correlation-status', jobId),
  cancelCorrelation: (jobId: string) => ipcRenderer.invoke('cancel-correlation', jobId),
  getCorrelationResult: (jobId: string) => ipcRenderer.invoke('get-correlation-result', jobId)
});
