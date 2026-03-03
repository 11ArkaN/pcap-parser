import { contextBridge, ipcRenderer } from 'electron';

contextBridge.exposeInMainWorld('electronAPI', {
  openFileDialog: () => ipcRenderer.invoke('open-file-dialog'),
  readFile: (filePath: string) => ipcRenderer.invoke('read-file', filePath),
  parseFile: (filePath: string, maxConnections?: number) => ipcRenderer.invoke('parse-file', filePath, maxConnections),
  lookupIp: (ip: string) => ipcRenderer.invoke('lookup-ip', ip)
});
