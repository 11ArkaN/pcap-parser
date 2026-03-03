const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const https = require('https');

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1600,
    height: 1000,
    minWidth: 1200,
    minHeight: 700,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js')
    },
    title: 'Analizator PCAP',
    show: false
  });

  mainWindow.loadFile('dist/index.html');
  
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});

// IPC handlers
ipcMain.handle('open-file-dialog', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openFile'],
    filters: [
      { name: 'Pliki PCAP', extensions: ['pcap', 'pcapng', 'cap', 'dmp'] },
      { name: 'Wszystkie pliki', extensions: ['*'] }
    ]
  });
  return result;
});

ipcMain.handle('read-file', async (event, filePath) => {
  try {
    const buffer = fs.readFileSync(filePath);
    return { 
      success: true, 
      buffer: Array.from(buffer),
      fileName: path.basename(filePath)
    };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

// IP Lookup API handler (bypasses CORS)
ipcMain.handle('lookup-ip', async (event, ip) => {
  console.log(`[IPC] lookup-ip wywolane dla: ${ip}`);
  return new Promise((resolve) => {
    const options = {
      hostname: 'ipwho.is',
      path: `/${ip}`,
      method: 'GET',
      timeout: 10000
    };

    const req = https.request(options, (res) => {
      let data = '';
      
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          console.log(`[IPC] Odpowiedz API dla ${ip}:`, json.success ? 'sukces' : 'blad');
          resolve({
            success: json.success,
            data: {
              ip: ip,
              asn: json.connection?.asn ? `AS${json.connection.asn}` : null,
              isp: json.connection?.isp || null,
              org: json.connection?.org || null,
              country: json.country_code || null,
              countryName: json.country || null,
              city: json.city || null,
              region: json.region || null,
              cidr: json.connection?.route || null,
              latitude: json.latitude,
              longitude: json.longitude,
              timezone: json.timezone?.id || null
            }
          });
        } catch (e) {
          console.error(`[IPC] Blad parsowania odpowiedzi dla ${ip}:`, e);
          resolve({ success: false, error: 'Failed to parse response' });
        }
      });
    });

    req.on('error', (error) => {
      console.error('API Error:', error);
      resolve({ success: false, error: error.message });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({ success: false, error: 'Request timeout' });
    });

    req.end();
  });
});
