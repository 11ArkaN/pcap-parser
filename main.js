const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const https = require('https');
const http = require('http');

let mainWindow;

// Helper function to make HTTP/HTTPS request with retry logic
function makeRequest(options, maxRetries = 3) {
  return new Promise((resolve, reject) => {
    let attempt = 0;
    
    const tryRequest = () => {
      attempt++;
      
      // Wybierz modul w zaleznosci od protokolu
      const client = options.protocol === 'http:' ? http : https;
      
      const req = client.request(options, (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => resolve({ data, statusCode: res.statusCode }));
      });
      
      req.on('error', (error) => {
        if (attempt < maxRetries && (error.code === 'ECONNRESET' || error.code === 'ETIMEDOUT' || error.message.includes('socket hang up'))) {
          console.log(`[IPC] Retry ${attempt}/${maxRetries} dla ${options.hostname} po bledzie: ${error.message}`);
          setTimeout(tryRequest, 1000 * attempt);
        } else {
          reject(error);
        }
      });
      
      req.on('timeout', () => {
        req.destroy();
        if (attempt < maxRetries) {
          console.log(`[IPC] Retry ${attempt}/${maxRetries} po timeout`);
          setTimeout(tryRequest, 1000 * attempt);
        } else {
          reject(new Error('Request timeout'));
        }
      });
      
      req.end();
    };
    
    tryRequest();
  });
}

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

// IP Lookup API handler (bypasses CORS) - używa RIPE Stat API z fallbackiem do ip-api.com
ipcMain.handle('lookup-ip', async (event, ip) => {
  console.log(`[IPC] lookup-ip wywolane dla: ${ip}`);
  
  try {
    // Próbuj RIPE Stat API z retry logic
    const ripeOptions = {
      hostname: 'stat.ripe.net',
      path: `/data/whois/data.json?resource=${ip}`,
      method: 'GET',
      timeout: 15000,
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'PCAP-Analyzer/1.0'
      }
    };
    
    const { data: ripeData } = await makeRequest(ripeOptions, 3);
    const json = JSON.parse(ripeData);
    console.log(`[IPC] Odpowiedz RIPE API dla ${ip}:`, json.status);
    
    if (json.status === 'ok') {
      // Parsowanie danych WHOIS z RIPE
      let cidr = null;
      let asn = null;
      let isp = null;
      let org = null;
      let country = null;
      let city = null;
      let region = null;
      
      // Szukamy CIDR w records (może być jako CIDR, inetnum lub NetRange)
      if (json.data?.records) {
        for (const recordSet of json.data.records) {
          for (const record of recordSet) {
            if (record.key === 'CIDR' || record.key === 'inetnum' || record.key === 'NetRange') {
              cidr = record.value;
            } else if (record.key === 'OrgName' || record.key === 'Organization' || record.key === 'org') {
              org = record.value;
            } else if (record.key === 'City') {
              city = record.value;
            } else if (record.key === 'StateProv' || record.key === 'region' || record.key === 'State') {
              region = record.value;
            } else if (record.key === 'Country') {
              country = record.value;
            } else if (record.key === 'netname') {
              // Dodatkowe info
              if (!org) org = record.value;
            }
          }
        }
      }
      
      // Szukamy ASN w irr_records
      if (json.data?.irr_records) {
        for (const irrSet of json.data.irr_records) {
          for (const record of irrSet) {
            if (record.key === 'origin') {
              asn = `AS${record.value}`;
            } else if (record.key === 'descr') {
              if (!isp) isp = record.value;
            }
          }
        }
      }
      // Jeśli brak kraju, miasta, lub CIDR - pobierz z ip-api.com (lepsza geolokalizacja)
      // CIDR pobieramy z RDAP, zeby byl zgodny z publicznymi wynikami WHOIS.
      const rdapCidr = await lookupRdapCidr(ip);
      if (rdapCidr) {
        cidr = rdapCidr;
      }

      console.log(`[IPC] Dane przed fallbackiem dla ${ip}: country=${country}, city=${city}, cidr=${cidr}`);
      if (!country || !city || !cidr || country === 'EU') {
        console.log(`[IPC] Brak danych dla ${ip} (country: ${country}, city: ${city}), uzywam fallbacku ip-api.com`);
        const fallback = await lookupIpApi(ip);
        console.log(`[IPC] Fallback dla ${ip} zwraca:`, fallback);
        if (fallback.success) {
          // ip-api.com zazwyczaj ma lepsze dane geolokalizacyjne
          if (!country || country === 'EU') {
            console.log(`[IPC] Aktualizuje country dla ${ip}: ${country} -> ${fallback.country}`);
            country = fallback.country;
          }
          if (!city) {
            console.log(`[IPC] Aktualizuje city dla ${ip}: ${city} -> ${fallback.city}`);
            city = fallback.city;
          }
          if (!region) region = fallback.region;
          if (!isp) isp = fallback.isp;
          if (!org) org = fallback.org;
          if (!asn) asn = fallback.asn;
          // CIDR zostawiamy z RIPE (bardziej szczegółowe)
        }
      }
      console.log(`[IPC] Dane po fallbacku dla ${ip}: country=${country}, city=${city}`);
      
      return {
        success: true,
        data: {
          ip: ip,
          asn: asn,
          isp: isp || org,
          org: org,
          country: country,
          countryName: null,
          city: city,
          region: region,
          cidr: cidr,
          latitude: null,
          longitude: null,
          timezone: null
        }
      };
    }
  } catch (error) {
    console.error(`[IPC] RIPE API error dla ${ip}:`, error.message);
  }
  
  // Fallback do ip-api.com
  console.log(`[IPC] Uzywam ip-api.com dla ${ip}`);
  const fallback = await lookupIpApi(ip);
  
  if (fallback.success) {
    const rdapCidr = await lookupRdapCidr(ip);
    return { success: true, data: { ...fallback, cidr: rdapCidr || null } };
  }
  
  return { success: false, error: 'All APIs failed' };
});

// RDAP lookup dla CIDR (niezalezny od IRR route)
async function lookupRdapCidr(ip) {
  try {
    const options = {
      protocol: 'https:',
      hostname: 'rdap.org',
      path: `/ip/${encodeURIComponent(ip)}`,
      method: 'GET',
      timeout: 12000,
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'PCAP-Analyzer/1.0'
      }
    };

    const { data, statusCode } = await makeRequest(options, 2);
    if (statusCode < 200 || statusCode >= 300) {
      return null;
    }

    const json = JSON.parse(data);
    const cidrBlocks = Array.isArray(json?.cidr0_cidrs) ? json.cidr0_cidrs : [];
    const cidrs = cidrBlocks
      .map((block) => {
        const prefix = block?.v4prefix || block?.v6prefix;
        const length = block?.length;
        if (!prefix || length === undefined || length === null) {
          return null;
        }
        return `${prefix}/${length}`;
      })
      .filter(Boolean);

    return cidrs.length ? cidrs.join(', ') : null;
  } catch (error) {
    console.warn(`[IPC] RDAP CIDR error dla ${ip}:`, error.message);
    return null;
  }
}

// Funkcja pomocnicza do pobierania danych z ip-api.com jako fallback
function lookupIpApi(ip) {
  return new Promise((resolve) => {
    const options = {
      protocol: 'http:',
      hostname: 'ip-api.com',
      path: `/json/${ip}?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query`,
      method: 'GET',
      timeout: 10000,
      headers: {
        'User-Agent': 'PCAP-Analyzer/1.0'
      }
    };

    makeRequest(options, 2)
      .then(({ data }) => {
        console.log(`[IPC] ip-api.com odpowiedz dla ${ip}:`, data.substring(0, 200));
        const json = JSON.parse(data);
        if (json.status === 'success') {
          resolve({
            success: true,
            country: json.countryCode,
            countryName: json.country,
            region: json.regionName,
            city: json.city,
            isp: json.isp,
            org: json.org,
            asn: json.as,
            asname: json.asname
          });
        } else {
          console.log(`[IPC] ip-api.com zwrocil status:`, json.status);
          resolve({ success: false, error: json.message || 'API error' });
        }
      })
      .catch((err) => {
        console.error(`[IPC] ip-api.com blad dla ${ip}:`, err.message);
        resolve({ success: false, error: err.message });
      });
  });
}
