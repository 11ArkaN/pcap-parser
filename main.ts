import { app, BrowserWindow, dialog, ipcMain } from 'electron';
import fs from 'fs';
import http from 'http';
import https from 'https';
import path from 'path';

let mainWindow: BrowserWindow | null = null;

type HttpProtocol = 'http:' | 'https:';

interface RequestOptions extends https.RequestOptions {
  protocol?: HttpProtocol;
  timeout?: number;
}

interface RequestResult {
  data: string;
  statusCode: number;
}

interface LookupData {
  ip: string;
  asn: string | null;
  isp: string | null;
  org: string | null;
  country: string | null;
  countryName: string | null;
  city: string | null;
  region: string | null;
  cidr: string | null;
  latitude: number | null;
  longitude: number | null;
  timezone: string | null;
  asname?: string | null;
}

interface LookupSuccess {
  success: true;
  data: LookupData;
}

interface LookupFailure {
  success: false;
  error: string;
}

type LookupResponse = LookupSuccess | LookupFailure;

function makeRequest(options: RequestOptions, maxRetries = 3): Promise<RequestResult> {
  return new Promise((resolve, reject) => {
    let attempt = 0;

    const tryRequest = (): void => {
      attempt += 1;
      const client = options.protocol === 'http:' ? http : https;

      const req = client.request(options, (res) => {
        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => resolve({ data, statusCode: res.statusCode ?? 0 }));
      });

      req.on('error', (error) => {
        const message = error?.message ?? '';
        const shouldRetry =
          attempt < maxRetries &&
          (error.code === 'ECONNRESET' || error.code === 'ETIMEDOUT' || message.includes('socket hang up'));

        if (shouldRetry) {
          console.log(`[IPC] Retry ${attempt}/${maxRetries} dla ${options.hostname} po bledzie: ${message}`);
          setTimeout(tryRequest, 1000 * attempt);
          return;
        }

        reject(error);
      });

      req.on('timeout', () => {
        req.destroy();
        if (attempt < maxRetries) {
          console.log(`[IPC] Retry ${attempt}/${maxRetries} po timeout`);
          setTimeout(tryRequest, 1000 * attempt);
          return;
        }

        reject(new Error('Request timeout'));
      });

      req.end();
    };

    tryRequest();
  });
}

function createWindow(): void {
  const distDir = path.join(app.getAppPath(), 'dist');

  mainWindow = new BrowserWindow({
    width: 1600,
    height: 1000,
    minWidth: 1200,
    minHeight: 700,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(distDir, 'preload.js')
    },
    title: 'Analizator PCAP',
    show: false
  });

  mainWindow.loadFile(path.join(distDir, 'index.html'));
  mainWindow.once('ready-to-show', () => {
    mainWindow?.show();
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

ipcMain.handle('open-file-dialog', async () => {
  const targetWindow = mainWindow ?? BrowserWindow.getAllWindows()[0] ?? undefined;
  return dialog.showOpenDialog(targetWindow, {
    properties: ['openFile'],
    filters: [
      { name: 'Pliki PCAP', extensions: ['pcap', 'pcapng', 'cap', 'dmp'] },
      { name: 'Wszystkie pliki', extensions: ['*'] }
    ]
  });
});

ipcMain.handle('read-file', async (_event, filePath: string) => {
  try {
    const buffer = fs.readFileSync(filePath);
    return {
      success: true,
      buffer: Array.from(buffer),
      fileName: path.basename(filePath)
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { success: false, error: message };
  }
});

ipcMain.handle('lookup-ip', async (_event, ip: string): Promise<LookupResponse> => {
  console.log(`[IPC] lookup-ip wywolane dla: ${ip}`);

  try {
    const ripeOptions: RequestOptions = {
      protocol: 'https:',
      hostname: 'stat.ripe.net',
      path: `/data/whois/data.json?resource=${ip}`,
      method: 'GET',
      timeout: 15000,
      headers: {
        Accept: 'application/json',
        'User-Agent': 'PCAP-Analyzer/1.0'
      }
    };

    const { data: ripeData } = await makeRequest(ripeOptions, 3);
    const json = JSON.parse(ripeData) as {
      status?: string;
      data?: {
        records?: Array<Array<{ key: string; value: string }>>;
        irr_records?: Array<Array<{ key: string; value: string }>>;
      };
    };

    if (json.status === 'ok') {
      let cidr: string | null = null;
      let asn: string | null = null;
      let isp: string | null = null;
      let org: string | null = null;
      let country: string | null = null;
      let city: string | null = null;
      let region: string | null = null;

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
            } else if (record.key === 'netname' && !org) {
              org = record.value;
            }
          }
        }
      }

      if (json.data?.irr_records) {
        for (const irrSet of json.data.irr_records) {
          for (const record of irrSet) {
            if (record.key === 'origin') {
              asn = `AS${record.value}`;
            } else if (record.key === 'descr' && !isp) {
              isp = record.value;
            }
          }
        }
      }

      const rdapCidr = await lookupRdapCidr(ip);
      if (rdapCidr) {
        cidr = rdapCidr;
      }

      if (!country || !city || !cidr || country === 'EU') {
        const fallback = await lookupIpApi(ip);
        if (fallback.success) {
          if (!country || country === 'EU') {
            country = fallback.country;
          }
          if (!city) {
            city = fallback.city;
          }
          if (!region) {
            region = fallback.region;
          }
          if (!isp) {
            isp = fallback.isp;
          }
          if (!org) {
            org = fallback.org;
          }
          if (!asn) {
            asn = fallback.asn;
          }
        }
      }

      return {
        success: true,
        data: {
          ip,
          asn,
          isp: isp || org,
          org,
          country,
          countryName: null,
          city,
          region,
          cidr,
          latitude: null,
          longitude: null,
          timezone: null
        }
      };
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[IPC] RIPE API error dla ${ip}:`, message);
  }

  const fallback = await lookupIpApi(ip);
  if (fallback.success) {
    const rdapCidr = await lookupRdapCidr(ip);
    return { success: true, data: { ...fallback, cidr: rdapCidr || null } };
  }

  return { success: false, error: 'All APIs failed' };
});

async function lookupRdapCidr(ip: string): Promise<string | null> {
  try {
    const options: RequestOptions = {
      protocol: 'https:',
      hostname: 'rdap.org',
      path: `/ip/${encodeURIComponent(ip)}`,
      method: 'GET',
      timeout: 12000,
      headers: {
        Accept: 'application/json',
        'User-Agent': 'PCAP-Analyzer/1.0'
      }
    };

    const { data, statusCode } = await makeRequest(options, 2);
    if (statusCode < 200 || statusCode >= 300) {
      return null;
    }

    const json = JSON.parse(data) as {
      cidr0_cidrs?: Array<{ v4prefix?: string; v6prefix?: string; length?: number }>;
    };

    const cidrBlocks = Array.isArray(json.cidr0_cidrs) ? json.cidr0_cidrs : [];
    const cidrs = cidrBlocks
      .map((block) => {
        const prefix = block.v4prefix || block.v6prefix;
        const length = block.length;
        if (!prefix || length === undefined || length === null) {
          return null;
        }
        return `${prefix}/${length}`;
      })
      .filter((item): item is string => Boolean(item));

    return cidrs.length ? cidrs.join(', ') : null;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.warn(`[IPC] RDAP CIDR error dla ${ip}:`, message);
    return null;
  }
}

function lookupIpApi(ip: string): Promise<(LookupData & { success: true }) | LookupFailure> {
  return new Promise((resolve) => {
    const options: RequestOptions = {
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
        const json = JSON.parse(data) as {
          status: string;
          message?: string;
          countryCode?: string;
          country?: string;
          regionName?: string;
          city?: string;
          isp?: string;
          org?: string;
          as?: string;
          asname?: string;
        };

        if (json.status === 'success') {
          resolve({
            success: true,
            ip,
            country: json.countryCode ?? null,
            countryName: json.country ?? null,
            region: json.regionName ?? null,
            city: json.city ?? null,
            isp: json.isp ?? null,
            org: json.org ?? null,
            asn: json.as ?? null,
            asname: json.asname ?? null,
            cidr: null,
            latitude: null,
            longitude: null,
            timezone: null
          });
        } else {
          resolve({ success: false, error: json.message || 'API error' });
        }
      })
      .catch((err) => {
        const message = err instanceof Error ? err.message : String(err);
        resolve({ success: false, error: message });
      });
  });
}
