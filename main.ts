import { app, BrowserWindow, dialog, ipcMain } from 'electron';
import { execFile } from 'child_process';
import fs from 'fs';
import http from 'http';
import https from 'https';
import os from 'os';
import path from 'path';
import { CorrelationJobManager } from './src/main/correlationJobManager';
import { parsePcapDetailed } from './src/utils/pcapParser';
import { parsePcapStreamCatalog, readStreamPayloadFromBuffer } from './src/utils/pcapStreams';
import type { CorrelationRequest, HostNetworkAdapterInfo, HostNetworkInfo, ParsedConnection } from './src/types';

let mainWindow: BrowserWindow | null = null;
const correlationJobs = new CorrelationJobManager();

const DEFAULT_MAX_CONNECTIONS = 400_000;
const DEFAULT_MAX_STREAM_PACKETS = 400_000;
const MAX_PCAP_CACHE_ENTRIES = 3;
const pcapBufferCache = new Map<string, Uint8Array>();
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

type ParseFileResponse =
  | {
    success: true;
    data: {
      filePath: string;
      fileName: string;
      fileSize: number;
      connections: ParsedConnection[];
      truncated: boolean;
    };
  }
  | {
    success: false;
    error: string;
  };

type HostNetworkInfoResponse =
  | {
    success: true;
    data: HostNetworkInfo;
  }
  | {
    success: false;
    error: string;
  };

function normalizeCacheKey(filePath: string): string {
  return path.resolve(filePath).toLowerCase();
}

function readPcapBufferCached(filePath: string): Uint8Array {
  const key = normalizeCacheKey(filePath);
  const existing = pcapBufferCache.get(key);
  if (existing) {
    pcapBufferCache.delete(key);
    pcapBufferCache.set(key, existing);
    return existing;
  }

  const next = fs.readFileSync(filePath);
  pcapBufferCache.set(key, next);
  while (pcapBufferCache.size > MAX_PCAP_CACHE_ENTRIES) {
    const oldestKey = pcapBufferCache.keys().next().value;
    if (!oldestKey) break;
    pcapBufferCache.delete(oldestKey);
  }
  return next;
}

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
        const networkError = error as NodeJS.ErrnoException;
        const message = error?.message ?? '';
        const shouldRetry =
          attempt < maxRetries &&
          (networkError.code === 'ECONNRESET' || networkError.code === 'ETIMEDOUT' || message.includes('socket hang up'));

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
    correlationJobs.dispose();
    app.quit();
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});

app.on('before-quit', () => {
  correlationJobs.dispose();
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

ipcMain.handle('open-procmon-dialog', async () => {
  const targetWindow = mainWindow ?? BrowserWindow.getAllWindows()[0] ?? undefined;
  return dialog.showOpenDialog(targetWindow, {
    properties: ['openFile', 'multiSelections'],
    filters: [
      { name: 'Pliki Process Monitor', extensions: ['pml'] },
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

ipcMain.handle('parse-file', async (_event, filePath: string, maxConnections = DEFAULT_MAX_CONNECTIONS): Promise<ParseFileResponse> => {
  try {
    const fileStat = fs.statSync(filePath);
    const raw = readPcapBufferCached(filePath);
    const { connections, truncated } = await parsePcapDetailed(raw, { maxConnections });

    return {
      success: true,
      data: {
        filePath,
        fileName: path.basename(filePath),
        fileSize: fileStat.size,
        connections,
        truncated
      }
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { success: false, error: message };
  }
});

ipcMain.handle('parse-stream-catalog', async (_event, filePath: string, maxPackets = DEFAULT_MAX_STREAM_PACKETS) => {
  try {
    const fileStat = fs.statSync(filePath);
    const raw = readPcapBufferCached(filePath);
    const catalog = await parsePcapStreamCatalog(raw, { maxPackets });

    return {
      success: true,
      data: {
        filePath,
        fileName: path.basename(filePath),
        fileSize: fileStat.size,
        catalog
      }
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { success: false, error: message };
  }
});

ipcMain.handle(
  'get-stream-packet-payload',
  async (
    _event,
    payload: { filePath?: string; payloadRef?: { fileOffset?: number; capturedLength?: number }; maxBytes?: number }
  ) => {
    try {
      if (!payload?.filePath || !payload.payloadRef) {
        return { success: false, error: 'Brak danych do odczytu payloadu.' };
      }

      const raw = readPcapBufferCached(payload.filePath);
      const payloadRef = {
        fileOffset: Number(payload.payloadRef.fileOffset ?? 0),
        capturedLength: Number(payload.payloadRef.capturedLength ?? 0)
      };
      const data = readStreamPayloadFromBuffer(raw, payloadRef, payload.maxBytes);
      return { success: true, data };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return { success: false, error: message };
    }
  }
);

ipcMain.handle('get-host-network-info', async (): Promise<HostNetworkInfoResponse> => {
  try {
    const data = await collectHostNetworkInfo();
    return { success: true, data };
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

ipcMain.handle('start-correlation', async (_event, request: CorrelationRequest) => {
  const started = correlationJobs.startJob(request);
  if (!started.success) {
    const errorMessage = 'error' in started ? started.error : 'Nie udalo sie uruchomic korelacji.';
    return { success: false, error: errorMessage };
  }

  return { success: true, jobId: started.jobId };
});

ipcMain.handle('get-correlation-status', async (_event, jobId: string) => {
  const status = correlationJobs.getStatus(jobId);
  if (!status) {
    return { success: false, error: 'Nie znaleziono zadania korelacji.' };
  }

  return { success: true, status };
});

ipcMain.handle('cancel-correlation', async (_event, jobId: string) => {
  return correlationJobs.cancelJob(jobId);
});

ipcMain.handle('get-correlation-result', async (_event, jobId: string) => {
  const result = correlationJobs.getResult(jobId);
  if (!result) {
    return { success: false, error: 'Raport korelacji nie jest jeszcze dostepny.' };
  }

  return { success: true, data: result };
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

async function collectHostNetworkInfo(): Promise<HostNetworkInfo> {
  const baseAdapters = collectAdaptersFromOs();
  const windowsAdapters = process.platform === 'win32' ? await collectWindowsNetworkAdapters() : [];
  const windowsOsName = process.platform === 'win32' ? await collectWindowsOsName() : null;
  const adapters = mergeAdapterData(baseAdapters, windowsAdapters);
  const activeAdapter = pickActiveAdapter(adapters);
  const localIpv4 = uniqueStrings(adapters.flatMap((adapter) => adapter.ipv4));
  const localIpv6 = uniqueStrings(adapters.flatMap((adapter) => adapter.ipv6));
  const dnsServers = uniqueStrings(adapters.flatMap((adapter) => adapter.dnsServers));
  const publicIp = await lookupPublicIpAddress();

  return {
    collectedAt: new Date().toISOString(),
    hostName: os.hostname(),
    osName: windowsOsName,
    osPlatform: os.platform(),
    osRelease: os.release(),
    activeAdapter,
    adapters,
    localIpv4,
    localIpv6,
    dnsServers,
    defaultGateway: activeAdapter?.defaultGateway ?? null,
    gatewayMacAddress: activeAdapter?.gatewayMacAddress ?? null,
    publicIp,
    natStatus: determineNatStatus(activeAdapter, publicIp)
  };
}

async function collectWindowsOsName(): Promise<string | null> {
  const script = [
    "$computerInfo = Get-ComputerInfo -Property WindowsProductName,OsName -ErrorAction SilentlyContinue",
    "$cv = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' -ErrorAction SilentlyContinue",
    "$caption = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption",
    "$candidates = @(",
    "  $computerInfo.WindowsProductName,",
    "  $cv.ProductName,",
    "  $computerInfo.OsName,",
    "  $caption",
    ") | Where-Object { $_ -and $_.ToString().Trim() }",
    "$selected = $candidates | Select-Object -First 1",
    "if (-not $selected) { return }",
    "$selected.ToString().Trim() -replace '^Microsoft\\s+', ''"
  ].join('\n');

  try {
    const raw = await runPowerShell(script);
    return raw.trim() || null;
  } catch {
    return null;
  }
}

function collectAdaptersFromOs(): HostNetworkAdapterInfo[] {
  const interfaces = os.networkInterfaces();
  const adapters: HostNetworkAdapterInfo[] = [];

  for (const [name, entries] of Object.entries(interfaces)) {
    if (!entries?.length) continue;
    const ipv4 = uniqueStrings(
      entries
        .filter((entry) => entry.family === 'IPv4' && !entry.internal)
        .map((entry) => entry.address)
    );
    const ipv6 = uniqueStrings(
      entries
        .filter((entry) => entry.family === 'IPv6' && !entry.internal)
        .map((entry) => entry.address)
    );
    const macAddress = normalizeMac(entries.find((entry) => entry.mac && entry.mac !== '00:00:00:00:00:00')?.mac ?? null);

    if (!ipv4.length && !ipv6.length && !macAddress) continue;

    adapters.push({
      name,
      description: null,
      macAddress,
      ipv4,
      ipv6,
      dnsServers: [],
      defaultGateway: null,
      gatewayMacAddress: null
    });
  }

  return adapters;
}

async function collectWindowsNetworkAdapters(): Promise<Array<Partial<HostNetworkAdapterInfo> & { name: string }>> {
  const script = [
    "$configs = Get-NetIPConfiguration | Where-Object { $_.NetAdapter.Status -eq 'Up' -and ($_.IPv4Address -or $_.IPv6Address) }",
    "$rows = foreach ($cfg in $configs) {",
    "  $gateway = $null",
    "  if ($cfg.IPv4DefaultGateway) { $gateway = $cfg.IPv4DefaultGateway.NextHop }",
    "  $neighbor = $null",
    "  if ($gateway) { $neighbor = Get-NetNeighbor -IPAddress $gateway -ErrorAction SilentlyContinue | Select-Object -First 1 }",
    "  [pscustomobject]@{",
    "    name = $cfg.InterfaceAlias",
    "    description = $cfg.InterfaceDescription",
    "    macAddress = $cfg.NetAdapter.MacAddress",
    "    ipv4 = @($cfg.IPv4Address | ForEach-Object { $_.IPAddress })",
    "    ipv6 = @($cfg.IPv6Address | ForEach-Object { $_.IPAddress })",
    "    dnsServers = @($cfg.DNSServer.ServerAddresses)",
    "    defaultGateway = $gateway",
    "    gatewayMacAddress = if ($neighbor) { $neighbor.LinkLayerAddress } else { $null }",
    "  }",
    "}",
    "$rows | ConvertTo-Json -Depth 4 -Compress"
  ].join('\n');

  try {
    const raw = await runPowerShell(script);
    if (!raw.trim()) return [];
    const parsed = JSON.parse(raw) as Record<string, unknown> | Array<Record<string, unknown>>;
    const rows = Array.isArray(parsed) ? parsed : [parsed];
    return rows.map((item) => ({
      name: String(item.name ?? ''),
      description: item.description ? String(item.description) : null,
      macAddress: normalizeMac(item.macAddress ? String(item.macAddress) : null),
      ipv4: toStringArray(item.ipv4),
      ipv6: toStringArray(item.ipv6),
      dnsServers: toStringArray(item.dnsServers),
      defaultGateway: item.defaultGateway ? String(item.defaultGateway) : null,
      gatewayMacAddress: normalizeMac(item.gatewayMacAddress ? String(item.gatewayMacAddress) : null)
    }));
  } catch {
    return [];
  }
}

function mergeAdapterData(
  baseAdapters: HostNetworkAdapterInfo[],
  windowsAdapters: Array<Partial<HostNetworkAdapterInfo> & { name: string }>
): HostNetworkAdapterInfo[] {
  const merged = new Map<string, HostNetworkAdapterInfo>();

  for (const adapter of baseAdapters) {
    merged.set(adapter.name.toLowerCase(), { ...adapter });
  }

  for (const adapter of windowsAdapters) {
    const key = adapter.name.toLowerCase();
    const existing = merged.get(key);
    if (!existing) {
      merged.set(key, {
        name: adapter.name,
        description: adapter.description ?? null,
        macAddress: adapter.macAddress ?? null,
        ipv4: uniqueStrings(adapter.ipv4 ?? []),
        ipv6: uniqueStrings(adapter.ipv6 ?? []),
        dnsServers: uniqueStrings(adapter.dnsServers ?? []),
        defaultGateway: adapter.defaultGateway ?? null,
        gatewayMacAddress: adapter.gatewayMacAddress ?? null
      });
      continue;
    }

    merged.set(key, {
      name: existing.name,
      description: adapter.description ?? existing.description ?? null,
      macAddress: adapter.macAddress ?? existing.macAddress ?? null,
      ipv4: uniqueStrings([...(existing.ipv4 ?? []), ...(adapter.ipv4 ?? [])]),
      ipv6: uniqueStrings([...(existing.ipv6 ?? []), ...(adapter.ipv6 ?? [])]),
      dnsServers: uniqueStrings([...(existing.dnsServers ?? []), ...(adapter.dnsServers ?? [])]),
      defaultGateway: adapter.defaultGateway ?? existing.defaultGateway ?? null,
      gatewayMacAddress: adapter.gatewayMacAddress ?? existing.gatewayMacAddress ?? null
    });
  }

  return Array.from(merged.values()).sort((left, right) => {
    const leftScore = (left.defaultGateway ? 1 : 0) + left.ipv4.length;
    const rightScore = (right.defaultGateway ? 1 : 0) + right.ipv4.length;
    return rightScore - leftScore || left.name.localeCompare(right.name);
  });
}

function pickActiveAdapter(adapters: HostNetworkAdapterInfo[]): HostNetworkAdapterInfo | null {
  if (!adapters.length) return null;
  return (
    adapters.find((adapter) => adapter.defaultGateway && (adapter.ipv4.length > 0 || adapter.ipv6.length > 0)) ??
    adapters.find((adapter) => adapter.ipv4.length > 0 || adapter.ipv6.length > 0) ??
    adapters[0] ??
    null
  );
}

async function lookupPublicIpAddress(): Promise<string | null> {
  try {
    const { data, statusCode } = await makeRequest(
      {
        protocol: 'https:',
        hostname: 'api.ipify.org',
        path: '/?format=json',
        method: 'GET',
        timeout: 10000,
        headers: {
          Accept: 'application/json',
          'User-Agent': 'PCAP-Analyzer/1.0'
        }
      },
      2
    );
    if (statusCode < 200 || statusCode >= 300) return null;
    const parsed = JSON.parse(data) as { ip?: string };
    return parsed.ip && typeof parsed.ip === 'string' ? parsed.ip : null;
  } catch {
    return null;
  }
}

function determineNatStatus(adapter: HostNetworkAdapterInfo | null, publicIp: string | null): HostNetworkInfo['natStatus'] {
  const localIp = adapter?.ipv4.find((value) => Boolean(value)) ?? null;
  if (!localIp || !publicIp) return 'unknown';
  if (!isPrivateIpv4(localIp) && localIp === publicIp) return 'public_ip';
  if (isPrivateIpv4(localIp)) return 'behind_nat';
  return 'unknown';
}

function isPrivateIpv4(ip: string): boolean {
  const parts = ip.split('.').map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => Number.isNaN(part))) return false;
  if (parts[0] === 10) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  if (parts[0] === 169 && parts[1] === 254) return true;
  return false;
}

function runPowerShell(script: string): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(
      'powershell',
      ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', script],
      { windowsHide: true, timeout: 15000, maxBuffer: 1024 * 1024 },
      (error, stdout, stderr) => {
        if (error) {
          reject(new Error(stderr?.trim() || error.message));
          return;
        }
        resolve(stdout.trim());
      }
    );
  });
}

function toStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return uniqueStrings(value.map((item) => String(item ?? '')).filter(Boolean));
}

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values.filter(Boolean)));
}

function normalizeMac(value: string | null): string | null {
  if (!value) return null;
  return value.replace(/-/g, ':').toUpperCase();
}
