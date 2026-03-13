import * as XLSX from 'xlsx';
import type { HostNetworkInfo } from '../types';

const EXCEL_WORKBOOK_AUTHOR = '11ArkaN';

export function createWorkbookWithMetadata(): XLSX.WorkBook {
  const workbook = XLSX.utils.book_new();
  workbook.Props = {
    Author: EXCEL_WORKBOOK_AUTHOR,
    LastAuthor: EXCEL_WORKBOOK_AUTHOR
  };
  return workbook;
}

export async function appendHostNetworkSheet(workbook: XLSX.WorkBook): Promise<void> {
  const info = await getHostNetworkInfoCached();
  const rows = buildHostNetworkRows(info);
  const worksheet = XLSX.utils.json_to_sheet(rows);
  worksheet['!cols'] = buildExcelColumnWidths(rows);
  XLSX.utils.book_append_sheet(workbook, worksheet, 'Stanowisko');
}

export function buildHostNetworkRows(info: HostNetworkInfo | null): Array<Record<string, string | number>> {
  if (!info) {
    return [
      { Sekcja: 'Stanowisko', Pole: 'Status', Wartosc: 'Nie udalo sie pobrac konfiguracji hosta.' }
    ];
  }

  const rows: Array<Record<string, string | number>> = [
    { Sekcja: 'Stanowisko', Pole: 'Czas zebrania', Wartosc: info.collectedAt },
    { Sekcja: 'Stanowisko', Pole: 'Host', Wartosc: info.hostName },
    { Sekcja: 'Stanowisko', Pole: 'System', Wartosc: formatOperatingSystem(info) },
    { Sekcja: 'Stanowisko', Pole: 'Publiczny IP', Wartosc: info.publicIp || 'N/D' },
    { Sekcja: 'Stanowisko', Pole: 'Tryb polaczenia', Wartosc: natStatusLabel(info.natStatus) },
    { Sekcja: 'Stanowisko', Pole: 'Lokalne IPv4', Wartosc: info.localIpv4.join(', ') || 'N/D' },
    { Sekcja: 'Stanowisko', Pole: 'Lokalne IPv6', Wartosc: info.localIpv6.join(', ') || 'N/D' },
    { Sekcja: 'Stanowisko', Pole: 'DNS', Wartosc: info.dnsServers.join(', ') || 'N/D' },
    { Sekcja: 'Stanowisko', Pole: 'Brama domyslna', Wartosc: info.defaultGateway || 'N/D' },
    { Sekcja: 'Stanowisko', Pole: 'MAC bramy', Wartosc: info.gatewayMacAddress || 'N/D' }
  ];

  if (info.activeAdapter) {
    rows.push(
      { Sekcja: 'Aktywny adapter', Pole: 'Nazwa', Wartosc: info.activeAdapter.name },
      { Sekcja: 'Aktywny adapter', Pole: 'Opis', Wartosc: info.activeAdapter.description || 'N/D' },
      { Sekcja: 'Aktywny adapter', Pole: 'MAC', Wartosc: info.activeAdapter.macAddress || 'N/D' },
      { Sekcja: 'Aktywny adapter', Pole: 'IPv4', Wartosc: info.activeAdapter.ipv4.join(', ') || 'N/D' },
      { Sekcja: 'Aktywny adapter', Pole: 'IPv6', Wartosc: info.activeAdapter.ipv6.join(', ') || 'N/D' },
      { Sekcja: 'Aktywny adapter', Pole: 'DNS', Wartosc: info.activeAdapter.dnsServers.join(', ') || 'N/D' },
      { Sekcja: 'Aktywny adapter', Pole: 'Brama', Wartosc: info.activeAdapter.defaultGateway || 'N/D' },
      { Sekcja: 'Aktywny adapter', Pole: 'MAC bramy', Wartosc: info.activeAdapter.gatewayMacAddress || 'N/D' }
    );
  }

  for (const adapter of info.adapters) {
    rows.push(
      { Sekcja: 'Adaptery', Pole: `${adapter.name} / Opis`, Wartosc: adapter.description || 'N/D' },
      { Sekcja: 'Adaptery', Pole: `${adapter.name} / MAC`, Wartosc: adapter.macAddress || 'N/D' },
      { Sekcja: 'Adaptery', Pole: `${adapter.name} / IPv4`, Wartosc: adapter.ipv4.join(', ') || 'N/D' },
      { Sekcja: 'Adaptery', Pole: `${adapter.name} / IPv6`, Wartosc: adapter.ipv6.join(', ') || 'N/D' },
      { Sekcja: 'Adaptery', Pole: `${adapter.name} / DNS`, Wartosc: adapter.dnsServers.join(', ') || 'N/D' },
      { Sekcja: 'Adaptery', Pole: `${adapter.name} / Brama`, Wartosc: adapter.defaultGateway || 'N/D' },
      { Sekcja: 'Adaptery', Pole: `${adapter.name} / MAC bramy`, Wartosc: adapter.gatewayMacAddress || 'N/D' }
    );
  }

  return rows;
}

async function getHostNetworkInfoCached(): Promise<HostNetworkInfo | null> {
  return window.electronAPI
    .getHostNetworkInfo()
    .then((result) => (result.success ? result.data : null))
    .catch(() => null);
}

function natStatusLabel(status: HostNetworkInfo['natStatus']): string {
  if (status === 'behind_nat') return 'Za NAT';
  if (status === 'public_ip') return 'Publiczny adres na interfejsie';
  return 'Nieustalony';
}

function formatOperatingSystem(info: HostNetworkInfo): string {
  if (info.osName) {
    return info.osName;
  }
  if (info.osPlatform === 'win32') {
    const version = classifyWindowsRelease(info.osRelease);
    return version ? `${version} (build ${info.osRelease})` : `Windows (build ${info.osRelease})`;
  }
  if (info.osPlatform === 'darwin') {
    return `macOS ${info.osRelease}`;
  }
  if (info.osPlatform === 'linux') {
    return `Linux ${info.osRelease}`;
  }
  return `${info.osPlatform} ${info.osRelease}`;
}

function classifyWindowsRelease(release: string): string | null {
  const majorMinor = release.split('.').slice(0, 2).join('.');
  const build = Number(release.split('.')[2] ?? 0);
  if (majorMinor === '10.0') {
    if (build >= 22000) return 'Windows 11';
    return 'Windows 10';
  }
  if (majorMinor === '6.3') return 'Windows 8.1';
  if (majorMinor === '6.2') return 'Windows 8';
  if (majorMinor === '6.1') return 'Windows 7';
  return null;
}

function buildExcelColumnWidths(rows: Array<Record<string, string | number>>) {
  const minWidth = 12;
  const maxWidth = 80;
  if (!rows.length) return [];

  const headers = Object.keys(rows[0]) as Array<keyof (typeof rows)[number]>;
  return headers.map((header) => {
    let longest = String(header).length;
    for (const row of rows) {
      const width = String(row[header] ?? '').length;
      if (width > longest) longest = width;
    }
    return { wch: Math.max(minWidth, Math.min(maxWidth, longest + 2)) };
  });
}
